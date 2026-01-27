package index

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func (i *Index) GitSyncState(ctx context.Context, ownerName string) (int64, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return 0, fmt.Errorf("owner name required")
	}
	var lastSync int64
	err := i.queryRowContext(ctx, "SELECT last_sync_unix FROM git_sync_state WHERE owner_name=?", ownerName).Scan(&lastSync)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	return lastSync, nil
}

func (i *Index) SetGitSyncState(ctx context.Context, ownerName string, lastSync int64) error {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return fmt.Errorf("owner name required")
	}
	_, err := i.execContext(ctx, `
		INSERT INTO git_sync_state(owner_name, last_sync_unix)
		VALUES(?, ?)
		ON CONFLICT(owner_name) DO UPDATE SET last_sync_unix=excluded.last_sync_unix
	`, ownerName, lastSync)
	return err
}

func (i *Index) SyncGitHistory(ctx context.Context, ownerName, repoDir string) (int, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return 0, fmt.Errorf("owner name required")
	}
	repoDir = strings.TrimSpace(repoDir)
	if repoDir == "" {
		return 0, fmt.Errorf("repo dir required")
	}
	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		return 0, nil
	}
	lastSync, err := i.GitSyncState(ctx, ownerName)
	if err != nil {
		return 0, err
	}
	slog.Debug("git history sync start", "owner", ownerName, "since", lastSync)
	userName, err := gitConfigLocal(ctx, repoDir, "user.name")
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(userName) == "" {
		userName = "system"
	}
	actorID, err := i.ensureUser(ctx, userName)
	if err != nil {
		return 0, err
	}
	ownerUserID, ownerGroupID, err := i.LookupOwnerIDs(ctx, ownerName)
	if err != nil {
		return 0, err
	}
	ownerClause, ownerArgs := ownerWhereClause(ownerUserID, ownerGroupID, "files")

	args := []string{
		"log",
		"--since=@" + strconv.FormatInt(lastSync, 10),
		"--name-only",
		"--pretty=format:%at",
		"--",
		"notes/",
	}
	slog.Debug("git history log", "owner", ownerName, "repo", repoDir, "args", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repoDir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var (
		currentTime int64
		maxTime     = lastSync
	)
	tx, err := i.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	inserted := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if ts, ok := parseUnixLine(line); ok {
			currentTime = ts
			if ts > maxTime {
				maxTime = ts
			}
			slog.Debug("git history commit", "owner", ownerName, "time", currentTime)
			continue
		}
		if currentTime == 0 {
			continue
		}
		if !strings.HasPrefix(line, "notes/") {
			continue
		}
		relPath := strings.TrimPrefix(line, "notes/")
		relPath = filepath.ToSlash(relPath)
		if !strings.HasSuffix(strings.ToLower(relPath), ".md") {
			continue
		}
		slog.Debug("git history file", "owner", ownerName, "path", relPath)
		var fileID int
		args := append([]interface{}{}, ownerArgs...)
		args = append(args, relPath)
		query := "SELECT id FROM files WHERE " + ownerClause + " AND path=?"
		if err := i.queryRowContextTx(ctx, tx, query, args...).Scan(&fileID); err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return 0, err
		}
		actionDate := currentTime / secondsPerDay
		res, err := i.execContextTx(ctx, tx, `
			INSERT OR IGNORE INTO file_histories(file_id, user_id, action_date)
			VALUES(?, ?, ?)
		`, fileID, actorID, actionDate)
		if err != nil {
			return 0, err
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			inserted++
			slog.Debug("git history insert", "owner", ownerName, "file_id", fileID, "user_id", actorID, "action_date", actionDate)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if err := cmd.Wait(); err != nil {
		return 0, err
	}
	if maxTime > lastSync {
		if _, err := i.execContextTx(ctx, tx, `
			INSERT INTO git_sync_state(owner_name, last_sync_unix)
			VALUES(?, ?)
			ON CONFLICT(owner_name) DO UPDATE SET last_sync_unix=excluded.last_sync_unix
		`, ownerName, maxTime); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	slog.Debug("git history sync done", "owner", ownerName, "inserted", inserted, "last_sync", maxTime)
	return inserted, nil
}

func gitConfigLocal(ctx context.Context, repoDir, key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", nil
	}
	cmd := exec.CommandContext(ctx, "git", "config", "--local", "--get", key)
	cmd.Dir = repoDir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.Output()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func parseUnixLine(line string) (int64, bool) {
	for _, r := range line {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	if line == "" {
		return 0, false
	}
	val, err := strconv.ParseInt(line, 10, 64)
	if err != nil {
		return 0, false
	}
	return val, true
}
