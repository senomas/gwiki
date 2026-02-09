package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"time"
)

type AccessMember struct {
	User   string
	Access string
}

type AccessPathRule struct {
	Path    string
	Members []AccessMember
}

type OwnerSyncStats struct {
	UsersInFile  int
	UsersAdded   int
	UsersUpdated int
}

type AccessSyncStats struct {
	OwnersInFile  int
	PathsInFile   int
	GrantsAdded   int
	GrantsUpdated int
	GrantsRemoved int
}

func (i *Index) SyncOwners(ctx context.Context, users []string) error {
	_, err := i.SyncOwnersWithStats(ctx, users)
	return err
}

func (i *Index) SyncAuthSources(ctx context.Context, users []string, access map[string][]AccessPathRule) (OwnerSyncStats, AccessSyncStats, error) {
	i.syncMu.Lock()
	defer i.syncMu.Unlock()

	ownerStats, err := i.SyncOwnersWithStats(ctx, users)
	if err != nil {
		return ownerStats, AccessSyncStats{}, err
	}

	accessStats, err := i.syncPathAccessWithRetry(ctx, access, 1, 200*time.Millisecond)
	if err != nil {
		return ownerStats, AccessSyncStats{}, err
	}
	if err := i.rebuildFileAccessAll(ctx); err != nil {
		return ownerStats, accessStats, err
	}
	return ownerStats, accessStats, nil
}

func (i *Index) SyncOwnersWithStats(ctx context.Context, users []string) (OwnerSyncStats, error) {
	userSet := map[string]struct{}{}
	for _, name := range users {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		userSet[name] = struct{}{}
	}
	userSet["system"] = struct{}{}

	stats := OwnerSyncStats{
		UsersInFile: len(users),
	}

	for name := range userSet {
		created, err := i.ensureUser(ctx, name)
		if err != nil {
			return stats, err
		}
		if created {
			stats.UsersAdded++
		}
	}

	return stats, nil
}

func (i *Index) CanWriteOwner(ctx context.Context, ownerName, userName string) (bool, error) {
	ownerName = strings.TrimSpace(ownerName)
	userName = strings.TrimSpace(userName)
	if ownerName == "" || userName == "" {
		return false, nil
	}
	if ownerName == userName {
		return true, nil
	}
	userID, err := i.userIDByName(ctx, userName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	ownerID, err := i.userIDByName(ctx, ownerName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var access string
	err = i.queryRowContext(ctx, `
		SELECT access
		FROM path_access
		WHERE owner_user_id=? AND grantee_user_id=? AND lower(access)='rw'
		LIMIT 1
	`, ownerID, userID).Scan(&access)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (i *Index) CanWritePath(ctx context.Context, ownerName, relPath, userName string) (bool, error) {
	ownerName = strings.TrimSpace(ownerName)
	userName = strings.TrimSpace(userName)
	if ownerName == "" || userName == "" {
		return false, nil
	}
	if ownerName == userName {
		return true, nil
	}
	tx, txStart, err := i.beginTx(ctx, "can-write-path")
	if err != nil {
		return false, err
	}
	defer i.rollbackTx(tx, "can-write-path", txStart)
	userID, err := i.userIDByNameTx(ctx, tx, userName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	ownerID, err := i.userIDByNameTx(ctx, tx, ownerName)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	boundary, ok, err := i.accessBoundaryPathTx(ctx, tx, ownerID, relPath)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	var access string
	err = i.queryRowContextTx(ctx, tx, `
		SELECT access
		FROM path_access
		WHERE owner_user_id=? AND path=? AND grantee_user_id=?
	`, ownerID, boundary, userID).Scan(&access)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.EqualFold(access, "rw"), nil
}

func (i *Index) ensureUser(ctx context.Context, name string) (bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return false, fmt.Errorf("empty user name")
	}
	if _, err := i.execContext(ctx, "INSERT OR IGNORE INTO users(name) VALUES(?)", name); err != nil {
		return false, err
	}
	userID, err := i.userIDByName(ctx, name)
	if err != nil {
		return false, err
	}
	var changes int64
	if err := i.queryRowContext(ctx, "SELECT changes()").Scan(&changes); err != nil {
		return false, err
	}
	return changes > 0 && userID > 0, nil
}

func (i *Index) ensureUserTx(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return false, fmt.Errorf("empty user name")
	}
	if _, err := i.execContextTx(ctx, tx, "INSERT OR IGNORE INTO users(name) VALUES(?)", name); err != nil {
		return false, err
	}
	userID, err := i.userIDByNameTx(ctx, tx, name)
	if err != nil {
		return false, err
	}
	var changes int64
	if err := i.queryRowContextTx(ctx, tx, "SELECT changes()").Scan(&changes); err != nil {
		return false, err
	}
	return changes > 0 && userID > 0, nil
}

func (i *Index) EnsureUser(ctx context.Context, name string) (int, error) {
	_, err := i.ensureUser(ctx, name)
	if err != nil {
		return 0, err
	}
	return i.userIDByName(ctx, name)
}

func (i *Index) SyncPathAccessWithStats(ctx context.Context, access map[string][]AccessPathRule) (AccessSyncStats, error) {
	stats := AccessSyncStats{OwnersInFile: len(access)}
	existing := map[string]string{}
	rows, err := i.queryContext(ctx, `
		SELECT owners.name, path_access.path, grantees.name, path_access.access
		FROM path_access
		JOIN users owners ON owners.id = path_access.owner_user_id
		JOIN users grantees ON grantees.id = path_access.grantee_user_id
	`)
	if err != nil {
		return stats, err
	}
	for rows.Next() {
		var ownerName, pathName, granteeName, accessLevel string
		if err := rows.Scan(&ownerName, &pathName, &granteeName, &accessLevel); err != nil {
			rows.Close()
			return stats, err
		}
		key := strings.ToLower(strings.TrimSpace(ownerName)) + "|" + strings.ToLower(strings.TrimSpace(pathName)) + "|" + strings.ToLower(strings.TrimSpace(granteeName))
		if key == "||" {
			continue
		}
		existing[key] = strings.ToLower(strings.TrimSpace(accessLevel))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return stats, err
	}
	rows.Close()

	desired := map[string]string{}
	for ownerName, rules := range access {
		ownerName = strings.TrimSpace(ownerName)
		if ownerName == "" {
			continue
		}
		for _, rule := range rules {
			pathName := normalizeAccessPath(rule.Path)
			for _, member := range rule.Members {
				user := strings.TrimSpace(member.User)
				if user == "" {
					continue
				}
				level := strings.ToLower(strings.TrimSpace(member.Access))
				if level != "ro" && level != "rw" {
					level = "ro"
				}
				key := strings.ToLower(ownerName) + "|" + strings.ToLower(pathName) + "|" + strings.ToLower(user)
				desired[key] = level
			}
			stats.PathsInFile++
		}
	}

	for key, level := range desired {
		prev, ok := existing[key]
		if !ok {
			stats.GrantsAdded++
			continue
		}
		if prev != level {
			stats.GrantsUpdated++
		}
	}
	for key := range existing {
		if _, ok := desired[key]; !ok {
			stats.GrantsRemoved++
		}
	}

	tx, txStart, err := i.beginTx(ctx, "sync-path-access")
	if err != nil {
		return stats, err
	}
	defer i.rollbackTx(tx, "sync-path-access", txStart)

	if _, err := i.execContextTx(ctx, tx, "DELETE FROM path_access"); err != nil {
		return stats, err
	}
	if _, err := i.execContextTx(ctx, tx, "DELETE FROM path_access_files"); err != nil {
		return stats, err
	}
	for ownerName, rules := range access {
		ownerName = strings.TrimSpace(ownerName)
		if ownerName == "" {
			continue
		}
		if _, err := i.ensureUserTx(ctx, tx, ownerName); err != nil {
			return stats, err
		}
		ownerID, err := i.userIDByNameTx(ctx, tx, ownerName)
		if err != nil {
			return stats, err
		}
		for _, rule := range rules {
			pathName := normalizeAccessPath(rule.Path)
			if _, err := i.execContextTx(ctx, tx, `
				INSERT OR REPLACE INTO path_access_files(owner_user_id, path, depth)
				VALUES(?, ?, ?)
			`, ownerID, pathName, accessPathDepth(pathName)); err != nil {
				return stats, err
			}
			for _, member := range rule.Members {
				user := strings.TrimSpace(member.User)
				if user == "" {
					continue
				}
				accessLevel := strings.ToLower(strings.TrimSpace(member.Access))
				if accessLevel != "ro" && accessLevel != "rw" {
					accessLevel = "ro"
				}
				if _, err := i.ensureUserTx(ctx, tx, user); err != nil {
					return stats, err
				}
				userID, err := i.userIDByNameTx(ctx, tx, user)
				if err != nil {
					return stats, err
				}
				if _, err := i.execContextTx(ctx, tx, `
					INSERT INTO path_access(owner_user_id, path, grantee_user_id, access)
					VALUES(?, ?, ?, ?)
				`, ownerID, pathName, userID, accessLevel); err != nil {
					return stats, err
				}
			}
		}
	}

	if err := i.commitTx(tx, "sync-path-access", txStart); err != nil {
		return stats, err
	}
	return stats, nil
}

func (i *Index) syncPathAccessWithRetry(ctx context.Context, access map[string][]AccessPathRule, retries int, backoff time.Duration) (AccessSyncStats, error) {
	stats, err := i.SyncPathAccessWithStats(ctx, access)
	if err == nil || retries <= 0 || !isSQLiteBusy(err) {
		return stats, err
	}
	timer := time.NewTimer(backoff)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return stats, ctx.Err()
	case <-timer.C:
	}
	return i.SyncPathAccessWithStats(ctx, access)
}

func (i *Index) WritableOwnersForUser(ctx context.Context, userName string) ([]string, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return nil, fmt.Errorf("empty user name")
	}
	userID, err := i.userIDByName(ctx, userName)
	if err != nil {
		return nil, err
	}
	rows, err := i.queryContext(ctx, `
		SELECT DISTINCT owners.name
		FROM path_access
		JOIN users owners ON owners.id = path_access.owner_user_id
		WHERE path_access.grantee_user_id = ? AND lower(path_access.access) = 'rw'
		ORDER BY owners.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var owners []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		owners = append(owners, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !containsString(owners, userName) {
		owners = append(owners, userName)
	}
	return owners, nil
}

func (i *Index) AccessibleOwnersForUser(ctx context.Context, userName string) ([]string, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return nil, fmt.Errorf("empty user name")
	}
	userID, err := i.userIDByName(ctx, userName)
	if err != nil {
		return nil, err
	}
	rows, err := i.queryContext(ctx, `
		SELECT DISTINCT owners.name
		FROM path_access
		JOIN users owners ON owners.id = path_access.owner_user_id
		WHERE path_access.grantee_user_id = ?
		ORDER BY owners.name
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var owners []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		owners = append(owners, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !containsString(owners, userName) {
		owners = append(owners, userName)
	}
	return owners, nil
}

func (i *Index) userIDByName(ctx context.Context, name string) (int, error) {
	return i.userIDByNameTx(ctx, nil, name)
}

func (i *Index) userIDByNameTx(ctx context.Context, tx *sql.Tx, name string) (int, error) {
	var id int
	if tx != nil {
		slog.Debug("user id lookup start", "name", name, "tx", true)
		err := i.queryRowContextTx(ctx, tx, "SELECT id FROM users WHERE name=?", name).Scan(&id)
		slog.Debug("user id lookup done", "name", name, "id", id, "tx", true, "err", err)
		return id, err
	}
	slog.Debug("user id lookup start", "name", name, "tx", false)
	err := i.queryRowContext(ctx, "SELECT id FROM users WHERE name=?", name).Scan(&id)
	slog.Debug("user id lookup done", "name", name, "id", id, "tx", false, "err", err)
	return id, err
}

func (i *Index) ResolveOwnerIDs(ctx context.Context, ownerName string) (int, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return 0, fmt.Errorf("empty owner name")
	}
	if _, err := i.ensureUser(ctx, ownerName); err != nil {
		return 0, err
	}
	userID, err := i.userIDByName(ctx, ownerName)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func (i *Index) LookupOwnerIDs(ctx context.Context, ownerName string) (int, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return 0, fmt.Errorf("empty owner name")
	}
	userID, err := i.userIDByName(ctx, ownerName)
	if err == nil {
		return userID, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return 0, sql.ErrNoRows
}

func (i *Index) AccessFilterForUser(ctx context.Context, userName string) (int, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return 0, fmt.Errorf("empty user name")
	}
	userID, err := i.userIDByName(ctx, userName)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func (i *Index) accessBoundaryPath(ctx context.Context, ownerID int, relPath string) (string, bool, error) {
	return i.accessBoundaryPathTx(ctx, nil, ownerID, relPath)
}

func (i *Index) accessBoundaryPathTx(ctx context.Context, tx *sql.Tx, ownerID int, relPath string) (string, bool, error) {
	relPath = normalizeAccessPath(relPath)
	rows, err := i.queryContextTx(ctx, tx, `
		SELECT path
		FROM path_access_files
		WHERE owner_user_id = ?
		ORDER BY depth DESC
	`, ownerID)
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	for rows.Next() {
		var pathName string
		if err := rows.Scan(&pathName); err != nil {
			return "", false, err
		}
		if accessPathMatches(pathName, relPath) {
			return pathName, true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	return "", false, nil
}

func normalizeAccessPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.Trim(value, "/")
	value = path.Clean(value)
	if value == "." {
		return ""
	}
	return value
}

func accessPathDepth(value string) int {
	value = normalizeAccessPath(value)
	if value == "" {
		return 0
	}
	return strings.Count(value, "/") + 1
}

func accessPathMatches(rulePath, relPath string) bool {
	rulePath = normalizeAccessPath(rulePath)
	relPath = normalizeAccessPath(relPath)
	if rulePath == "" {
		return true
	}
	return strings.HasPrefix(relPath, rulePath+"/")
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func (i *Index) actorUserID(ctx context.Context) (int, error) {
	if filter, ok := accessFilterFromContext(ctx); ok && filter.userID > 0 {
		return filter.userID, nil
	}
	_, err := i.ensureUser(ctx, "system")
	if err != nil {
		return 0, err
	}
	return i.userIDByName(ctx, "system")
}

func (i *Index) ListUsers(ctx context.Context) ([]string, error) {
	rows, err := i.queryContext(ctx, "SELECT name FROM users ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		users = append(users, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (i *Index) CountSharedNotesByOwner(ctx context.Context, userName string) (map[string]int, error) {
	userName = strings.TrimSpace(userName)
	if userName == "" {
		return map[string]int{}, nil
	}
	userID, err := i.userIDByName(ctx, userName)
	if err != nil {
		return nil, err
	}
	rows, err := i.queryContext(ctx, `
		SELECT owners.name, COUNT(DISTINCT files.id)
		FROM files
		JOIN users owners ON owners.id = files.user_id
		LEFT JOIN file_access ON file_access.file_id = files.id AND file_access.grantee_user_id = ?
		WHERE owners.name != ? AND (file_access.grantee_user_id IS NOT NULL OR files.visibility = 'public')
		GROUP BY owners.name
	`, userID, userName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var (
			owner string
			count int
		)
		if err := rows.Scan(&owner, &count); err != nil {
			return nil, err
		}
		counts[owner] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return counts, nil
}

func (i *Index) CountOwnedNotesByOwner(ctx context.Context, ownerName string) (int, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return 0, nil
	}
	ownerID, err := i.userIDByName(ctx, ownerName)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var count int
	if err := i.queryRowContext(ctx, "SELECT COUNT(DISTINCT id) FROM files WHERE user_id=?", ownerID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
