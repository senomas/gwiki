package index

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (i *Index) EnqueueFileCleanup(ctx context.Context, ownerName string, paths []string, expiresAt time.Time) (int, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" || len(paths) == 0 {
		return 0, nil
	}
	if _, err := i.ensureUser(ctx, ownerName); err != nil {
		return 0, err
	}
	userID, err := i.userIDByName(ctx, ownerName)
	if err != nil {
		return 0, err
	}
	unique := map[string]struct{}{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		unique[path] = struct{}{}
	}
	if len(unique) == 0 {
		return 0, nil
	}
	tx, txStart, err := i.beginTx(ctx, "file-cleanup-enqueue")
	if err != nil {
		return 0, err
	}
	defer func() {
		if tx != nil {
			i.rollbackTx(tx, "file-cleanup-enqueue", txStart)
		}
	}()
	query := `
		INSERT INTO file_cleanup(user_id, path, expires_at)
		VALUES(?, ?, ?)
		ON CONFLICT(user_id, path) DO UPDATE SET expires_at=excluded.expires_at`
	count := 0
	for path := range unique {
		if _, err := i.execContextTx(ctx, tx, query, userID, path, expiresAt.Unix()); err != nil {
			return 0, err
		}
		count++
	}
	if err := i.commitTx(tx, "file-cleanup-enqueue", txStart); err != nil {
		return 0, err
	}
	tx = nil
	return count, nil
}

func (i *Index) ClearFileCleanup(ctx context.Context, ownerName string, paths []string) (int, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" || len(paths) == 0 {
		return 0, nil
	}
	userID, err := i.userIDByName(ctx, ownerName)
	if err != nil {
		return 0, err
	}
	unique := map[string]struct{}{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		unique[path] = struct{}{}
	}
	if len(unique) == 0 {
		return 0, nil
	}
	placeholders := strings.Repeat("?,", len(unique))
	placeholders = strings.TrimSuffix(placeholders, ",")
	args := make([]any, 0, len(unique)+1)
	args = append(args, userID)
	for path := range unique {
		args = append(args, path)
	}
	query := fmt.Sprintf("DELETE FROM file_cleanup WHERE user_id=? AND path IN (%s)", placeholders)
	res, err := i.execContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	affected, _ := res.RowsAffected()
	return int(affected), nil
}

func (i *Index) ListExpiredFileCleanup(ctx context.Context, ownerName string, now time.Time, limit int) ([]string, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return nil, nil
	}
	userID, err := i.userIDByName(ctx, ownerName)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 500
	}
	rows, err := i.queryContext(ctx, `
		SELECT path
		FROM file_cleanup
		WHERE user_id = ? AND expires_at <= ?
		ORDER BY expires_at
		LIMIT ?`, userID, now.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		paths = append(paths, path)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return paths, nil
}
