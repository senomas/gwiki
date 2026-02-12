package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

func normalizeAttachmentNames(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (i *Index) AttachmentCommitUnixMap(ctx context.Context, ownerName, noteID string, names []string) (map[string]int64, error) {
	ownerName = strings.TrimSpace(ownerName)
	noteID = strings.TrimSpace(noteID)
	result := map[string]int64{}
	if ownerName == "" || noteID == "" {
		return result, nil
	}
	names = normalizeAttachmentNames(names)
	if len(names) == 0 {
		return result, nil
	}
	ownerID, err := i.LookupOwnerIDs(ctx, ownerName)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")
	query := fmt.Sprintf(`
		SELECT name, commit_unix
		FROM attachment_dates
		WHERE owner_user_id = ? AND note_id = ? AND name IN (%s)
	`, placeholders)
	args := make([]any, 0, len(names)+2)
	args = append(args, ownerID, noteID)
	for _, name := range names {
		args = append(args, name)
	}
	rows, err := i.queryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var commitUnix int64
		if err := rows.Scan(&name, &commitUnix); err != nil {
			return nil, err
		}
		if commitUnix <= 0 {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		result[name] = commitUnix
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (i *Index) UpsertAttachmentCommitUnixBatch(ctx context.Context, ownerName, noteID string, values map[string]int64) error {
	ownerName = strings.TrimSpace(ownerName)
	noteID = strings.TrimSpace(noteID)
	if ownerName == "" || noteID == "" || len(values) == 0 {
		return nil
	}
	ownerID, err := i.ResolveOwnerIDs(ctx, ownerName)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(values))
	for name, commitUnix := range values {
		name = strings.TrimSpace(name)
		if name == "" || commitUnix <= 0 {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)

	tx, txStart, err := i.beginTx(ctx, "attachment-date-upsert")
	if err != nil {
		return err
	}
	defer i.rollbackTx(tx, "attachment-date-upsert", txStart)
	nowUnix := time.Now().Unix()
	query := `
		INSERT INTO attachment_dates(owner_user_id, note_id, name, commit_unix, updated_at)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(owner_user_id, note_id, name) DO UPDATE SET
			commit_unix = excluded.commit_unix,
			updated_at = excluded.updated_at
	`
	for _, name := range names {
		commitUnix := values[name]
		if commitUnix <= 0 {
			continue
		}
		if _, err := i.execContextTx(ctx, tx, query, ownerID, noteID, name, commitUnix, nowUnix); err != nil {
			return err
		}
	}
	return i.commitTx(tx, "attachment-date-upsert", txStart)
}
