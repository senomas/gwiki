package index

import (
	"context"
	"database/sql"
	"time"
)

const (
	EmbedCacheStatusFound  = "found"
	EmbedCacheStatusFailed = "failed"
)

type EmbedCacheEntry struct {
	URL       string
	Kind      string
	EmbedURL  string
	Status    string
	ErrorMsg  string
	UpdatedAt time.Time
	ExpiresAt time.Time
}

func (i *Index) GetEmbedCache(ctx context.Context, url, kind string) (EmbedCacheEntry, bool, error) {
	userID, err := i.actorUserID(ctx)
	if err != nil {
		return EmbedCacheEntry{}, false, err
	}
	var entry EmbedCacheEntry
	var updatedUnix int64
	var expiresUnix int64

	row := i.queryRowContext(ctx, `
		SELECT url, kind, embed_url, status, error_msg, updated_at, expires_at
		FROM embed_cache
		WHERE url = ? AND kind = ? AND user_id = ?
		LIMIT 1`,
		url,
		kind,
		userID,
	)
	err = row.Scan(&entry.URL, &entry.Kind, &entry.EmbedURL, &entry.Status, &entry.ErrorMsg, &updatedUnix, &expiresUnix)
	if err != nil {
		if err == sql.ErrNoRows {
			return EmbedCacheEntry{}, false, nil
		}
		return EmbedCacheEntry{}, false, err
	}
	entry.UpdatedAt = time.Unix(updatedUnix, 0)
	entry.ExpiresAt = time.Unix(expiresUnix, 0)

	if time.Now().After(entry.ExpiresAt) {
		_, _ = i.execContext(ctx, "DELETE FROM embed_cache WHERE url = ? AND kind = ? AND user_id = ?", url, kind, userID)
		return EmbedCacheEntry{}, false, nil
	}
	return entry, true, nil
}

func (i *Index) UpsertEmbedCache(ctx context.Context, entry EmbedCacheEntry) error {
	userID, err := i.actorUserID(ctx)
	if err != nil {
		return err
	}
	_, err = i.execContext(ctx, `
		INSERT INTO embed_cache(user_id, url, kind, embed_url, status, error_msg, updated_at, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id, url, kind) DO UPDATE SET
			embed_url = excluded.embed_url,
			status = excluded.status,
			error_msg = excluded.error_msg,
			updated_at = excluded.updated_at,
			expires_at = excluded.expires_at`,
		userID,
		entry.URL,
		entry.Kind,
		entry.EmbedURL,
		entry.Status,
		entry.ErrorMsg,
		entry.UpdatedAt.Unix(),
		entry.ExpiresAt.Unix(),
	)
	return err
}
