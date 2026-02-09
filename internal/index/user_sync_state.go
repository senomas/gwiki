package index

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type UserSyncState struct {
	LastSyncUnix   int64
	LastSyncStatus string
}

func (i *Index) UserSyncState(ctx context.Context, ownerName string) (UserSyncState, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return UserSyncState{}, fmt.Errorf("owner name required")
	}
	var state UserSyncState
	err := i.queryRowContext(ctx, `
		SELECT last_sync_unix, last_sync_status
		FROM users
		WHERE name=?
	`, ownerName).Scan(&state.LastSyncUnix, &state.LastSyncStatus)
	if err != nil {
		if err == sql.ErrNoRows {
			return UserSyncState{}, nil
		}
		return UserSyncState{}, err
	}
	state.LastSyncStatus = strings.ToLower(strings.TrimSpace(state.LastSyncStatus))
	return state, nil
}

func (i *Index) UserSyncStates(ctx context.Context) (map[string]UserSyncState, error) {
	rows, err := i.queryContext(ctx, `
		SELECT name, last_sync_unix, last_sync_status
		FROM users
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	states := map[string]UserSyncState{}
	for rows.Next() {
		var (
			name   string
			state  UserSyncState
			status string
		)
		if err := rows.Scan(&name, &state.LastSyncUnix, &status); err != nil {
			return nil, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		state.LastSyncStatus = strings.ToLower(strings.TrimSpace(status))
		states[name] = state
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return states, nil
}

func (i *Index) SetUserSyncState(ctx context.Context, ownerName string, status string, syncedAt time.Time) error {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return fmt.Errorf("owner name required")
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "unknown"
	}
	if syncedAt.IsZero() {
		syncedAt = time.Now()
	}
	if _, err := i.ensureUser(ctx, ownerName); err != nil {
		return err
	}
	_, err := i.execContext(ctx, `
		UPDATE users
		SET last_sync_unix=?, last_sync_status=?
		WHERE name=?
	`, syncedAt.Unix(), status, ownerName)
	return err
}
