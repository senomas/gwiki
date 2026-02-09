package index

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUserSyncStateRoundTrip(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "local", "notes"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	syncAt := time.Date(2026, 2, 9, 15, 4, 5, 0, time.UTC)
	if err := idx.SetUserSyncState(ctx, "alice", "Success", syncAt); err != nil {
		t.Fatalf("set sync state: %v", err)
	}

	state, err := idx.UserSyncState(ctx, "alice")
	if err != nil {
		t.Fatalf("get sync state: %v", err)
	}
	if state.LastSyncUnix != syncAt.Unix() {
		t.Fatalf("expected last_sync_unix=%d, got %d", syncAt.Unix(), state.LastSyncUnix)
	}
	if state.LastSyncStatus != "success" {
		t.Fatalf("expected status success, got %q", state.LastSyncStatus)
	}

	allStates, err := idx.UserSyncStates(ctx)
	if err != nil {
		t.Fatalf("list sync states: %v", err)
	}
	got, ok := allStates["alice"]
	if !ok {
		t.Fatalf("expected alice in sync state map")
	}
	if got.LastSyncUnix != syncAt.Unix() || got.LastSyncStatus != "success" {
		t.Fatalf("unexpected sync state %+v", got)
	}
}

func TestUserSyncStateMigrateFromSchema30(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "legacy", "notes"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}
	dbPath := filepath.Join(dataDir, "index.sqlite")

	rawDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	if _, err := rawDB.Exec(`CREATE TABLE schema_version (version INTEGER NOT NULL)`); err != nil {
		t.Fatalf("create schema_version: %v", err)
	}
	if _, err := rawDB.Exec(`INSERT INTO schema_version(version) VALUES(30)`); err != nil {
		t.Fatalf("insert schema version: %v", err)
	}
	if _, err := rawDB.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			name TEXT UNIQUE NOT NULL
		)
	`); err != nil {
		t.Fatalf("create legacy users table: %v", err)
	}
	if _, err := rawDB.Exec(`INSERT INTO users(name) VALUES('legacy')`); err != nil {
		t.Fatalf("insert legacy user: %v", err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	idx, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	syncAt := time.Date(2026, 2, 9, 16, 7, 8, 0, time.UTC)
	if err := idx.SetUserSyncState(ctx, "legacy", "failed", syncAt); err != nil {
		t.Fatalf("set sync state after migration: %v", err)
	}
	state, err := idx.UserSyncState(ctx, "legacy")
	if err != nil {
		t.Fatalf("get sync state after migration: %v", err)
	}
	if state.LastSyncUnix != syncAt.Unix() {
		t.Fatalf("expected migrated last_sync_unix=%d, got %d", syncAt.Unix(), state.LastSyncUnix)
	}
	if state.LastSyncStatus != "failed" {
		t.Fatalf("expected migrated status failed, got %q", state.LastSyncStatus)
	}
}
