package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDBFileMTime(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "note.md"), []byte("# Note\n"), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	mtime, err := idx.DBFileMTime()
	if err != nil {
		t.Fatalf("db file mtime: %v", err)
	}
	if mtime <= 0 {
		t.Fatalf("expected positive db file mtime, got %d", mtime)
	}
}
