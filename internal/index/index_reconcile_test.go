package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReconcileFilesFromDBWithStats_ReindexesChangedAndRemovesMissing(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}

	keepPath := filepath.Join(notesDir, "keep.md")
	removePath := filepath.Join(notesDir, "remove.md")
	if err := os.WriteFile(keepPath, []byte("# Keep\n\ninitial body\n"), 0o644); err != nil {
		t.Fatalf("write keep note: %v", err)
	}
	if err := os.WriteFile(removePath, []byte("# Remove\n\ninitial body\n"), 0o644); err != nil {
		t.Fatalf("write remove note: %v", err)
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

	updatedKeep := "# Keep Updated\n\nreconcileupdatedmarker\n"
	if err := os.WriteFile(keepPath, []byte(updatedKeep), 0o644); err != nil {
		t.Fatalf("update keep note: %v", err)
	}
	if err := os.Remove(removePath); err != nil {
		t.Fatalf("remove delete note: %v", err)
	}

	scanned, updated, cleaned, err := idx.ReconcileFilesFromDBWithStats(ctx, repo)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if scanned < 2 {
		t.Fatalf("expected at least 2 scanned records, got %d", scanned)
	}
	if updated != 1 {
		t.Fatalf("expected exactly 1 updated record, got %d", updated)
	}
	if cleaned != 1 {
		t.Fatalf("expected exactly 1 cleaned record, got %d", cleaned)
	}

	results, err := idx.Search(ctx, "reconcileupdatedmarker", 10)
	if err != nil {
		t.Fatalf("search updated marker: %v", err)
	}
	if len(results) != 1 || results[0].Path != "local/keep.md" {
		t.Fatalf("expected updated keep note indexed, got %+v", results)
	}

	exists, err := idx.NoteExists(ctx, "local/remove.md")
	if err != nil {
		t.Fatalf("note exists remove.md: %v", err)
	}
	if exists {
		t.Fatalf("expected removed note record to be cleaned")
	}
}
