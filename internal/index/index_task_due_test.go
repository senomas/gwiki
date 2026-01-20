package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestJournalTaskDefaultsDueDate(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes", "2026-01")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	content := "# 05 Jan 2026\n\n- [ ] Journal task\n"
	if err := os.WriteFile(filepath.Join(notesDir, "05.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write journal note: %v", err)
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

	count, err := idx.CountTasks(ctx, TaskCountFilter{DueOnly: true, DueDate: "2026-01-05"})
	if err != nil {
		t.Fatalf("count tasks: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 due task, got %d", count)
	}

	count, err = idx.CountTasks(ctx, TaskCountFilter{DueOnly: true, DueDate: "2026-01-04"})
	if err != nil {
		t.Fatalf("count tasks: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 due tasks before journal date, got %d", count)
	}
}

func TestJournalTaskRespectsInlineDueDate(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes", "2026-01")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	content := "# 05 Jan 2026\n\n- [ ] Journal task Due:2026-01-10\n"
	if err := os.WriteFile(filepath.Join(notesDir, "05.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write journal note: %v", err)
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

	count, err := idx.CountTasks(ctx, TaskCountFilter{DueOnly: true, DueDate: "2026-01-05"})
	if err != nil {
		t.Fatalf("count tasks: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 due tasks on journal date, got %d", count)
	}

	count, err = idx.CountTasks(ctx, TaskCountFilter{DueOnly: true, DueDate: "2026-01-10"})
	if err != nil {
		t.Fatalf("count tasks: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 due task on inline date, got %d", count)
	}
}
