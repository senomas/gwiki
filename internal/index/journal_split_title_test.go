package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDisplayTitleForPathSplitJournal(t *testing.T) {
	got := DisplayTitleForPath("2026-02/21-10-15.md", "")
	if got != "21 Feb 2026 10:15" {
		t.Fatalf("DisplayTitleForPath split journal=%q want %q", got, "21 Feb 2026 10:15")
	}
}

func TestDisplayTitleForPathPrefersExplicitTitle(t *testing.T) {
	got := DisplayTitleForPath("2026-02/21-10-15.md", "Manual Title")
	if got != "Manual Title" {
		t.Fatalf("DisplayTitleForPath explicit=%q want %q", got, "Manual Title")
	}
}

func TestIndexNoteSplitJournalTitleFallback(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes", "2026-02")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
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

	content := "body only without h1\n"
	noteRel := "2026-02/21-10-15.md"
	notePath := owner + "/" + noteRel
	fullPath := filepath.Join(repo, owner, "notes", filepath.FromSlash(noteRel))
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	summary, err := idx.NoteSummaryByPath(ctx, notePath)
	if err != nil {
		t.Fatalf("note summary: %v", err)
	}
	if summary.Title != "21 Feb 2026 10:15" {
		t.Fatalf("summary title=%q want %q", summary.Title, "21 Feb 2026 10:15")
	}
}

func TestIndexNoteSplitJournalExplicitTitleWins(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes", "2026-02")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
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

	content := "# Manual title\n\nbody\n"
	noteRel := "2026-02/21-10-15.md"
	notePath := owner + "/" + noteRel
	fullPath := filepath.Join(repo, owner, "notes", filepath.FromSlash(noteRel))
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	summary, err := idx.NoteSummaryByPath(ctx, notePath)
	if err != nil {
		t.Fatalf("note summary: %v", err)
	}
	if summary.Title != "Manual title" {
		t.Fatalf("summary title=%q want %q", summary.Title, "Manual title")
	}
}
