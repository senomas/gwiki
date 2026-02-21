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

func TestJournalUpdatedAtForPathSplitJournal(t *testing.T) {
	got, ok := journalUpdatedAtForPath("local/2026-02/21-10-15.md")
	if !ok {
		t.Fatalf("journalUpdatedAtForPath split journal: expected ok")
	}
	want := time.Date(2026, time.February, 21, 10, 15, 59, 0, time.Local)
	if !got.Equal(want) {
		t.Fatalf("journalUpdatedAtForPath split journal=%s want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestJournalUpdatedAtForPathDailyJournal(t *testing.T) {
	got, ok := journalUpdatedAtForPath("local/2026-02/21.md")
	if !ok {
		t.Fatalf("journalUpdatedAtForPath daily journal: expected ok")
	}
	want := time.Date(2026, time.February, 21, 23, 59, 59, 0, time.Local)
	if !got.Equal(want) {
		t.Fatalf("journalUpdatedAtForPath daily journal=%s want %s", got.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestJournalDateForPathSplitJournal(t *testing.T) {
	got, ok := JournalDateForPath("local/2026-02/21-10-15.md")
	if !ok {
		t.Fatalf("JournalDateForPath split journal: expected ok")
	}
	if got != "2026-02-21" {
		t.Fatalf("JournalDateForPath split journal=%q want %q", got, "2026-02-21")
	}
}

func TestIndexNoteSplitJournalUpdatedAtFromPath(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	if err := os.MkdirAll(filepath.Join(repo, owner, "notes"), 0o755); err != nil {
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

	noteRel := "2026-02/21-10-15.md"
	notePath := owner + "/" + noteRel
	content := "journal split entry\n"
	mtime := time.Date(2020, time.January, 2, 3, 4, 5, 0, time.Local)
	if err := idx.IndexNote(ctx, notePath, []byte(content), mtime, int64(len(content))); err != nil {
		t.Fatalf("index note: %v", err)
	}

	var updatedAt int64
	var isJournal int
	if err := idx.queryRowContext(ctx, `
		SELECT files.updated_at, files.is_journal
		FROM files
		JOIN users ON users.id = files.user_id
		WHERE users.name = ? AND files.path = ?
	`, owner, noteRel).Scan(&updatedAt, &isJournal); err != nil {
		t.Fatalf("query updated_at: %v", err)
	}
	want := time.Date(2026, time.February, 21, 10, 15, 59, 0, time.Local).Unix()
	if updatedAt != want {
		t.Fatalf("split journal updated_at=%d want %d", updatedAt, want)
	}
	if isJournal != 1 {
		t.Fatalf("split journal is_journal=%d want 1", isJournal)
	}
}

func TestIndexNoteDailyJournalUpdatedAtFromPath(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	if err := os.MkdirAll(filepath.Join(repo, owner, "notes"), 0o755); err != nil {
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

	noteRel := "2026-02/21.md"
	notePath := owner + "/" + noteRel
	content := "daily journal entry\n"
	mtime := time.Date(2020, time.January, 2, 3, 4, 5, 0, time.Local)
	if err := idx.IndexNote(ctx, notePath, []byte(content), mtime, int64(len(content))); err != nil {
		t.Fatalf("index note: %v", err)
	}

	var updatedAt int64
	var isJournal int
	if err := idx.queryRowContext(ctx, `
		SELECT files.updated_at, files.is_journal
		FROM files
		JOIN users ON users.id = files.user_id
		WHERE users.name = ? AND files.path = ?
	`, owner, noteRel).Scan(&updatedAt, &isJournal); err != nil {
		t.Fatalf("query updated_at: %v", err)
	}
	want := time.Date(2026, time.February, 21, 23, 59, 59, 0, time.Local).Unix()
	if updatedAt != want {
		t.Fatalf("daily journal updated_at=%d want %d", updatedAt, want)
	}
	if isJournal != 1 {
		t.Fatalf("daily journal is_journal=%d want 1", isJournal)
	}
}

func TestIndexNoteNonJournalUpdatedFromFrontmatter(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	if err := os.MkdirAll(filepath.Join(repo, owner, "notes"), 0o755); err != nil {
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

	noteRel := "dev/plain.md"
	notePath := owner + "/" + noteRel
	content := "---\nupdated: 2024-01-02T03:04:05Z\n---\n\nbody\n"
	mtime := time.Date(2026, time.February, 21, 7, 8, 9, 0, time.Local)
	if err := idx.IndexNote(ctx, notePath, []byte(content), mtime, int64(len(content))); err != nil {
		t.Fatalf("index note: %v", err)
	}

	var updatedAt int64
	var isJournal int
	if err := idx.queryRowContext(ctx, `
		SELECT files.updated_at, files.is_journal
		FROM files
		JOIN users ON users.id = files.user_id
		WHERE users.name = ? AND files.path = ?
	`, owner, noteRel).Scan(&updatedAt, &isJournal); err != nil {
		t.Fatalf("query updated_at: %v", err)
	}
	want := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC).Unix()
	if updatedAt != want {
		t.Fatalf("non-journal updated_at=%d want %d", updatedAt, want)
	}
	if isJournal != 0 {
		t.Fatalf("non-journal is_journal=%d want 0", isJournal)
	}
}
