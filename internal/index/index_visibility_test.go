package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicVisibilityFilter(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	publicContent := `---
id: public-note
visibility: public
---
# Public Note

Shared content with #publictag.
`
	privateContent := `---
id: private-note
visibility: private
---
# Private Note

Secret bananas with #privatetag.
`
	if err := os.WriteFile(filepath.Join(notesDir, "public.md"), []byte(publicContent), 0o644); err != nil {
		t.Fatalf("write public note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "private.md"), []byte(privateContent), 0o644); err != nil {
		t.Fatalf("write private note: %v", err)
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

	publicCtx := WithPublicVisibility(ctx)
	notes, err := idx.NoteList(publicCtx, NoteListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("note list: %v", err)
	}
	if len(notes) != 1 || notes[0].Path != "public.md" {
		t.Fatalf("expected only public note, got %+v", notes)
	}

	results, err := idx.Search(publicCtx, "bananas", 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no private search results, got %+v", results)
	}

	tags, err := idx.ListTags(publicCtx, 100, "", false)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	for _, tag := range tags {
		if tag.Name == "privatetag" {
			t.Fatalf("private tag leaked: %+v", tags)
		}
	}

	exists, err := idx.NoteExists(publicCtx, "private.md")
	if err != nil {
		t.Fatalf("note exists: %v", err)
	}
	if exists {
		t.Fatalf("expected private note to be hidden from public access")
	}

	if err := os.Remove(filepath.Join(notesDir, "public.md")); err != nil {
		t.Fatalf("remove public note: %v", err)
	}
	if err := os.Remove(filepath.Join(notesDir, "private.md")); err != nil {
		t.Fatalf("remove private note: %v", err)
	}
	if _, _, _, err := idx.RecheckFromFS(ctx, repo); err != nil {
		t.Fatalf("recheck after delete: %v", err)
	}
	notes, err = idx.NoteList(publicCtx, NoteListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("note list after delete: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("expected no notes after delete, got %+v", notes)
	}
}
