package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExclusiveTagsFiltering(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	files := map[string]string{
		"a.md": "# A\n\n#work! #btn\n",
		"b.md": "# B\n\n#btn\n",
		"c.md": "# C\n\n#bni\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(notesDir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
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

	notes, err := idx.NoteList(ctx, NoteListFilter{Limit: 50})
	if err != nil {
		t.Fatalf("note list: %v", err)
	}
	paths := map[string]struct{}{}
	for _, note := range notes {
		paths[note.Path] = struct{}{}
	}
	if _, ok := paths["local/a.md"]; ok {
		t.Fatalf("expected exclusive note to be hidden without filter")
	}
	if _, ok := paths["local/b.md"]; !ok {
		t.Fatalf("expected non-exclusive note b.md in list")
	}
	if _, ok := paths["local/c.md"]; !ok {
		t.Fatalf("expected non-exclusive note c.md in list")
	}

	notes, err = idx.NoteList(ctx, NoteListFilter{Tags: []string{"work"}, Limit: 50})
	if err != nil {
		t.Fatalf("note list filtered: %v", err)
	}
	if len(notes) != 1 || notes[0].Path != "local/a.md" {
		t.Fatalf("expected only a.md when filtering by work, got %#v", notes)
	}

	notes, err = idx.NoteList(ctx, NoteListFilter{Tags: []string{"work", "btn"}, Limit: 50})
	if err != nil {
		t.Fatalf("note list filtered (work+btn): %v", err)
	}
	if len(notes) != 1 || notes[0].Path != "local/a.md" {
		t.Fatalf("expected a.md when filtering by work+btn, got %#v", notes)
	}

	notes, err = idx.NoteList(ctx, NoteListFilter{Tags: []string{"work", "bni"}, Limit: 50})
	if err != nil {
		t.Fatalf("note list filtered (work+bni): %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("expected no notes when filtering by work+bni, got %#v", notes)
	}

	tags, err := idx.ListTags(ctx, 100, "", false, false, "")
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	tagSet := map[string]struct{}{}
	for _, tag := range tags {
		tagSet[tag.Name] = struct{}{}
	}
	if _, ok := tagSet["work"]; !ok {
		t.Fatalf("expected exclusive tag to appear in list")
	}
	if _, ok := tagSet["btn"]; !ok {
		t.Fatalf("expected tag btn in list")
	}
	if _, ok := tagSet["bni"]; !ok {
		t.Fatalf("expected tag bni in list")
	}
}
