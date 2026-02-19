package index

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestHiddenExclusiveForNoteList(t *testing.T) {
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
		"hidden.md":  "# Hidden\n\n#work! #tag1\n- [ ] hidden task #tag1\n",
		"visible.md": "# Visible\n\n#tag1\n- [ ] visible task #tag1\n",
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

	summary, err := idx.HiddenExclusiveForNoteList(ctx, NoteListFilter{
		Tags: []string{"tag1"},
	})
	if err != nil {
		t.Fatalf("hidden exclusive summary: %v", err)
	}
	if summary.Count != 1 {
		t.Fatalf("expected 1 hidden note, got %d (%+v)", summary.Count, summary)
	}
	if len(summary.Tags) != 1 || summary.Tags[0] != "work" {
		t.Fatalf("expected hidden exclusive tag [work], got %+v", summary.Tags)
	}

	summary, err = idx.HiddenExclusiveForNoteList(ctx, NoteListFilter{
		Tags: []string{"tag1", "work"},
	})
	if err != nil {
		t.Fatalf("hidden exclusive summary with work: %v", err)
	}
	if summary.Count != 0 {
		t.Fatalf("expected no hidden notes when exclusive tag is selected, got %+v", summary)
	}
}

func TestHiddenExclusiveForTasks(t *testing.T) {
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
		"hidden.md": strings.Join([]string{
			"# Hidden",
			"",
			"#work! #tag1",
			"- [ ] hidden open #tag1",
			"- [x] hidden done #tag1",
		}, "\n"),
		"visible.md": strings.Join([]string{
			"# Visible",
			"",
			"#tag1",
			"- [ ] visible open #tag1",
			"- [x] visible done #tag1",
		}, "\n"),
	}
	for relPath, content := range files {
		full := filepath.Join(notesDir, relPath)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", relPath, err)
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

	openSummary, err := idx.HiddenExclusiveForTasks(ctx, HiddenTaskFilter{
		Tags:      []string{"tag1"},
		OwnerName: owner,
		Checked:   false,
	})
	if err != nil {
		t.Fatalf("hidden exclusive open summary: %v", err)
	}
	if openSummary.Count != 1 {
		t.Fatalf("expected 1 hidden open note, got %+v", openSummary)
	}
	if len(openSummary.Tags) != 1 || openSummary.Tags[0] != "work" {
		t.Fatalf("expected hidden open exclusive tag [work], got %+v", openSummary.Tags)
	}

	doneSummary, err := idx.HiddenExclusiveForTasks(ctx, HiddenTaskFilter{
		Tags:      []string{"tag1"},
		OwnerName: owner,
		Checked:   true,
	})
	if err != nil {
		t.Fatalf("hidden exclusive completed summary: %v", err)
	}
	if doneSummary.Count != 1 {
		t.Fatalf("expected 1 hidden completed note, got %+v", doneSummary)
	}
	if len(doneSummary.Tags) != 1 || doneSummary.Tags[0] != "work" {
		t.Fatalf("expected hidden completed exclusive tag [work], got %+v", doneSummary.Tags)
	}
}
