//go:build sqlite_fts5

package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFTSSearchMatchesPathTitleBody(t *testing.T) {
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
		"path-term.md": `# Title A

Body has nothing special.
`,
		"title-note.md": `# TitleTerm

Body without marker.
`,
		"body-note.md": `# Note

This mentions bodyterm and jan 18 in the content.
`,
		"frontmatter-note.md": `---
id: frontmatterterm
---
# Hidden

Body without the term.
`,
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

	results, err := idx.Search(ctx, "\"path-term\"", 10)
	if err != nil {
		t.Fatalf("search path term: %v", err)
	}
	if len(results) != 1 || results[0].Path != "local/path-term.md" {
		t.Fatalf("expected path match, got %+v", results)
	}

	results, err = idx.Search(ctx, "TitleTerm", 10)
	if err != nil {
		t.Fatalf("search title term: %v", err)
	}
	if len(results) != 1 || results[0].Path != "local/title-note.md" {
		t.Fatalf("expected title match, got %+v", results)
	}

	results, err = idx.Search(ctx, "bodyterm", 10)
	if err != nil {
		t.Fatalf("search body term: %v", err)
	}
	if len(results) != 1 || results[0].Path != "local/body-note.md" {
		t.Fatalf("expected body match, got %+v", results)
	}

	results, err = idx.Search(ctx, "frontmatterterm", 10)
	if err != nil {
		t.Fatalf("search frontmatter term: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected frontmatter term to be excluded, got %+v", results)
	}
}

func TestFTSSearchRankingPrefersStructuredFields(t *testing.T) {
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
		"title.md": `# rankfocus

Plain body text.
`,
		"h1.md": `# Intro

# rankfocus

Plain body text.
`,
		"h2.md": `# Intro

## rankfocus

Plain body text.
`,
		"h3.md": `# Intro

### rankfocus

Plain body text.
`,
		"body.md": `# Intro

Plain body rankfocus text.
`,
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

	results, err := idx.Search(ctx, "rankfocus", 10)
	if err != nil {
		t.Fatalf("search rankfocus: %v", err)
	}

	want := []string{
		"local/title.md",
		"local/h1.md",
		"local/h2.md",
		"local/h3.md",
		"local/body.md",
	}
	if len(results) < len(want) {
		t.Fatalf("expected at least %d results, got %+v", len(want), results)
	}
	for i, path := range want {
		if results[i].Path != path {
			t.Fatalf("unexpected rank at %d: want=%s got=%s full=%+v", i, path, results[i].Path, results)
		}
	}
}

func TestFTSSearchWithShortTokens(t *testing.T) {
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

	content := `# Note

Entry for jan 18 in the body.
`
	if err := os.WriteFile(filepath.Join(notesDir, "dates.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write dates note: %v", err)
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

	results, err := idx.SearchWithShortTokens(ctx, "jan", []string{"18"}, 10)
	if err != nil {
		t.Fatalf("search jan 18: %v", err)
	}
	if len(results) != 1 || results[0].Path != "local/dates.md" {
		t.Fatalf("expected jan 18 match, got %+v", results)
	}

	results, err = idx.SearchWithShortTokens(ctx, "jan", []string{"19"}, 10)
	if err != nil {
		t.Fatalf("search jan 19: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected jan 19 to return no matches, got %+v", results)
	}
}

func TestFTSSearchPathTitleWithShortTokens(t *testing.T) {
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
		"topic-aa.md": `# Find Topic

Body has no short token.
`,
		"body-only.md": `# Find Body

Body mentions aa but title/path do not.
`,
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

	results, err := idx.SearchPathTitleWithShortTokens(ctx, "(path:find* OR title:find*)", []string{"aa"}, 10)
	if err != nil {
		t.Fatalf("search path/title short tokens: %v", err)
	}
	if len(results) != 1 || results[0].Path != "local/topic-aa.md" {
		t.Fatalf("expected only path/title match, got %+v", results)
	}
}
