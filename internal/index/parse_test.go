package index

import "testing"

func TestParseContent(t *testing.T) {
	input := `---
title: Test Note
tags: [alpha, beta]
---
# Ignored Title

Some text with #inline tag and a link [[Wiki Note]].

- [ ] Task one @due(2024-01-01)
- [x] Done task due:2024-02-02

[md](path/to.md)
`
	meta := ParseContent(input)
	if meta.Title != "Ignored Title" {
		t.Fatalf("expected title from H1, got %q", meta.Title)
	}
	if len(meta.Tags) < 2 {
		t.Fatalf("expected tags, got %v", meta.Tags)
	}
	if len(meta.Links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(meta.Links))
	}
	if len(meta.Tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(meta.Tasks))
	}
}

func TestStripFrontmatter(t *testing.T) {
	input := `---
title: Test Note
tags: [alpha, beta]
---
# Body Title

Body text.
`
	out := StripFrontmatter(input)
	if len(out) == 0 {
		t.Fatalf("expected body, got empty string")
	}
	if out[0:1] == "-" {
		t.Fatalf("expected frontmatter to be stripped")
	}
	if out != "# Body Title\n\nBody text.\n" {
		t.Fatalf("unexpected body: %q", out)
	}
}
