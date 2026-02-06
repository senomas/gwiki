package index

import (
	"strings"
	"testing"
)

func TestParseContent(t *testing.T) {
	input := strings.Join([]string{
		"---",
		"title: Test Note",
		"tags: [alpha, beta]",
		"---",
		"# Ignored Title",
		"",
		"Some text with #inline tag, #travel/food and a link [[Wiki Note]].",
		"Ping @dev and user@domain.com",
		"",
		"- [ ] Task one @due(2024-01-01)",
		"- [x] Done task due:2024-02-02",
		"",
		"[md](path/to.md)",
		"",
		"```",
		"#codeblock",
		"```",
		"",
		"    #indented",
		"",
	}, "\n")
	meta := ParseContent(input)
	if meta.Title != "Ignored Title" {
		t.Fatalf("expected title from H1, got %q", meta.Title)
	}
	if len(meta.Tags) < 2 {
		t.Fatalf("expected tags, got %v", meta.Tags)
	}
	for _, tag := range []string{"travel", "travel/food"} {
		found := false
		for _, existing := range meta.Tags {
			if existing == tag {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected tag %q, got %v", tag, meta.Tags)
		}
	}
	found := false
	for _, existing := range meta.Tags {
		if existing == "@dev" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mention tag %q, got %v", "@dev", meta.Tags)
	}
	for _, existing := range meta.Tags {
		if existing == "@domain" || existing == "@user@domain.com" {
			t.Fatalf("unexpected mention tag from email, got %v", meta.Tags)
		}
	}
	if len(meta.Links) != 2 {
		t.Fatalf("expected 2 links, got %d", len(meta.Links))
	}
	for _, link := range meta.Links {
		if link.LineNo <= 0 {
			t.Fatalf("expected link line_no to be set, got %d", link.LineNo)
		}
		if strings.TrimSpace(link.Line) == "" {
			t.Fatalf("expected link line to be set")
		}
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

func TestUncheckedTasksSnippet(t *testing.T) {
	input := `---
title: Demo
---
# demo-cache

cache 4

## demo

- [ ] demo

  Call me at https://wa.me/628129777287 thanks

  - [x] finished subtask

    ignored details

- foo

  https://chatgpt.com/s/t_696d2140457c819180ea7dfed7e578d9
- [x] sample foo

  https://youtu.be/Yzb5c-fIfnM

  demoo
`
	out := UncheckedTasksSnippet(input)
	expected := `---
title: Demo
---

# demo-cache

- [ ] demo

  Call me at https://wa.me/628129777287 thanks
`
	if out != expected {
		t.Fatalf("unexpected snippet:\n%s", out)
	}
}

func TestParseTaskTags(t *testing.T) {
	input := strings.Join([]string{
		"# demo",
		"",
		"- [ ] task one #alpha",
		"",
		"  details with #beta and #work/btn",
		"  ping @dev and user@domain.com",
		"",
		"  ```",
		"  #codeblock",
		"  ```",
		"",
		"      #indented",
		"",
		"- [ ] task two",
		"",
	}, "\n")
	meta := ParseContent(input)
	if len(meta.Tasks) < 2 {
		t.Fatalf("expected tasks, got %d", len(meta.Tasks))
	}
	first := meta.Tasks[0]
	if len(first.Tags) == 0 {
		t.Fatalf("expected task tags, got none")
	}
	tagSet := map[string]struct{}{}
	for _, tag := range first.Tags {
		tagSet[tag] = struct{}{}
	}
	for _, want := range []string{"alpha", "beta", "work", "work/btn"} {
		if _, ok := tagSet[want]; !ok {
			t.Fatalf("expected task tag %q, got %v", want, first.Tags)
		}
	}
	if _, ok := tagSet["@dev"]; !ok {
		t.Fatalf("expected mention tag %q, got %v", "@dev", first.Tags)
	}
	if _, ok := tagSet["@domain"]; ok {
		t.Fatalf("unexpected mention tag from email, got %v", first.Tags)
	}
	second := meta.Tasks[1]
	if len(second.Tags) != 0 {
		t.Fatalf("expected no tags for second task, got %v", second.Tags)
	}
}

func TestDueTasksSnippet(t *testing.T) {
	input := `---
title: Demo
---
# demo-cache

## demo

- [ ] demo @due(2026-01-20)

  Call me at https://wa.me/628129777287 thanks

- [ ] no due here

  https://chatgpt.com/s/t_696d2140457c819180ea7dfed7e578d9
- [x] sample foo due:2026-01-21

  https://youtu.be/Yzb5c-fIfnM
`
	out := DueTasksSnippet(input)
	expected := `---
title: Demo
---

# demo-cache

- [ ] demo @due(2026-01-20)

  Call me at https://wa.me/628129777287 thanks
`
	if out != expected {
		t.Fatalf("unexpected snippet:\n%s", out)
	}
}

func TestDueTasksSnippetWithDefaultDate(t *testing.T) {
	input := `# demo-cache

- [ ] demo

  Call me at https://wa.me/628129777287 thanks

- [ ] has due @due(2026-02-01)
`
	out := DueTasksSnippetWithDefaultDate(input, "2026-01-15")
	expected := `# demo-cache

- [ ] demo due:2026-01-15

  Call me at https://wa.me/628129777287 thanks

- [ ] has due @due(2026-02-01)
`
	if out != expected {
		t.Fatalf("unexpected snippet:\n%s", out)
	}
}
