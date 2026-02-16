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

func TestFilterCompletedTasksWithHidden(t *testing.T) {
	input := strings.Join([]string{
		"# Title",
		"",
		"- [ ] open task",
		"- [x] done task",
		"  hidden detail",
		"",
		"## Empty",
		"",
		"## Keep",
		"visible text",
		"",
		"- [x] done task two",
		"",
		"after",
	}, "\n")

	result := FilterCompletedTasksWithHidden(input)

	if result.CompletedCount != 2 {
		t.Fatalf("expected completed count 2, got %d", result.CompletedCount)
	}
	if len(result.OpenTasks) != 1 {
		t.Fatalf("expected 1 open task, got %d", len(result.OpenTasks))
	}
	if result.OpenTasks[0].LineNo != 3 {
		t.Fatalf("expected open task line 3, got %d", result.OpenTasks[0].LineNo)
	}
	if strings.Contains(result.Visible, "done task") {
		t.Fatalf("visible snippet should not include completed tasks:\n%s", result.Visible)
	}
	if strings.Contains(result.Visible, "## Empty") {
		t.Fatalf("visible snippet should not include empty h2:\n%s", result.Visible)
	}
	if !strings.Contains(result.Visible, "## Keep") {
		t.Fatalf("visible snippet should include non-empty h2:\n%s", result.Visible)
	}
	if len(result.Hidden) != 3 {
		t.Fatalf("expected 3 hidden blocks, got %d (%+v)", len(result.Hidden), result.Hidden)
	}
	if result.Hidden[0].StartLine != 4 || result.Hidden[0].EndLine != 5 || result.Hidden[0].Kind != HiddenBlockKindCompleted {
		t.Fatalf("unexpected first hidden block: %+v", result.Hidden[0])
	}
	if !strings.Contains(result.Hidden[0].Markdown, "done task") {
		t.Fatalf("expected completed task markdown in first hidden block: %+v", result.Hidden[0])
	}
	if result.Hidden[1].StartLine != 7 || result.Hidden[1].EndLine != 7 || result.Hidden[1].Kind != HiddenBlockKindEmptyH2 {
		t.Fatalf("unexpected second hidden block: %+v", result.Hidden[1])
	}
	if strings.TrimSpace(result.Hidden[1].Markdown) != "## Empty" {
		t.Fatalf("unexpected empty h2 markdown: %q", result.Hidden[1].Markdown)
	}
	if result.Hidden[2].StartLine != 12 || result.Hidden[2].EndLine != 12 || result.Hidden[2].Kind != HiddenBlockKindCompleted {
		t.Fatalf("unexpected third hidden block: %+v", result.Hidden[2])
	}
}

func TestFilterCompletedTasksSnippetCompatibility(t *testing.T) {
	input := strings.Join([]string{
		"- [ ] open",
		"- [x] done",
		"## Empty",
		"",
	}, "\n")

	visible, completed, tasks := FilterCompletedTasksSnippet(input)
	structured := FilterCompletedTasksWithHidden(input)

	if visible != structured.Visible {
		t.Fatalf("expected visible compatibility, got:\n%s\nwant:\n%s", visible, structured.Visible)
	}
	if completed != structured.CompletedCount {
		t.Fatalf("expected completed compatibility %d, got %d", structured.CompletedCount, completed)
	}
	if len(tasks) != len(structured.OpenTasks) {
		t.Fatalf("expected tasks compatibility len %d, got %d", len(structured.OpenTasks), len(tasks))
	}
}

func TestParseNoteBlocksAddsSyntheticRoot(t *testing.T) {
	input := strings.Join([]string{
		"alpha",
		"beta",
	}, "\n")

	blocks := ParseNoteBlocks(input)
	if len(blocks) < 2 {
		t.Fatalf("expected at least root + child blocks, got %d (%+v)", len(blocks), blocks)
	}

	root := blocks[0]
	if root.ParentID != 0 || root.Level != 0 {
		t.Fatalf("unexpected synthetic root hierarchy: %+v", root)
	}
	if root.StartLine != 1 || root.EndLine != 2 {
		t.Fatalf("unexpected synthetic root line span: %+v", root)
	}
	if root.Markdown != input {
		t.Fatalf("unexpected synthetic root markdown: %q", root.Markdown)
	}
}

func TestParseNoteBlocksListHierarchyMatchesRequestedShape(t *testing.T) {
	input := strings.Join([]string{
		"- xxx",
		"  uuu",
		"",
		"    aaa",
		"    bbb",
		"",
		"- zzz",
		"  www",
	}, "\n")

	blocks := ParseNoteBlocks(input)
	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks (root + item1 + nested + item2), got %d (%+v)", len(blocks), blocks)
	}

	root := blocks[0]
	firstItem := blocks[1]
	nested := blocks[2]
	secondItem := blocks[3]

	if root.ParentID != 0 || root.Level != 0 || root.StartLine != 1 || root.EndLine != 8 {
		t.Fatalf("unexpected root block: %+v", root)
	}
	if firstItem.ParentID != root.ID || firstItem.Level != 1 {
		t.Fatalf("unexpected first item hierarchy: %+v", firstItem)
	}
	if secondItem.ParentID != root.ID || secondItem.Level != 1 {
		t.Fatalf("unexpected second item hierarchy: %+v", secondItem)
	}
	if firstItem.StartLine != 1 || firstItem.EndLine != 5 {
		t.Fatalf("unexpected first item span: %+v", firstItem)
	}
	if secondItem.StartLine != 7 || secondItem.EndLine != 8 {
		t.Fatalf("unexpected second item span: %+v", secondItem)
	}

	if nested.ParentID != firstItem.ID || nested.Level != 2 {
		t.Fatalf("unexpected nested block hierarchy: %+v", nested)
	}
	if nested.StartLine != 4 || nested.EndLine != 5 {
		t.Fatalf("unexpected nested block span: %+v", nested)
	}
	if !strings.Contains(nested.Markdown, "aaa") || !strings.Contains(nested.Markdown, "bbb") {
		t.Fatalf("unexpected nested markdown: %q", nested.Markdown)
	}
}

func TestParseNoteBlocksHeaderAndSeparatorHierarchy(t *testing.T) {
	input := strings.Join([]string{
		"# Root",
		"root text",
		"---",
		"## Child",
		"child text",
	}, "\n")

	blocks := ParseNoteBlocks(input)
	if len(blocks) != 6 {
		t.Fatalf("expected 6 blocks, got %d (%+v)", len(blocks), blocks)
	}

	root := blocks[0]
	h1 := blocks[1]
	rootText := blocks[2]
	separator := blocks[3]
	h2 := blocks[4]
	h2Text := blocks[5]

	if h1.ParentID != root.ID || h1.Level != 1 {
		t.Fatalf("unexpected h1 hierarchy: %+v", h1)
	}
	if h1.StartLine != 1 || h1.EndLine != 5 {
		t.Fatalf("unexpected h1 span: %+v", h1)
	}
	if rootText.ParentID != h1.ID || rootText.Level != 2 {
		t.Fatalf("unexpected root text hierarchy: %+v", rootText)
	}
	if separator.ParentID != h1.ID || separator.Level != 2 || strings.TrimSpace(separator.Markdown) != "---" {
		t.Fatalf("unexpected separator block: %+v", separator)
	}
	if h2.ParentID != h1.ID || h2.Level != 2 {
		t.Fatalf("unexpected h2 hierarchy: %+v", h2)
	}
	if h2.StartLine != 4 || h2.EndLine != 5 {
		t.Fatalf("unexpected h2 span: %+v", h2)
	}
	if h2Text.ParentID != h2.ID || h2Text.Level != 3 {
		t.Fatalf("unexpected h2 text hierarchy: %+v", h2Text)
	}
}

func TestParseNoteBlocksSkipsEmptyOnlyBlocks(t *testing.T) {
	input := strings.Join([]string{
		"# Root",
		"",
		"## Child",
		"",
		"child body",
		"",
	}, "\n")

	blocks := ParseNoteBlocks(input)
	if len(blocks) == 0 {
		t.Fatalf("expected non-empty blocks")
	}
	for _, block := range blocks {
		if strings.TrimSpace(block.Markdown) == "" {
			t.Fatalf("unexpected empty-only block: %+v", block)
		}
	}
}

func TestParseNoteBlocksTrimsPrefixSuffixEmptyLines(t *testing.T) {
	input := strings.Join([]string{
		"",
		"",
		"# Root",
		"",
		"text",
		"",
		"",
	}, "\n")

	blocks := ParseNoteBlocks(input)
	if len(blocks) < 2 {
		t.Fatalf("expected root and child blocks, got %d (%+v)", len(blocks), blocks)
	}

	root := blocks[0]
	if root.StartLine != 3 || root.EndLine != 5 {
		t.Fatalf("unexpected trimmed root span: %+v", root)
	}
	if strings.HasPrefix(root.Markdown, "\n") || strings.HasSuffix(root.Markdown, "\n") {
		t.Fatalf("expected trimmed root markdown without prefix/suffix empty lines: %q", root.Markdown)
	}
}
