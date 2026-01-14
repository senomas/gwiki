package index

import (
	"strings"
	"testing"
	"time"
)

func TestEnsureFrontmatterAddsFields(t *testing.T) {
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	out, err := EnsureFrontmatter("# Title\n\nBody", now, 5)
	if err != nil {
		t.Fatalf("EnsureFrontmatter: %v", err)
	}

	fmLines, body, ok := splitFrontmatterLines(out)
	if !ok {
		t.Fatalf("expected frontmatter")
	}
	if !strings.Contains(body, "# Title") {
		t.Fatalf("expected body to include title")
	}

	fm := fmLineMap(fmLines)
	if fm["id"] == "" {
		t.Fatalf("expected id to be set")
	}
	if fm["created"] != now.Format(time.RFC3339) {
		t.Fatalf("expected created to be %s, got %s", now.Format(time.RFC3339), fm["created"])
	}
	if fm["updated"] != now.Format(time.RFC3339) {
		t.Fatalf("expected updated to be %s, got %s", now.Format(time.RFC3339), fm["updated"])
	}
	if fm["priority"] != "10" {
		t.Fatalf("expected priority to be 10, got %s", fm["priority"])
	}
	if _, ok := fm["title"]; ok {
		t.Fatalf("expected title to be omitted from frontmatter")
	}
	if !strings.Contains(strings.Join(fmLines, "\n"), "history:\n  - user: dummy") {
		t.Fatalf("expected history to be added")
	}
}

func TestEnsureFrontmatterPreservesIDAndCreated(t *testing.T) {
	now := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	input := strings.Join([]string{
		"---",
		"id: abc-123",
		"created: 2020-01-01T00:00:00Z",
		"updated: 2020-01-02T00:00:00Z",
		"---",
		"# Title",
	}, "\n")

	out, err := EnsureFrontmatter(input, now, 5)
	if err != nil {
		t.Fatalf("EnsureFrontmatter: %v", err)
	}

	fmLines, _, ok := splitFrontmatterLines(out)
	if !ok {
		t.Fatalf("expected frontmatter")
	}
	fm := fmLineMap(fmLines)
	if fm["id"] != "abc-123" {
		t.Fatalf("expected id to be preserved, got %s", fm["id"])
	}
	if fm["created"] != "2020-01-01T00:00:00Z" {
		t.Fatalf("expected created to be preserved, got %s", fm["created"])
	}
	if fm["priority"] != "10" {
		t.Fatalf("expected priority to default to 10, got %s", fm["priority"])
	}
	if _, ok := fm["title"]; ok {
		t.Fatalf("expected title to be omitted from frontmatter")
	}
	expectedUpdated := now.Format(time.RFC3339)
	if fm["updated"] != expectedUpdated {
		t.Fatalf("expected updated to be %s, got %s", expectedUpdated, fm["updated"])
	}
	if !strings.Contains(strings.Join(fmLines, "\n"), "action: edit") {
		t.Fatalf("expected history edit entry to be added")
	}
}

func TestEnsureFrontmatterNoUpdated(t *testing.T) {
	now := time.Date(2024, 4, 5, 6, 7, 8, 0, time.UTC)
	input := strings.Join([]string{
		"---",
		"id: abc-123",
		"created: 2020-01-01T00:00:00Z",
		"updated: 2020-01-02T00:00:00Z",
		"---",
		"# Title",
	}, "\n")

	out, err := EnsureFrontmatterWithTitleAndUserNoUpdated(input, now, 5, "Title", "tester")
	if err != nil {
		t.Fatalf("EnsureFrontmatterWithTitleAndUserNoUpdated: %v", err)
	}

	fmLines, _, ok := splitFrontmatterLines(out)
	if !ok {
		t.Fatalf("expected frontmatter")
	}
	fm := fmLineMap(fmLines)
	if fm["updated"] != "2020-01-02T00:00:00Z" {
		t.Fatalf("expected updated to stay the same, got %s", fm["updated"])
	}
	if !strings.Contains(strings.Join(fmLines, "\n"), "action: edit") {
		t.Fatalf("expected history edit entry to be added")
	}
}

func TestEnsureFrontmatterHistoryMax(t *testing.T) {
	now := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	input := strings.Join([]string{
		"---",
		"updated: 2024-03-04T05:06:07Z",
		"history:",
		"  - user: dummy",
		"    at: 2024-01-01T00:00:00Z",
		"    action: edit",
		"  - user: dummy",
		"    at: 2023-12-31T23:59:59Z",
		"    action: edit",
		"---",
		"# Title",
	}, "\n")

	out, err := EnsureFrontmatter(input, now, 2)
	if err != nil {
		t.Fatalf("EnsureFrontmatter: %v", err)
	}
	fmLines, _, ok := splitFrontmatterLines(out)
	if !ok {
		t.Fatalf("expected frontmatter")
	}
	historyBlock := strings.Join(fmLines, "\n")
	if strings.Count(historyBlock, "  - user: dummy") != 2 {
		t.Fatalf("expected history to be trimmed to 2 entries")
	}
}

func TestEnsureFrontmatterHistoryMergeWindow(t *testing.T) {
	now := time.Date(2024, 3, 4, 5, 20, 0, 0, time.UTC)
	input := strings.Join([]string{
		"---",
		"updated: 2024-03-04T05:10:00Z",
		"history:",
		"  - user: dummy",
		"    at: 2024-03-04T05:10:00Z",
		"    action: edit",
		"---",
		"# Title",
	}, "\n")

	out, err := EnsureFrontmatter(input, now, 10)
	if err != nil {
		t.Fatalf("EnsureFrontmatter: %v", err)
	}
	fmLines, _, ok := splitFrontmatterLines(out)
	if !ok {
		t.Fatalf("expected frontmatter")
	}
	historyBlock := strings.Join(fmLines, "\n")
	if strings.Count(historyBlock, "  - user: dummy") != 2 {
		t.Fatalf("expected history to merge within window without duplicate header")
	}
	if !strings.Contains(historyBlock, "at: 2024-03-04T05:20:00Z") {
		t.Fatalf("expected history timestamp to update")
	}
}

func fmLineMap(lines []string) map[string]string {
	out := make(map[string]string)
	for _, line := range lines {
		key, val := parseFrontmatterLine(line)
		key = strings.ToLower(key)
		if key != "" {
			out[key] = strings.TrimSpace(strings.Trim(val, "\""))
		}
	}
	return out
}
