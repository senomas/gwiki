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
	expectedUpdated := now.Format(time.RFC3339) + ", 2020-01-02T00:00:00Z"
	if fm["updated"] != expectedUpdated {
		t.Fatalf("expected updated to be %s, got %s", expectedUpdated, fm["updated"])
	}
}

func TestEnsureFrontmatterUpdatedHistoryDedupAndMax(t *testing.T) {
	now := time.Date(2024, 3, 4, 5, 6, 7, 0, time.UTC)
	input := strings.Join([]string{
		"---",
		"updated: 2024-03-04T05:06:07Z, 2024-01-01T00:00:00Z, 2024-03-04T05:06:07Z, 2023-12-31T23:59:59Z",
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
	fm := fmLineMap(fmLines)
	expected := "2024-03-04T05:06:07Z, 2024-01-01T00:00:00Z"
	if fm["updated"] != expected {
		t.Fatalf("expected updated to be %s, got %s", expected, fm["updated"])
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
