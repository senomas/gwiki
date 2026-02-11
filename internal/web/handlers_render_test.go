package web

import (
	"strings"
	"testing"

	"gwiki/internal/index"
)

func TestRemapTasksToBodyLineNumbers_ShiftAfterFilter(t *testing.T) {
	body := "- [ ] open #inbox\n"
	original := []index.Task{
		{
			LineNo: 2,
			Hash:   index.TaskLineHash("- [ ] open #inbox"),
			Done:   false,
		},
	}

	remapped := remapTasksToBodyLineNumbers(body, original)
	if len(remapped) != 1 {
		t.Fatalf("expected 1 task, got %d", len(remapped))
	}
	if remapped[0].DisplayLineNo != 1 {
		t.Fatalf("expected remapped display line 1, got %d", remapped[0].DisplayLineNo)
	}
	if remapped[0].SourceLineNo != 2 {
		t.Fatalf("expected source line to remain 2, got %d", remapped[0].SourceLineNo)
	}
}

func TestRemapTasksToBodyLineNumbers_DuplicateHashOrder(t *testing.T) {
	line := "- [ ] same #inbox"
	body := line + "\n" + line + "\n"
	hash := index.TaskLineHash(line)
	original := []index.Task{
		{LineNo: 10, Hash: hash, Done: false},
		{LineNo: 20, Hash: hash, Done: false},
	}

	remapped := remapTasksToBodyLineNumbers(body, original)
	if len(remapped) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(remapped))
	}
	if remapped[0].DisplayLineNo != 1 {
		t.Fatalf("expected first remapped display line 1, got %d", remapped[0].DisplayLineNo)
	}
	if remapped[1].DisplayLineNo != 2 {
		t.Fatalf("expected second remapped display line 2, got %d", remapped[1].DisplayLineNo)
	}
	if remapped[0].SourceLineNo != 10 {
		t.Fatalf("expected first source line 10, got %d", remapped[0].SourceLineNo)
	}
	if remapped[1].SourceLineNo != 20 {
		t.Fatalf("expected second source line 20, got %d", remapped[1].SourceLineNo)
	}
}

func TestRemapTasksToBodyLineNumbers_PreservesSourceLineAfterShift(t *testing.T) {
	line := "- [ ] shifted #inbox"
	body := strings.Repeat("prefix\n", 29) + line + "\n"
	hash := index.TaskLineHash(line)
	original := []index.Task{
		{LineNo: 21, Hash: hash, Done: false},
	}

	remapped := remapTasksToBodyLineNumbers(body, original)
	if len(remapped) != 1 {
		t.Fatalf("expected 1 task, got %d", len(remapped))
	}
	if remapped[0].DisplayLineNo != 30 {
		t.Fatalf("expected display line 30, got %d", remapped[0].DisplayLineNo)
	}
	if remapped[0].SourceLineNo != 21 {
		t.Fatalf("expected source line 21, got %d", remapped[0].SourceLineNo)
	}
}

func TestRemapTasksToBodyLineNumbers_EmptyTasks(t *testing.T) {
	remapped := remapTasksToBodyLineNumbers("- [ ] open #inbox\n", nil)
	if remapped != nil {
		t.Fatalf("expected nil result for empty input tasks")
	}
}

func TestInjectInboxLinks_UsesSourceLineRange(t *testing.T) {
	lines := []string{
		"- [ ] item #inbox #signal",
		"",
		"  detail line",
		"",
	}
	out := injectInboxLinks(lines, "note-uid", "/notes/new?o=seno", []inboxLinkTask{
		{
			DisplayLineNo: 1,
			SourceLineNo:  21,
		},
	})
	if len(out) != len(lines) {
		t.Fatalf("expected %d lines, got %d", len(lines), len(out))
	}
	if !strings.Contains(out[0], "/notes/new?line=21-24&note=note-uid&o=seno&type=inbox") {
		t.Fatalf("expected source line range in generated link, got %q", out[0])
	}
}
