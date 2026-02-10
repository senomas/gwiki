package web

import (
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
	if remapped[0].LineNo != 1 {
		t.Fatalf("expected remapped line 1, got %d", remapped[0].LineNo)
	}
	if remapped[0].Hash != original[0].Hash {
		t.Fatalf("expected hash to stay same")
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
	if remapped[0].LineNo != 1 {
		t.Fatalf("expected first remapped line 1, got %d", remapped[0].LineNo)
	}
	if remapped[1].LineNo != 2 {
		t.Fatalf("expected second remapped line 2, got %d", remapped[1].LineNo)
	}
}

func TestRemapTasksToBodyLineNumbers_EmptyTasks(t *testing.T) {
	remapped := remapTasksToBodyLineNumbers("- [ ] open #inbox\n", nil)
	if remapped != nil {
		t.Fatalf("expected nil result for empty input tasks")
	}
}
