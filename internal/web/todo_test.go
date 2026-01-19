package web

import (
	"testing"
	"time"

	"gwiki/internal/index"
)

func TestFilterFutureJournalTasks(t *testing.T) {
	now := time.Date(2026, 1, 19, 12, 0, 0, 0, time.Local)
	tasks := []index.TaskItem{
		{Path: "2026-01/18.md", Text: "past", Hash: "a", FileID: 1},
		{Path: "2026-01/19.md", Text: "today", Hash: "b", FileID: 2},
		{Path: "2026-01/21.md", Text: "future", Hash: "c", FileID: 3},
		{Path: "notes/normal.md", Text: "normal", Hash: "d", FileID: 4},
	}
	filtered := filterFutureJournalTasks(tasks, now)
	if len(filtered) != 3 {
		t.Fatalf("expected 3 tasks after filter, got %d", len(filtered))
	}
	for _, task := range filtered {
		if task.Path == "2026-01/21.md" {
			t.Fatalf("future journal task should be filtered")
		}
	}
}
