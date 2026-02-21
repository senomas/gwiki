package web

import (
	"strings"
	"testing"
	"time"

	"gwiki/internal/index"
)

func TestFilterFutureJournalTasks(t *testing.T) {
	now := time.Date(2026, 1, 19, 12, 0, 0, 0, time.Local)
	owner := "local"
	tasks := []index.TaskItem{
		{Path: owner + "/2026-01/18.md", Text: "past", Hash: "a", FileID: 1},
		{Path: owner + "/2026-01/19.md", Text: "today", Hash: "b", FileID: 2},
		{Path: owner + "/2026-01/21.md", Text: "future", Hash: "c", FileID: 3},
		{Path: owner + "/notes/normal.md", Text: "normal", Hash: "d", FileID: 4},
	}
	filtered := filterFutureJournalTasks(tasks, now)
	if len(filtered) != 3 {
		t.Fatalf("expected 3 tasks after filter, got %d", len(filtered))
	}
	for _, task := range filtered {
		if task.Path == owner+"/2026-01/21.md" {
			t.Fatalf("future journal task should be filtered")
		}
	}
}

func TestFilterFutureJournalTasksSplitJournalPaths(t *testing.T) {
	now := time.Date(2026, 1, 19, 12, 0, 0, 0, time.Local)
	owner := "local"
	tasks := []index.TaskItem{
		{Path: owner + "/2026-01/19-09-30.md", Text: "today split", Hash: "a", FileID: 1},
		{Path: owner + "/2026-01/21-08-00-2.md", Text: "future split", Hash: "b", FileID: 2},
		{Path: owner + "/notes/normal.md", Text: "normal", Hash: "c", FileID: 3},
	}
	filtered := filterFutureJournalTasks(tasks, now)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 tasks after filter, got %d", len(filtered))
	}
	for _, task := range filtered {
		if task.Path == owner+"/2026-01/21-08-00-2.md" {
			t.Fatalf("future split journal task should be filtered")
		}
	}
}

func TestApplyRenderReplacementsDue(t *testing.T) {
	input := `<p>Pay rent due:2026-02-05 and call @due(2026-02-07).</p>`
	out := applyRenderReplacements(input)
	if !strings.Contains(out, "Due 5 Feb 2026") {
		t.Fatalf("expected formatted due date, got %q", out)
	}
	if !strings.Contains(out, "Due 7 Feb 2026") {
		t.Fatalf("expected formatted due date for second token, got %q", out)
	}
	if strings.Contains(out, "due:2026-02-05") || strings.Contains(out, "@due(2026-02-07)") {
		t.Fatalf("expected due tokens to be replaced, got %q", out)
	}
}

func TestApplyRenderReplacementsMissingWikiLinkAddsClassAndRef(t *testing.T) {
	input := `<p><a href="/__missing__?ref=%40alice%2Fdemo%2Ffile.md">Demo</a></p>`
	out := applyRenderReplacements(input)
	if !strings.Contains(out, `class="js-wiki-missing"`) {
		t.Fatalf("expected missing-link class, got %q", out)
	}
	if !strings.Contains(out, `data-wiki-ref="@alice/demo/file.md"`) {
		t.Fatalf("expected decoded data-wiki-ref, got %q", out)
	}
}

func TestApplyRenderReplacementsMissingWikiLinkMergesClassWithoutDuplicates(t *testing.T) {
	input := `<p><a class="foo" href="/__missing__?ref=demo.md">Demo</a></p>`
	out := applyRenderReplacements(input)
	if !strings.Contains(out, `class="foo js-wiki-missing"`) {
		t.Fatalf("expected class merge, got %q", out)
	}
	if strings.Count(out, "js-wiki-missing") != 1 {
		t.Fatalf("expected js-wiki-missing once, got %q", out)
	}
}

func TestApplyRenderReplacementsMissingWikiLinkIsIdempotent(t *testing.T) {
	input := `<p><a href="/__missing__?ref=demo%20note.md">Demo</a></p>`
	out1 := applyRenderReplacements(input)
	out2 := applyRenderReplacements(out1)
	if out1 != out2 {
		t.Fatalf("expected idempotent replacement\nfirst: %q\nsecond:%q", out1, out2)
	}
}

func TestApplyRenderReplacementsNonMissingLinkUnchanged(t *testing.T) {
	input := `<p><a href="/notes/@alice/demo.md">Demo</a></p>`
	out := applyRenderReplacements(input)
	if out != input {
		t.Fatalf("expected non-missing link unchanged, got %q", out)
	}
}

func TestBuildTodoTagFilteredRenderTasks_ContextBeforeSnippet(t *testing.T) {
	tasks := []index.TaskItem{
		{LineNo: 2, Hash: strings.Repeat("a", 64)},
		{LineNo: 5, Hash: strings.Repeat("b", 64)},
		{LineNo: 9, Hash: strings.Repeat("c", 64)},
	}
	renderTasks := buildTodoTagFilteredRenderTasks(tasks, []int{5})
	if len(renderTasks) != 3 {
		t.Fatalf("expected 3 render tasks, got %d", len(renderTasks))
	}
	if renderTasks[0].LineNo != 5 {
		t.Fatalf("expected context task first, got line %d", renderTasks[0].LineNo)
	}
	if renderTasks[1].LineNo != 2 || renderTasks[2].LineNo != 9 {
		t.Fatalf("expected snippet tasks after context in source order, got %+v", renderTasks)
	}
}
