package web

import "testing"

func TestArchivedDisplayTitleForNotePath_DailyJournalOverridesExplicit(t *testing.T) {
	got := archivedDisplayTitleForNotePath("local/2026-02/22.md", "Manual Daily Title")
	if got != "22 Feb 2026" {
		t.Fatalf("archived daily journal title=%q want %q", got, "22 Feb 2026")
	}
}

func TestArchivedDisplayTitleForNotePath_SplitJournalOverridesExplicit(t *testing.T) {
	got := archivedDisplayTitleForNotePath("local/2026-02/22-09-35.md", "Manual Split Title")
	if got != "22 Feb 2026 09:35" {
		t.Fatalf("archived split journal title=%q want %q", got, "22 Feb 2026 09:35")
	}
}

func TestArchivedDisplayTitleForNotePath_SplitJournalSuffixOverridesExplicit(t *testing.T) {
	got := archivedDisplayTitleForNotePath("local/2026-02/22-09-35-2.md", "Manual Split Suffix Title")
	if got != "22 Feb 2026 09:35" {
		t.Fatalf("archived split suffix journal title=%q want %q", got, "22 Feb 2026 09:35")
	}
}

func TestArchivedDisplayTitleForNotePath_NonJournalFallsBack(t *testing.T) {
	got := archivedDisplayTitleForNotePath("local/tasks.md", "Manual Title")
	if got != "Manual Title" {
		t.Fatalf("archived non-journal title=%q want %q", got, "Manual Title")
	}
}
