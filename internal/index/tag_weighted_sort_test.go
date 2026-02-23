package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createIndexWithNotes(t *testing.T, notes map[string]string) (*Index, context.Context, string) {
	t.Helper()

	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	for relPath, content := range notes {
		fullPath := filepath.Join(notesDir, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", relPath, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", relPath, err)
		}
	}

	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	t.Cleanup(func() {
		_ = idx.Close()
	})

	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}
	return idx, ctx, owner
}

func setNoteUpdatedAt(t *testing.T, idx *Index, ctx context.Context, ownerName, relPath string, updatedAt int64) {
	t.Helper()
	res, err := idx.execContext(ctx, `
		UPDATE files
		SET updated_at=?, mtime_unix=?
		WHERE user_id=(SELECT id FROM users WHERE name=?) AND path=?
	`, updatedAt, updatedAt, ownerName, relPath)
	if err != nil {
		t.Fatalf("update file updated_at %s: %v", relPath, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		t.Fatalf("update file updated_at %s: no rows affected", relPath)
	}
}

func setNoteActionDate(t *testing.T, idx *Index, ctx context.Context, ownerName, relPath string, actionDate int64) {
	t.Helper()
	res, err := idx.execContext(ctx, `
		UPDATE file_histories
		SET action_date=?
		WHERE file_id=(
			SELECT id
			FROM files
			WHERE user_id=(SELECT id FROM users WHERE name=?) AND path=?
		)
	`, actionDate, ownerName, relPath)
	if err != nil {
		t.Fatalf("update file action_date %s: %v", relPath, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		t.Fatalf("update file action_date %s: no rows affected", relPath)
	}
}

func indexTagNames(tags []TagSummary) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		out = append(out, tag.Name)
	}
	return out
}

func tagCountByName(tags []TagSummary, name string) (int, bool) {
	for _, tag := range tags {
		if tag.Name == name {
			return tag.Count, true
		}
	}
	return 0, false
}

func TestListTagsWeightedRecencyOrderAndRawCount(t *testing.T) {
	idx, ctx, owner := createIndexWithNotes(t, map[string]string{
		"new.md":   "# New\n\n#new\n",
		"old-1.md": "# Old 1\n\n#old\n",
		"old-2.md": "# Old 2\n\n#old\n",
	})

	now := time.Now().Unix()
	setNoteUpdatedAt(t, idx, ctx, owner, "new.md", now-2*secondsPerDay)
	setNoteUpdatedAt(t, idx, ctx, owner, "old-1.md", now-500*secondsPerDay)
	setNoteUpdatedAt(t, idx, ctx, owner, "old-2.md", now-700*secondsPerDay)

	tags, err := idx.ListTags(ctx, 20, "", false, false, "")
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	if len(tags) < 2 {
		t.Fatalf("expected at least 2 tags, got %v", indexTagNames(tags))
	}
	if tags[0].Name != "new" {
		t.Fatalf("expected most recent-weighted tag first, got %v", indexTagNames(tags))
	}

	if count, ok := tagCountByName(tags, "new"); !ok || count != 1 {
		t.Fatalf("expected raw count for new=1, got ok=%v count=%d", ok, count)
	}
	if count, ok := tagCountByName(tags, "old"); !ok || count != 2 {
		t.Fatalf("expected raw count for old=2, got ok=%v count=%d", ok, count)
	}
}

func TestListTagsWeightedTieBreakers(t *testing.T) {
	idx, ctx, owner := createIndexWithNotes(t, map[string]string{
		"countwin-1.md":  "# Count Win 1\n\n#countwin\n",
		"countwin-2.md":  "# Count Win 2\n\n#countwin\n",
		"countwin-3.md":  "# Count Win 3\n\n#countwin\n",
		"countwin-4.md":  "# Count Win 4\n\n#countwin\n",
		"countlose-1.md": "# Count Lose\n\n#countlose\n",
		"alpha-1.md":     "# Alpha\n\n#alpha\n",
		"beta-1.md":      "# Beta\n\n#beta\n",
	})

	now := time.Now().Unix()
	setNoteUpdatedAt(t, idx, ctx, owner, "countwin-1.md", now-20*secondsPerDay)  // 5
	setNoteUpdatedAt(t, idx, ctx, owner, "countwin-2.md", now-120*secondsPerDay) // 3
	setNoteUpdatedAt(t, idx, ctx, owner, "countwin-3.md", now-500*secondsPerDay) // 1
	setNoteUpdatedAt(t, idx, ctx, owner, "countwin-4.md", now-700*secondsPerDay) // 1
	setNoteUpdatedAt(t, idx, ctx, owner, "countlose-1.md", now-2*secondsPerDay)  // 10
	setNoteUpdatedAt(t, idx, ctx, owner, "alpha-1.md", now-2*secondsPerDay)      // 10
	setNoteUpdatedAt(t, idx, ctx, owner, "beta-1.md", now-2*secondsPerDay)       // 10

	tags, err := idx.ListTags(ctx, 20, "", false, false, "")
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	got := indexTagNames(tags)
	wantPrefix := []string{"countwin", "alpha", "beta", "countlose"}
	if len(got) < len(wantPrefix) {
		t.Fatalf("expected at least %d tags, got %v", len(wantPrefix), got)
	}
	for i := range wantPrefix {
		if got[i] != wantPrefix[i] {
			t.Fatalf("unexpected order: got=%v want prefix=%v", got, wantPrefix)
		}
	}
}

func TestListTagsFilteredUsesWeightedOrder(t *testing.T) {
	idx, ctx, owner := createIndexWithNotes(t, map[string]string{
		"old-focus.md": "# Old Focus\n\n#focus #old\n",
		"new-focus.md": "# New Focus\n\n#focus #new\n",
		"other.md":     "# Other\n\n#other\n",
	})

	now := time.Now().Unix()
	setNoteUpdatedAt(t, idx, ctx, owner, "old-focus.md", now-600*secondsPerDay)
	setNoteUpdatedAt(t, idx, ctx, owner, "new-focus.md", now-2*secondsPerDay)
	setNoteUpdatedAt(t, idx, ctx, owner, "other.md", now-2*secondsPerDay)

	tags, err := idx.ListTagsFiltered(ctx, []string{"focus"}, 20, "", false, false, "")
	if err != nil {
		t.Fatalf("list tags filtered: %v", err)
	}
	got := indexTagNames(tags)
	wantPrefix := []string{"focus", "new", "old"}
	if len(got) < len(wantPrefix) {
		t.Fatalf("expected at least %d tags, got %v", len(wantPrefix), got)
	}
	for i := range wantPrefix {
		if got[i] != wantPrefix[i] {
			t.Fatalf("unexpected filtered order: got=%v want prefix=%v", got, wantPrefix)
		}
	}
}

func TestListTagsFilteredByDateUsesWeightedOrder(t *testing.T) {
	idx, ctx, owner := createIndexWithNotes(t, map[string]string{
		"old-focus.md": "# Old Focus\n\n#focus #old\n",
		"new-focus.md": "# New Focus\n\n#focus #new\n",
		"other.md":     "# Other\n\n#other\n",
	})

	now := time.Now().Unix()
	setNoteUpdatedAt(t, idx, ctx, owner, "old-focus.md", now-600*secondsPerDay)
	setNoteUpdatedAt(t, idx, ctx, owner, "new-focus.md", now-2*secondsPerDay)
	setNoteUpdatedAt(t, idx, ctx, owner, "other.md", now-2*secondsPerDay)

	day := time.Now().UTC().Unix() / secondsPerDay
	date := time.Unix(day*secondsPerDay, 0).UTC().Format("2006-01-02")
	setNoteActionDate(t, idx, ctx, owner, "old-focus.md", day)
	setNoteActionDate(t, idx, ctx, owner, "new-focus.md", day)
	setNoteActionDate(t, idx, ctx, owner, "other.md", day)

	tags, err := idx.ListTagsFilteredByDate(ctx, []string{"focus"}, date, 20, "", false, false, "")
	if err != nil {
		t.Fatalf("list tags filtered by date: %v", err)
	}
	got := indexTagNames(tags)
	wantPrefix := []string{"focus", "new", "old"}
	if len(got) < len(wantPrefix) {
		t.Fatalf("expected at least %d tags, got %v", len(wantPrefix), got)
	}
	for i := range wantPrefix {
		if got[i] != wantPrefix[i] {
			t.Fatalf("unexpected filtered-by-date order: got=%v want prefix=%v", got, wantPrefix)
		}
	}
}
