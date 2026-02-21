package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gwiki/internal/index"
)

func TestParseDailyJournalSplitsByH2Time(t *testing.T) {
	day := time.Date(2026, 2, 16, 0, 0, 0, 0, time.Local)
	content := strings.Join([]string{
		"---",
		"id: abc",
		"---",
		"# 16 Feb 2026",
		"",
		"## 10:15",
		"entry one",
		"",
		"## 12:30",
		"entry two",
	}, "\n")

	got := parseDailyJournal(content, day)
	if len(got.Order) != 2 {
		t.Fatalf("expected 2 buckets, got %d (%v)", len(got.Order), got.Order)
	}
	if got.Order[0] != "10-15" || got.Order[1] != "12-30" {
		t.Fatalf("unexpected bucket order: %v", got.Order)
	}
	if strings.TrimSpace(got.Buckets["10-15"]) != "entry one" {
		t.Fatalf("unexpected 10-15 body: %q", got.Buckets["10-15"])
	}
	if strings.TrimSpace(got.Buckets["12-30"]) != "entry two" {
		t.Fatalf("unexpected 12-30 body: %q", got.Buckets["12-30"])
	}
}

func TestParseDailyJournalUncategorizedToZeroTime(t *testing.T) {
	day := time.Date(2026, 2, 16, 0, 0, 0, 0, time.Local)
	content := strings.Join([]string{
		"# 16 Feb 2026",
		"",
		"uncategorized",
		"",
		"## 09:00",
		"timed",
	}, "\n")

	got := parseDailyJournal(content, day)
	if len(got.Order) != 2 {
		t.Fatalf("expected 2 buckets, got %d (%v)", len(got.Order), got.Order)
	}
	if got.Order[0] != "00-00" || got.Order[1] != "09-00" {
		t.Fatalf("unexpected bucket order: %v", got.Order)
	}
	if strings.TrimSpace(got.Buckets["00-00"]) != "uncategorized" {
		t.Fatalf("unexpected 00-00 body: %q", got.Buckets["00-00"])
	}
	if strings.TrimSpace(got.Buckets["09-00"]) != "timed" {
		t.Fatalf("unexpected 09-00 body: %q", got.Buckets["09-00"])
	}
}

func TestParseDailyJournalDuplicateTimesMerged(t *testing.T) {
	day := time.Date(2026, 2, 16, 0, 0, 0, 0, time.Local)
	content := strings.Join([]string{
		"## 10:00",
		"one",
		"",
		"## 10:00",
		"two",
	}, "\n")

	got := parseDailyJournal(content, day)
	if len(got.Order) != 1 || got.Order[0] != "10-00" {
		t.Fatalf("expected single 10-00 bucket, got %v", got.Order)
	}
	want := "one\n\ntwo"
	if strings.TrimSpace(got.Buckets["10-00"]) != want {
		t.Fatalf("unexpected merged body: %q want %q", got.Buckets["10-00"], want)
	}
}

func TestParseDailyJournalInvalidTimeNotSplit(t *testing.T) {
	day := time.Date(2026, 2, 16, 0, 0, 0, 0, time.Local)
	content := strings.Join([]string{
		"## 24:00",
		"invalid",
		"",
		"## 09:00",
		"valid",
	}, "\n")

	got := parseDailyJournal(content, day)
	if len(got.Order) != 2 {
		t.Fatalf("expected 2 buckets, got %d (%v)", len(got.Order), got.Order)
	}
	if got.Order[0] != "00-00" || got.Order[1] != "09-00" {
		t.Fatalf("unexpected bucket order: %v", got.Order)
	}
	if !strings.Contains(got.Buckets["00-00"], "## 24:00") {
		t.Fatalf("expected invalid heading preserved in 00-00 bucket, got %q", got.Buckets["00-00"])
	}
	if strings.TrimSpace(got.Buckets["09-00"]) != "valid" {
		t.Fatalf("unexpected 09-00 body: %q", got.Buckets["09-00"])
	}
}

func TestTargetFileName(t *testing.T) {
	day := time.Date(2026, 2, 7, 0, 0, 0, 0, time.Local)
	got := targetFileName(day, "10-45")
	if got != "07-10-45.md" {
		t.Fatalf("targetFileName=%q want %q", got, "07-10-45.md")
	}
}

func TestMigrateSourceFileDryRunNoMutation(t *testing.T) {
	src, sourcePath, targetPath := buildSourceFixture(t, strings.Join([]string{
		"# 16 Feb 2026",
		"",
		"## 10:00",
		"hello dry run",
	}, "\n"))

	now := time.Date(2026, 2, 21, 10, 0, 0, 0, time.Local)
	result, err := migrateSourceFile(src, now, true)
	if err != nil {
		t.Fatalf("migrateSourceFile dry-run: %v", err)
	}
	if result.Skipped {
		t.Fatalf("expected migration result, got skipped")
	}
	if result.CreatedTargets != 1 || result.UpdatedTargets != 0 {
		t.Fatalf("unexpected dry-run target counts: %+v", result)
	}
	if !result.DeletedSource {
		t.Fatalf("expected dry-run to report source delete action")
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatalf("expected source to remain in dry-run, stat err: %v", err)
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("expected target not created in dry-run, stat err: %v", err)
	}
}

func TestMigrateSourceFileSuccessDeletesSource(t *testing.T) {
	src, sourcePath, targetPath := buildSourceFixture(t, strings.Join([]string{
		"# 16 Feb 2026",
		"",
		"## 10:00",
		"hello migrate",
	}, "\n"))

	now := time.Date(2026, 2, 21, 10, 0, 0, 0, time.Local)
	result, err := migrateSourceFile(src, now, false)
	if err != nil {
		t.Fatalf("migrateSourceFile: %v", err)
	}
	if result.Skipped {
		t.Fatalf("expected migrated result, got skipped")
	}
	if result.CreatedTargets != 1 || result.UpdatedTargets != 0 || !result.DeletedSource {
		t.Fatalf("unexpected migrate result: %+v", result)
	}
	if _, err := os.Stat(sourcePath); !os.IsNotExist(err) {
		t.Fatalf("expected source deleted, stat err: %v", err)
	}
	targetBytes, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	target := string(targetBytes)
	if !strings.Contains(target, "title: 16 Feb 2026") {
		t.Fatalf("expected migrated title in frontmatter, got %q", target)
	}
	if !strings.Contains(target, "hello migrate") {
		t.Fatalf("expected migrated body, got %q", target)
	}
}

func TestMigrateSourceFileCopiesAttachmentsAndRemovesSourceAttachments(t *testing.T) {
	sourceID := "note-source-id"
	src, sourcePath, _ := buildSourceFixture(t, strings.Join([]string{
		"---",
		"id: " + sourceID,
		"---",
		"# 16 Feb 2026",
		"",
		"## 10:00",
		"first ![](/attachments/" + sourceID + "/images/a.png)",
		"",
		"## 11:30",
		"second ![](attachments/" + sourceID + "/images/sub/b.png)",
	}, "\n"))

	notesRoot := filepath.Dir(filepath.Dir(sourcePath))
	sourceAttachments := filepath.Join(notesRoot, "attachments", sourceID)
	fileA := filepath.Join(sourceAttachments, "images", "a.png")
	fileB := filepath.Join(sourceAttachments, "images", "sub", "b.png")
	if err := os.MkdirAll(filepath.Dir(fileA), 0o755); err != nil {
		t.Fatalf("mkdir fileA dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(fileB), 0o755); err != nil {
		t.Fatalf("mkdir fileB dir: %v", err)
	}
	if err := os.WriteFile(fileA, []byte("a"), 0o644); err != nil {
		t.Fatalf("write fileA: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("b"), 0o644); err != nil {
		t.Fatalf("write fileB: %v", err)
	}

	now := time.Date(2026, 2, 21, 10, 0, 0, 0, time.Local)
	result, err := migrateSourceFile(src, now, false)
	if err != nil {
		t.Fatalf("migrateSourceFile: %v", err)
	}
	if result.CreatedTargets != 2 || result.UpdatedTargets != 0 || !result.DeletedSource {
		t.Fatalf("unexpected migrate result: %+v", result)
	}

	targetAPath := filepath.Join(notesRoot, "2026-02", "16-10-00.md")
	targetBPath := filepath.Join(notesRoot, "2026-02", "16-11-30.md")
	targetABytes, err := os.ReadFile(targetAPath)
	if err != nil {
		t.Fatalf("read targetA: %v", err)
	}
	targetBBytes, err := os.ReadFile(targetBPath)
	if err != nil {
		t.Fatalf("read targetB: %v", err)
	}
	targetA := string(targetABytes)
	targetB := string(targetBBytes)
	targetAID := strings.TrimSpace(index.FrontmatterAttributes(targetA).ID)
	targetBID := strings.TrimSpace(index.FrontmatterAttributes(targetB).ID)
	if targetAID == "" || targetBID == "" {
		t.Fatalf("expected target frontmatter ids, got targetA=%q targetB=%q", targetAID, targetBID)
	}
	if targetAID == sourceID || targetBID == sourceID {
		t.Fatalf("expected split targets to use new ids, got source=%q targetA=%q targetB=%q", sourceID, targetAID, targetBID)
	}
	if !strings.Contains(targetA, "/attachments/"+targetAID+"/images/a.png") {
		t.Fatalf("expected targetA attachment rewritten, got %q", targetA)
	}
	if !strings.Contains(targetB, "attachments/"+targetBID+"/images/sub/b.png") {
		t.Fatalf("expected targetB attachment rewritten, got %q", targetB)
	}

	if _, err := os.Stat(filepath.Join(notesRoot, "attachments", targetAID, "images", "a.png")); err != nil {
		t.Fatalf("expected copied attachment for targetA, stat err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(notesRoot, "attachments", targetBID, "images", "sub", "b.png")); err != nil {
		t.Fatalf("expected copied attachment for targetB, stat err: %v", err)
	}
	if _, err := os.Stat(sourceAttachments); !os.IsNotExist(err) {
		t.Fatalf("expected source attachments removed, stat err: %v", err)
	}
}

func TestMigrateSourceFileAttachmentMissingFailsAndKeepsSource(t *testing.T) {
	sourceID := "missing-source-id"
	src, sourcePath, targetPath := buildSourceFixture(t, strings.Join([]string{
		"---",
		"id: " + sourceID,
		"---",
		"# 16 Feb 2026",
		"",
		"## 10:00",
		"![](/attachments/" + sourceID + "/image.png)",
	}, "\n"))

	now := time.Date(2026, 2, 21, 10, 0, 0, 0, time.Local)
	if _, err := migrateSourceFile(src, now, false); err == nil {
		t.Fatalf("expected migration failure when source attachment is missing")
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatalf("expected source note to remain after failure, stat err: %v", err)
	}
	if _, err := os.Stat(targetPath); !os.IsNotExist(err) {
		t.Fatalf("expected target note not written on failure, stat err: %v", err)
	}
}

func TestMigrateSourceFileWriteFailureKeepsSource(t *testing.T) {
	src, sourcePath, targetPath := buildSourceFixture(t, strings.Join([]string{
		"# 16 Feb 2026",
		"",
		"## 10:00",
		"will fail",
	}, "\n"))
	if err := os.MkdirAll(targetPath, 0o755); err != nil {
		t.Fatalf("mkdir target path as dir: %v", err)
	}

	now := time.Date(2026, 2, 21, 10, 0, 0, 0, time.Local)
	if _, err := migrateSourceFile(src, now, false); err == nil {
		t.Fatalf("expected migration to fail when target path is directory")
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatalf("expected source to remain after failure, stat err: %v", err)
	}
}

func buildSourceFixture(t *testing.T, content string) (sourceFile, string, string) {
	t.Helper()
	repo := t.TempDir()
	owner := "local"
	monthDir := filepath.Join(repo, owner, "notes", "2026-02")
	if err := os.MkdirAll(monthDir, 0o755); err != nil {
		t.Fatalf("mkdir month dir: %v", err)
	}
	sourcePath := filepath.Join(monthDir, "16.md")
	if err := os.WriteFile(sourcePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}
	targetPath := filepath.Join(monthDir, "16-10-00.md")
	return sourceFile{
		Owner: owner,
		Path:  sourcePath,
		Rel:   "2026-02/16.md",
	}, sourcePath, targetPath
}
