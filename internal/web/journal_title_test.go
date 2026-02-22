package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/index"
)

func TestStripJournalFirstLineH1_RemovesLeadingH1(t *testing.T) {
	notePath := "seno/2026-02/22-02-40.md"
	input := strings.Join([]string{
		"---",
		"id: journal-note",
		"visibility: inherited",
		"---",
		"",
		"# Any Title",
		"",
		"## 02:40",
		"",
		"- [ ] task",
	}, "\n")

	got := stripJournalFirstLineH1(notePath, input)
	body := noteBody(got)
	if strings.Contains(body, "# Any Title") {
		t.Fatalf("expected journal H1 to be stripped, got:\n%s", body)
	}
	if first := firstNonEmptyLine(body); first != "## 02:40" {
		t.Fatalf("expected first non-empty body line to be journal heading, got %q", first)
	}
}

func TestStripJournalFirstLineH1_LeavesNonJournal(t *testing.T) {
	notePath := "seno/project/demo.md"
	input := "# Keep Title\n\ncontent"

	got := stripJournalFirstLineH1(notePath, input)
	if got != normalizeLineEndings(input) {
		t.Fatalf("expected non-journal content unchanged, got %q", got)
	}
}

func TestSaveNoteCommon_JournalAllowsNoH1Title(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes", "2026-02")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	noteRel := filepath.ToSlash(filepath.Join("2026-02", "22-02-40.md"))
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	fullPath := filepath.Join(repo, owner, "notes", filepath.FromSlash(noteRel))
	existing := strings.Join([]string{
		"# Old Journal Title",
		"",
		"old line",
		"",
	}, "\n")
	if err := os.WriteFile(fullPath, []byte(existing), 0o644); err != nil {
		t.Fatalf("write existing note: %v", err)
	}

	idx, err := index.Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	noteCtx := WithUser(context.Background(), User{Name: owner, Authenticated: true})
	result, apiErr := srv.saveNoteCommon(noteCtx, saveNoteInput{
		NotePath:       notePath,
		TargetOwner:    owner,
		Content:        "updated line",
		RenameDecision: "cancel",
	})
	if apiErr != nil {
		t.Fatalf("save journal note without H1 title: %+v", apiErr)
	}
	if result.TargetPath != notePath {
		t.Fatalf("expected journal path unchanged, got %q want %q", result.TargetPath, notePath)
	}

	storedRaw, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("read saved note: %v", err)
	}
	stored := normalizeLineEndings(string(storedRaw))
	body := noteBody(stored)
	if strings.Contains(body, "# Old Journal Title") {
		t.Fatalf("expected old H1 title removed from journal body, got:\n%s", body)
	}
	if first := firstNonEmptyLine(body); first != "updated line" {
		t.Fatalf("expected first non-empty body line to be updated content, got %q", first)
	}
}

func TestSaveNoteCommon_JournalRewriteWhenOnlyH1Removed(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes", "2026-02")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	noteRel := filepath.ToSlash(filepath.Join("2026-02", "22-11-06.md"))
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	fullPath := filepath.Join(repo, owner, "notes", filepath.FromSlash(noteRel))
	frontmatter := strings.Join([]string{
		"---",
		"id: journal-note",
		"created: 2026-02-22T11:06:34+07:00",
		"updated: 2026-02-22T11:06:34+07:00",
		"priority: 10",
		"visibility: inherited",
		"---",
	}, "\n")
	bodyWithH1 := strings.Join([]string{
		"# 22 Feb 2026",
		"",
		"## 11:06",
		"",
		"- [ ] Antarakata #inbox #signal",
	}, "\n")
	existing := frontmatter + "\n" + bodyWithH1 + "\n"
	if err := os.WriteFile(fullPath, []byte(existing), 0o644); err != nil {
		t.Fatalf("write existing note: %v", err)
	}

	idx, err := index.Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	noteCtx := WithUser(context.Background(), User{Name: owner, Authenticated: true})
	result, apiErr := srv.saveNoteCommon(noteCtx, saveNoteInput{
		NotePath:       notePath,
		TargetOwner:    owner,
		Content:        bodyWithH1,
		Frontmatter:    frontmatter,
		RenameDecision: "cancel",
	})
	if apiErr != nil {
		t.Fatalf("save journal note with H1: %+v", apiErr)
	}
	if result.NoChange {
		t.Fatalf("expected save to rewrite content and strip H1")
	}

	storedRaw, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("read saved note: %v", err)
	}
	stored := normalizeLineEndings(string(storedRaw))
	body := noteBody(stored)
	if strings.Contains(body, "# 22 Feb 2026") {
		t.Fatalf("expected journal H1 removed after save, got:\n%s", body)
	}
}

func noteBody(content string) string {
	fm := index.FrontmatterBlock(content)
	if fm == "" {
		return content
	}
	body := strings.TrimPrefix(content, fm)
	return strings.TrimPrefix(body, "\n")
}

func firstNonEmptyLine(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}
