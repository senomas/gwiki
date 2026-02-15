package web

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gwiki/internal/config"
)

func TestNoteGitHistoryEntriesIncludesNoteAndAttachments(t *testing.T) {
	requireGit(t)

	repoRoot := t.TempDir()
	owner := "alice"
	ownerRepo := filepath.Join(repoRoot, owner)
	noteID := "note-123"
	noteRelPath := "travel.md"
	noteFSPath := filepath.Join(ownerRepo, "notes", noteRelPath)
	attachmentRelPath := filepath.Join("notes", "attachments", noteID, "pic.jpg")
	attachmentFSPath := filepath.Join(ownerRepo, attachmentRelPath)

	if err := os.MkdirAll(filepath.Dir(noteFSPath), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(attachmentFSPath), 0o755); err != nil {
		t.Fatalf("mkdir attachments: %v", err)
	}

	runGit(t, ownerRepo, "init")
	runGit(t, ownerRepo, "config", "user.name", "test")
	runGit(t, ownerRepo, "config", "user.email", "test@example.com")

	if err := os.WriteFile(noteFSPath, []byte("# Travel\n"), 0o644); err != nil {
		t.Fatalf("write note v1: %v", err)
	}
	runGit(t, ownerRepo, "add", filepath.ToSlash(filepath.Join("notes", noteRelPath)))
	runGit(t, ownerRepo, "commit", "-m", "note v1")
	hashNoteV1 := runGit(t, ownerRepo, "rev-parse", "--short", "HEAD")

	if err := os.WriteFile(attachmentFSPath, []byte("image-bytes"), 0o644); err != nil {
		t.Fatalf("write attachment: %v", err)
	}
	runGit(t, ownerRepo, "add", filepath.ToSlash(attachmentRelPath))
	runGit(t, ownerRepo, "commit", "-m", "attachment")
	hashAttachment := runGit(t, ownerRepo, "rev-parse", "--short", "HEAD")

	if err := os.WriteFile(noteFSPath, []byte("# Travel\n\nUpdated.\n"), 0o644); err != nil {
		t.Fatalf("write note v2: %v", err)
	}
	runGit(t, ownerRepo, "add", filepath.ToSlash(filepath.Join("notes", noteRelPath)))
	runGit(t, ownerRepo, "commit", "-m", "note v2")
	hashNoteV2 := runGit(t, ownerRepo, "rev-parse", "--short", "HEAD")

	unrelatedPath := filepath.Join(ownerRepo, "notes", "other.md")
	if err := os.WriteFile(unrelatedPath, []byte("# Other\n"), 0o644); err != nil {
		t.Fatalf("write unrelated note: %v", err)
	}
	runGit(t, ownerRepo, "add", "notes/other.md")
	runGit(t, ownerRepo, "commit", "-m", "unrelated")

	s := &Server{cfg: config.Config{RepoPath: repoRoot}}
	entries, err := s.noteGitHistoryEntries(context.Background(), owner, noteRelPath, noteID, 20)
	if err != nil {
		t.Fatalf("noteGitHistoryEntries: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	wantOrder := []string{hashNoteV2, hashAttachment, hashNoteV1}
	for i, want := range wantOrder {
		if entries[i].ShortHash != want {
			t.Fatalf("entry[%d] hash=%q want %q", i, entries[i].ShortHash, want)
		}
	}
}

func TestNoteGitHistoryEntriesLimitAndNoteOnly(t *testing.T) {
	requireGit(t)

	repoRoot := t.TempDir()
	owner := "alice"
	ownerRepo := filepath.Join(repoRoot, owner)
	noteID := "note-123"
	noteRelPath := "travel.md"
	noteFSPath := filepath.Join(ownerRepo, "notes", noteRelPath)
	attachmentRelPath := filepath.Join("notes", "attachments", noteID, "pic.jpg")
	attachmentFSPath := filepath.Join(ownerRepo, attachmentRelPath)

	if err := os.MkdirAll(filepath.Dir(noteFSPath), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(attachmentFSPath), 0o755); err != nil {
		t.Fatalf("mkdir attachments: %v", err)
	}

	runGit(t, ownerRepo, "init")
	runGit(t, ownerRepo, "config", "user.name", "test")
	runGit(t, ownerRepo, "config", "user.email", "test@example.com")

	if err := os.WriteFile(noteFSPath, []byte("# Travel\n"), 0o644); err != nil {
		t.Fatalf("write note v1: %v", err)
	}
	runGit(t, ownerRepo, "add", filepath.ToSlash(filepath.Join("notes", noteRelPath)))
	runGit(t, ownerRepo, "commit", "-m", "note v1")
	hashNoteV1 := runGit(t, ownerRepo, "rev-parse", "--short", "HEAD")

	if err := os.WriteFile(attachmentFSPath, []byte("image-bytes"), 0o644); err != nil {
		t.Fatalf("write attachment: %v", err)
	}
	runGit(t, ownerRepo, "add", filepath.ToSlash(attachmentRelPath))
	runGit(t, ownerRepo, "commit", "-m", "attachment")
	hashAttachment := runGit(t, ownerRepo, "rev-parse", "--short", "HEAD")

	if err := os.WriteFile(noteFSPath, []byte("# Travel\n\nUpdated.\n"), 0o644); err != nil {
		t.Fatalf("write note v2: %v", err)
	}
	runGit(t, ownerRepo, "add", filepath.ToSlash(filepath.Join("notes", noteRelPath)))
	runGit(t, ownerRepo, "commit", "-m", "note v2")
	hashNoteV2 := runGit(t, ownerRepo, "rev-parse", "--short", "HEAD")

	s := &Server{cfg: config.Config{RepoPath: repoRoot}}

	limited, err := s.noteGitHistoryEntries(context.Background(), owner, noteRelPath, noteID, 2)
	if err != nil {
		t.Fatalf("noteGitHistoryEntries limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(limited))
	}
	if limited[0].ShortHash != hashNoteV2 || limited[1].ShortHash != hashAttachment {
		t.Fatalf("unexpected limited order: %#v", limited)
	}

	noteOnly, err := s.noteGitHistoryEntries(context.Background(), owner, noteRelPath, "", 20)
	if err != nil {
		t.Fatalf("noteGitHistoryEntries note-only: %v", err)
	}
	if len(noteOnly) != 2 {
		t.Fatalf("expected 2 note-only entries, got %d", len(noteOnly))
	}
	if noteOnly[0].ShortHash != hashNoteV2 || noteOnly[1].ShortHash != hashNoteV1 {
		t.Fatalf("unexpected note-only order: %#v", noteOnly)
	}
}

func TestQuickLauncherNotePathBlocksHistorySuffix(t *testing.T) {
	if _, ok := quickLauncherNotePath("/notes/@alice/travel.md/history", "alice"); ok {
		t.Fatalf("expected /history path to be blocked")
	}
	if got, ok := quickLauncherNotePath("/notes/travel.md", "alice"); !ok || got != "alice/travel.md" {
		t.Fatalf("unexpected parse result: got (%q, %v)", got, ok)
	}
}

func runGit(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
}
