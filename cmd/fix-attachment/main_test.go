package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteValidLocalAttachment(t *testing.T) {
	repo := t.TempDir()
	writeNote(t, repo, "alice", "local.md", "note-local",
		"# Local\n\n![](/attachments/note-local/photo.jpg)\n")

	_, stats, findings, err := execute(runOptions{RepoRoot: repo})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if stats.InvalidRefs != 0 {
		t.Fatalf("expected no invalid refs, got %d", stats.InvalidRefs)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

func TestExecuteInvalidOwnerAndNoteID(t *testing.T) {
	repo := t.TempDir()
	writeNote(t, repo, "alice", "source.md", "note-a",
		"# Source\n\n![](/attachments/note-b/photo.jpg)\n")
	writeNote(t, repo, "bob", "target.md", "note-b",
		"# Target\n")

	_, stats, findings, err := execute(runOptions{RepoRoot: repo})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if stats.InvalidRefs != 1 {
		t.Fatalf("expected 1 invalid ref, got %d", stats.InvalidRefs)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Reason, "note-id-mismatch") {
		t.Fatalf("expected note-id-mismatch reason, got %q", findings[0].Reason)
	}
	if !strings.Contains(findings[0].Reason, "owner-mismatch") {
		t.Fatalf("expected owner-mismatch reason, got %q", findings[0].Reason)
	}
}

func TestExecuteUnknownAttachmentNoteID(t *testing.T) {
	repo := t.TempDir()
	writeNote(t, repo, "alice", "source.md", "note-a",
		"# Source\n\n![](attachments/missing-id/photo.jpg)\n")

	_, stats, findings, err := execute(runOptions{RepoRoot: repo})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if stats.InvalidRefs != 1 {
		t.Fatalf("expected 1 invalid ref, got %d", stats.InvalidRefs)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.Contains(findings[0].Reason, "unknown-note-id(missing-id)") {
		t.Fatalf("expected unknown-note-id reason, got %q", findings[0].Reason)
	}
}

func TestRunCLIFixCopiesAndRewrites(t *testing.T) {
	repo := t.TempDir()
	writeNote(t, repo, "alice", "source.md", "note-a",
		"# Source\n\n![](/attachments/note-b/photo.jpg)\n")
	writeNote(t, repo, "bob", "target.md", "note-b", "# Target\n")
	writeAttachment(t, repo, "bob", "note-b", "photo.jpg", []byte("photo-data"))

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := runCLI([]string{"--repo", repo, "--fix", "--yes"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, out=%s err=%s", code, out.String(), errOut.String())
	}

	updated, err := os.ReadFile(filepath.Join(repo, "alice", "notes", "source.md"))
	if err != nil {
		t.Fatalf("read updated note: %v", err)
	}
	if !strings.Contains(string(updated), "/attachments/note-a/photo.jpg") {
		t.Fatalf("expected rewritten link, got:\n%s", string(updated))
	}

	data, err := os.ReadFile(filepath.Join(repo, "alice", "notes", "attachments", "note-a", "photo.jpg"))
	if err != nil {
		t.Fatalf("read copied attachment: %v", err)
	}
	if string(data) != "photo-data" {
		t.Fatalf("unexpected copied attachment content: %q", string(data))
	}
	if !strings.Contains(out.String(), "invalid=0") {
		t.Fatalf("expected clean summary after fix, got: %s", out.String())
	}
}

func TestRunCLIFixRestoresMissingSourceFromGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	repo := t.TempDir()
	writeNote(t, repo, "alice", "source.md", "note-a",
		"# Source\n\n![](/attachments/note-b/photo.jpg)\n")
	writeNote(t, repo, "bob", "target.md", "note-b", "# Target\n")
	srcAttachment := filepath.Join(repo, "bob", "notes", "attachments", "note-b", "photo.jpg")
	writeAttachment(t, repo, "bob", "note-b", "photo.jpg", []byte("photo-data"))

	bobRepo := filepath.Join(repo, "bob")
	runGit(t, bobRepo, "init")
	runGit(t, bobRepo, "config", "user.email", "test@example.com")
	runGit(t, bobRepo, "config", "user.name", "Test User")
	runGit(t, bobRepo, "add", ".")
	runGit(t, bobRepo, "commit", "-m", "initial")

	if err := os.Remove(srcAttachment); err != nil {
		t.Fatalf("remove source attachment: %v", err)
	}
	runGit(t, bobRepo, "add", ".")
	runGit(t, bobRepo, "commit", "-m", "delete attachment")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := runCLI([]string{"--repo", repo, "--fix", "--yes"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, out=%s err=%s", code, out.String(), errOut.String())
	}

	if _, err := os.Stat(srcAttachment); err != nil {
		t.Fatalf("expected source attachment restored, err=%v", err)
	}
	if !strings.Contains(out.String(), "restored source from git") {
		t.Fatalf("expected restore message in output, got: %s", out.String())
	}
}

func writeNote(t *testing.T, repoRoot, owner, relName, noteID, body string) {
	t.Helper()
	notesDir := filepath.Join(repoRoot, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	content := strings.Join([]string{
		"---",
		"id: " + noteID,
		"---",
		"",
		body,
	}, "\n")
	path := filepath.Join(notesDir, relName)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
}

func writeAttachment(t *testing.T, repoRoot, owner, noteID, rel string, data []byte) {
	t.Helper()
	fullPath := filepath.Join(repoRoot, owner, "notes", "attachments", noteID, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("mkdir attachment dir: %v", err)
	}
	if err := os.WriteFile(fullPath, data, 0o644); err != nil {
		t.Fatalf("write attachment: %v", err)
	}
}

func runGit(t *testing.T, repoDir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
}
