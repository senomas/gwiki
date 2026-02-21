package syncer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWithOptionsStagesAllButExcludesTempAttachments(t *testing.T) {
	requireGit(t)

	repoDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoDir, "notes"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "notes", "seed.md"), []byte("# Seed\n"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.name", "tester")
	runGit(t, repoDir, "config", "user.email", "tester@example.com")
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "initial")

	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("outside notes\n"), 0o644); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "app.log"), []byte("log\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	tempPath := filepath.Join(repoDir, "notes", "attachments", "TEMP-123", "tmp.txt")
	if err := os.MkdirAll(filepath.Dir(tempPath), 0o755); err != nil {
		t.Fatalf("mkdir temp attachment: %v", err)
	}
	if err := os.WriteFile(tempPath, []byte("temp\n"), 0o644); err != nil {
		t.Fatalf("write temp attachment: %v", err)
	}

	branch := runGit(t, repoDir, "rev-parse", "--abbrev-ref", "HEAD")
	_, err := RunWithOptions(context.Background(), repoDir, Options{
		RepoDir:       repoDir,
		LogFile:       filepath.Join(repoDir, ".git", "auto-sync-test.log"),
		CommitMessage: "manual sync",
		MainBranch:    branch,
		UserName:      "tester",
		EmailDomain:   "example.com",
	})
	if err != nil {
		t.Fatalf("run sync: %v", err)
	}

	lastMessage := runGit(t, repoDir, "log", "-1", "--format=%s")
	if lastMessage != "manual sync" {
		t.Fatalf("last commit message=%q want %q", lastMessage, "manual sync")
	}

	gitIgnoreBytes, err := os.ReadFile(filepath.Join(repoDir, ".gitignore"))
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	gitIgnore := string(gitIgnoreBytes)
	if !strings.Contains(gitIgnore, "/*.log") {
		t.Fatalf("expected .gitignore to contain /*.log, got %q", gitIgnore)
	}
	if !strings.Contains(gitIgnore, "/notes/attachments/TEMP*") {
		t.Fatalf("expected .gitignore to contain /notes/attachments/TEMP*, got %q", gitIgnore)
	}

	changed := runGit(t, repoDir, "show", "--name-only", "--pretty=format:", "HEAD")
	if !strings.Contains(changed, "README.md") {
		t.Fatalf("expected README.md committed, got %q", changed)
	}
	if !strings.Contains(changed, ".gitignore") {
		t.Fatalf("expected .gitignore committed, got %q", changed)
	}
	if strings.Contains(changed, "notes/attachments/TEMP-123/tmp.txt") {
		t.Fatalf("TEMP attachment should be excluded from commit, got %q", changed)
	}
	if strings.Contains(changed, "app.log") {
		t.Fatalf("log file should be ignored, got %q", changed)
	}

	status := runGit(t, repoDir, "status", "--porcelain")
	if strings.TrimSpace(status) != "" {
		t.Fatalf("expected clean status, got %q", status)
	}

	statusWithIgnored := runGit(t, repoDir, "status", "--porcelain", "--ignored")
	if !strings.Contains(statusWithIgnored, "app.log") {
		t.Fatalf("expected ignored app.log in status --ignored, got %q", statusWithIgnored)
	}
	if !strings.Contains(statusWithIgnored, "notes/attachments/") {
		t.Fatalf("expected ignored attachments dir in status --ignored, got %q", statusWithIgnored)
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
