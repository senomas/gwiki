package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRewritePrivateToInherited(t *testing.T) {
	input := strings.Join([]string{
		"---",
		"id: note-1",
		"visibility: private",
		"---",
		"",
		"hello",
	}, "\n")

	updated, changed, reason, err := rewritePrivateToInherited(input)
	if err != nil {
		t.Fatalf("rewritePrivateToInherited: %v", err)
	}
	if !changed {
		t.Fatalf("expected changed=true, reason=%s", reason)
	}
	if !strings.Contains(updated, "visibility: inherited") {
		t.Fatalf("expected inherited visibility, got:\n%s", updated)
	}
}

func TestRewriteSkipsNoFrontmatter(t *testing.T) {
	updated, changed, reason, err := rewritePrivateToInherited("# title\n\nbody\n")
	if err != nil {
		t.Fatalf("rewritePrivateToInherited: %v", err)
	}
	if changed {
		t.Fatalf("expected unchanged")
	}
	if reason != "no-frontmatter" {
		t.Fatalf("expected no-frontmatter, got %q", reason)
	}
	if updated == "" {
		t.Fatalf("expected original content returned")
	}
}

func TestExecuteDryRunAndApplyNested(t *testing.T) {
	root := t.TempDir()
	notesDir := filepath.Join(root, "notes")
	if err := os.MkdirAll(filepath.Join(notesDir, "nested", "deep"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}

	privatePath := filepath.Join(notesDir, "nested", "deep", "private.md")
	publicPath := filepath.Join(notesDir, "nested", "public.md")
	textPath := filepath.Join(notesDir, "nested", "skip.txt")

	privateContent := strings.Join([]string{
		"---",
		"id: private-note",
		"visibility: private",
		"---",
		"",
		"body",
	}, "\n")
	publicContent := strings.Join([]string{
		"---",
		"id: public-note",
		"visibility: public",
		"---",
		"",
		"body",
	}, "\n")
	if err := os.WriteFile(privatePath, []byte(privateContent), 0o644); err != nil {
		t.Fatalf("write private note: %v", err)
	}
	if err := os.WriteFile(publicPath, []byte(publicContent), 0o644); err != nil {
		t.Fatalf("write public note: %v", err)
	}
	if err := os.WriteFile(textPath, []byte(privateContent), 0o644); err != nil {
		t.Fatalf("write non-md file: %v", err)
	}

	_, dryStats, err := execute(runOptions{
		Root:   notesDir,
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("execute dry-run: %v", err)
	}
	if dryStats.Scanned != 2 {
		t.Fatalf("expected scanned=2 got=%d", dryStats.Scanned)
	}
	if dryStats.Matched != 1 {
		t.Fatalf("expected matched=1 got=%d", dryStats.Matched)
	}
	if dryStats.Updated != 1 {
		t.Fatalf("expected updated=1 got=%d", dryStats.Updated)
	}
	if dryStats.Errors != 0 {
		t.Fatalf("expected errors=0 got=%d", dryStats.Errors)
	}

	afterDry, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatalf("read private after dry-run: %v", err)
	}
	if strings.Contains(string(afterDry), "visibility: inherited") {
		t.Fatalf("dry-run should not modify files")
	}

	_, applyStats, err := execute(runOptions{
		Root: notesDir,
	})
	if err != nil {
		t.Fatalf("execute apply: %v", err)
	}
	if applyStats.Updated != 1 {
		t.Fatalf("expected updated=1 got=%d", applyStats.Updated)
	}
	if applyStats.Errors != 0 {
		t.Fatalf("expected errors=0 got=%d", applyStats.Errors)
	}

	afterApply, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatalf("read private after apply: %v", err)
	}
	if !strings.Contains(string(afterApply), "visibility: inherited") {
		t.Fatalf("expected inherited visibility after apply, got:\n%s", string(afterApply))
	}
}
