package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAccessFileWithVisibilityFirstLine(t *testing.T) {
	visibility, members, err := parseAccessFile(strings.NewReader("protected\nalice:rw\nbob:ro\n"))
	if err != nil {
		t.Fatalf("parse access: %v", err)
	}
	if visibility != "protected" {
		t.Fatalf("expected protected visibility, got %q", visibility)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
}

func TestParseAccessFileWithoutVisibilityLine(t *testing.T) {
	visibility, members, err := parseAccessFile(strings.NewReader("alice:rw\n"))
	if err != nil {
		t.Fatalf("parse access: %v", err)
	}
	if visibility != "inherited" {
		t.Fatalf("expected inherited visibility, got %q", visibility)
	}
	if len(members) != 1 {
		t.Fatalf("expected one member, got %+v", members)
	}
	if members[0].User != "alice" || members[0].Access != "rw" {
		t.Fatalf("unexpected members: %+v", members)
	}
}

func TestLoadAccessFromRepoResolvesInheritedVisibility(t *testing.T) {
	repo := t.TempDir()
	root := filepath.Join(repo, "alice", "notes")
	if err := os.MkdirAll(filepath.Join(root, "work"), 0o755); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "work", "deep"), 0o755); err != nil {
		t.Fatalf("mkdir deep: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".access.txt"), []byte("public\nbob:ro\n"), 0o644); err != nil {
		t.Fatalf("write root access: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "work", ".access.txt"), []byte("inherited\ncarol:rw\n"), 0o644); err != nil {
		t.Fatalf("write work access: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "work", "deep", ".access.txt"), []byte("private\n"), 0o644); err != nil {
		t.Fatalf("write deep access: %v", err)
	}

	access, err := LoadAccessFromRepo(repo)
	if err != nil {
		t.Fatalf("load access: %v", err)
	}
	rules := map[string]AccessPathRule{}
	for _, rule := range access["alice"] {
		rules[rule.Path] = rule
	}
	if got := rules[""].Visibility; got != "public" {
		t.Fatalf("root visibility: got %q want public", got)
	}
	if got := rules["work"].Visibility; got != "public" {
		t.Fatalf("work visibility: got %q want public", got)
	}
	if got := rules["work/deep"].Visibility; got != "private" {
		t.Fatalf("deep visibility: got %q want private", got)
	}
}

func TestLoadAccessFromRepoDefaultRootPrivate(t *testing.T) {
	repo := t.TempDir()
	work := filepath.Join(repo, "alice", "notes", "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	if err := os.WriteFile(filepath.Join(work, ".access.txt"), []byte("inherited\n"), 0o644); err != nil {
		t.Fatalf("write access: %v", err)
	}

	access, err := LoadAccessFromRepo(repo)
	if err != nil {
		t.Fatalf("load access: %v", err)
	}
	rules := access["alice"]
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if got := rules[0].Visibility; got != "private" {
		t.Fatalf("work visibility: got %q want private", got)
	}
}
