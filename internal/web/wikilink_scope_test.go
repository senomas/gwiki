package web

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gwiki/internal/index"
)

func TestResolveWikiLink_LocalOnlyWhenNoOwnerPrefix(t *testing.T) {
	s := newWikiLinkTestServer(t)
	ctx := withWikiLinkOwner(context.Background(), "alice")

	path, _, err := s.resolveWikiLink(ctx, "Shared")
	if err != nil {
		t.Fatalf("resolve title failed: %v", err)
	}
	if path != "alice/local.md" {
		t.Fatalf("expected local owner note, got %q", path)
	}

	path, _, err = s.resolveWikiLink(ctx, "local.md")
	if err != nil {
		t.Fatalf("resolve local path failed: %v", err)
	}
	if path != "alice/local.md" {
		t.Fatalf("expected local owner path, got %q", path)
	}

	path, _, err = s.resolveWikiLink(ctx, "bob/local.md")
	if err != nil {
		t.Fatalf("resolve cross-owner path failed: %v", err)
	}
	if path != "" {
		t.Fatalf("expected unresolved cross-owner path without @owner, got %q", path)
	}
}

func TestResolveWikiLink_ExplicitOwnerPrefix(t *testing.T) {
	s := newWikiLinkTestServer(t)
	ctx := withWikiLinkOwner(context.Background(), "alice")

	path, _, err := s.resolveWikiLink(ctx, "@bob/local.md")
	if err != nil {
		t.Fatalf("resolve explicit owner path failed: %v", err)
	}
	if path != "bob/local.md" {
		t.Fatalf("expected explicit owner note, got %q", path)
	}
}

func newWikiLinkTestServer(t *testing.T) *Server {
	t.Helper()

	repo := t.TempDir()
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	for _, owner := range []string{"alice", "bob"} {
		if err := os.MkdirAll(filepath.Join(repo, owner, "notes"), 0o755); err != nil {
			t.Fatalf("mkdir owner notes dir: %v", err)
		}
	}

	idx, err := index.Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	ctx := context.Background()
	if err := idx.InitWithOwners(ctx, repo, []string{"alice", "bob"}); err != nil {
		t.Fatalf("init index: %v", err)
	}

	aliceBody := []byte("# Shared\n\nalice body\n")
	bobBody := []byte("# Shared\n\nbob body\n")
	now := time.Now()
	if err := idx.IndexNote(ctx, "alice/local.md", aliceBody, now, int64(len(aliceBody))); err != nil {
		t.Fatalf("index alice note: %v", err)
	}
	if err := idx.IndexNote(ctx, "bob/local.md", bobBody, now.Add(time.Second), int64(len(bobBody))); err != nil {
		t.Fatalf("index bob note: %v", err)
	}

	return &Server{idx: idx}
}
