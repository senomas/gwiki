package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBacklinksIncludeOwnerScopedWikiLinksAcrossOwners(t *testing.T) {
	repo := t.TempDir()
	writeBacklinkTestNote(t, repo, "alice", "topic.md", `---
id: alice-topic-id
visibility: public
---
# Topic
`)
	writeBacklinkTestNote(t, repo, "bob", "from.md", `---
id: bob-from-id
visibility: public
---
# Ref

See [[@alice/topic.md]]
`)

	idx := openBacklinkTestIndex(t, repo, []string{"alice", "bob"})
	defer idx.Close()

	ctx := context.Background()
	viewerID, err := idx.EnsureUser(ctx, "viewer")
	if err != nil {
		t.Fatalf("ensure viewer: %v", err)
	}
	accessCtx := WithAccessFilter(ctx, viewerID)

	backlinks, err := idx.Backlinks(accessCtx, "alice/topic.md", "Topic", "alice-topic-id")
	if err != nil {
		t.Fatalf("backlinks: %v", err)
	}
	if !hasBacklinkPath(backlinks, "bob/from.md") {
		t.Fatalf("expected backlink from bob/from.md, got %+v", backlinks)
	}
}

func TestBacklinksIncludeOtherOwnerSameRelativePath(t *testing.T) {
	repo := t.TempDir()
	writeBacklinkTestNote(t, repo, "alice", "topic.md", `---
id: alice-topic-id
visibility: public
---
# Topic
`)
	writeBacklinkTestNote(t, repo, "bob", "topic.md", `---
id: bob-topic-id
visibility: public
---
# Bob Topic

See [[@alice/topic.md]]
`)

	idx := openBacklinkTestIndex(t, repo, []string{"alice", "bob"})
	defer idx.Close()

	ctx := context.Background()
	viewerID, err := idx.EnsureUser(ctx, "viewer")
	if err != nil {
		t.Fatalf("ensure viewer: %v", err)
	}
	accessCtx := WithAccessFilter(ctx, viewerID)

	backlinks, err := idx.Backlinks(accessCtx, "alice/topic.md", "Topic", "alice-topic-id")
	if err != nil {
		t.Fatalf("backlinks: %v", err)
	}
	if !hasBacklinkPath(backlinks, "bob/topic.md") {
		t.Fatalf("expected backlink from bob/topic.md, got %+v", backlinks)
	}
}

func openBacklinkTestIndex(t *testing.T, repo string, owners []string) *Index {
	t.Helper()

	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}

	if err := idx.InitWithOwners(context.Background(), repo, owners); err != nil {
		_ = idx.Close()
		t.Fatalf("init index: %v", err)
	}
	return idx
}

func writeBacklinkTestNote(t *testing.T, repo string, owner string, rel string, content string) {
	t.Helper()
	path := filepath.Join(repo, owner, "notes", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir note dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
}

func hasBacklinkPath(backlinks []Backlink, want string) bool {
	for _, link := range backlinks {
		if link.FromPath == want {
			return true
		}
	}
	return false
}
