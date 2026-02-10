package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPathByUIDPrefersCurrentUserOwner(t *testing.T) {
	repo := t.TempDir()
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	uid := "976ff36c-c2e5-4e6f-a29f-3cc615951f35"
	sharedIDNote := `---
id: ` + uid + `
title: Mugya The Villas
visibility: public
---
# Mugya The Villas
`

	senoNotes := filepath.Join(repo, "seno", "notes", "healing")
	if err := os.MkdirAll(senoNotes, 0o755); err != nil {
		t.Fatalf("mkdir seno notes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(senoNotes, "mugya-the-villas.md"), []byte(sharedIDNote), 0o644); err != nil {
		t.Fatalf("write seno note: %v", err)
	}

	healingNotes := filepath.Join(repo, "healing", "notes")
	if err := os.MkdirAll(healingNotes, 0o755); err != nil {
		t.Fatalf("mkdir healing notes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(healingNotes, "mugya-the-villas.md"), []byte(sharedIDNote), 0o644); err != nil {
		t.Fatalf("write healing note: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	healingID, err := idx.AccessFilterForUser(ctx, "healing")
	if err != nil {
		t.Fatalf("access filter user id: %v", err)
	}
	if healingID == 0 {
		t.Fatalf("invalid healing user id: %d", healingID)
	}

	healingCtx := WithAccessFilter(ctx, healingID)
	path, err := idx.PathByUID(healingCtx, uid)
	if err != nil {
		t.Fatalf("path by uid: %v", err)
	}
	if path != "healing/mugya-the-villas.md" {
		t.Fatalf("expected healing note path, got %q", path)
	}

	pathWithTitle, title, err := idx.PathTitleByUID(healingCtx, uid)
	if err != nil {
		t.Fatalf("path/title by uid: %v", err)
	}
	if pathWithTitle != "healing/mugya-the-villas.md" {
		t.Fatalf("expected healing note path from PathTitleByUID, got %q", pathWithTitle)
	}
	if title != "Mugya The Villas" {
		t.Fatalf("unexpected title %q", title)
	}
}
