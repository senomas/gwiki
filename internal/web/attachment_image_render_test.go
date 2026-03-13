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

func TestRenderAttachmentImageResponsiveMarkup(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes")
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
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

	srv, err := NewServer(config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	html, err := srv.renderMarkdown(ctx, []byte("![Photo](attachments/note-123/photo.png)"))
	if err != nil {
		t.Fatalf("render markdown: %v", err)
	}
	if !strings.Contains(html, `class="note-attachment-image"`) {
		t.Fatalf("expected attachment image wrapper, got %s", html)
	}
	if !strings.Contains(html, `/attachments/note-123/photo.png?w=768 768w`) {
		t.Fatalf("expected mobile srcset entry, got %s", html)
	}
	if !strings.Contains(html, `/attachments/note-123/photo.png?w=1600 1600w`) {
		t.Fatalf("expected desktop srcset entry, got %s", html)
	}
	if !strings.Contains(html, `href="/attachments/note-123/photo.png"`) {
		t.Fatalf("expected original image href, got %s", html)
	}
}
