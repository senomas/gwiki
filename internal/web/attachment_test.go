package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/index"
)

func TestAttachmentAccessByNoteID(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes")
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	noteID := "xxxx-yyyy"
	notePath := filepath.Join(notesDir, "test.md")
	noteContent := "---\n" +
		"id: " + noteID + "\n" +
		"title: Test Note\n" +
		"visibility: public\n" +
		"---\n\n" +
		"Hello\n"
	if err := os.WriteFile(notePath, []byte(noteContent), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}

	attachmentDir := filepath.Join(notesDir, "attachments", noteID)
	if err := os.MkdirAll(attachmentDir, 0o755); err != nil {
		t.Fatalf("mkdir attachments: %v", err)
	}
	attachmentName := "photo.png"
	attachmentContent := []byte("test-image")
	if err := os.WriteFile(filepath.Join(attachmentDir, attachmentName), attachmentContent, 0o644); err != nil {
		t.Fatalf("write attachment: %v", err)
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

	info, err := os.Stat(notePath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	if err := idx.IndexNote(ctx, "test.md", []byte(noteContent), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/attachments/" + noteID + "/" + attachmentName)
	if err != nil {
		t.Fatalf("get attachment: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read attachment: %v", err)
	}
	if string(body) != string(attachmentContent) {
		t.Fatalf("unexpected attachment body: %q", body)
	}
}

func TestRenderVideoAttachmentEmbed(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes")
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	noteID := "video-note"
	videoRel := "clip.mp4"
	videoPath := filepath.Join(notesDir, "attachments", noteID, videoRel)
	if err := os.MkdirAll(filepath.Dir(videoPath), 0o755); err != nil {
		t.Fatalf("mkdir video dir: %v", err)
	}
	if err := os.WriteFile(videoPath, []byte("fake-video"), 0o644); err != nil {
		t.Fatalf("write video: %v", err)
	}

	thumbDir := filepath.Join(dataDir, "assets", noteID)
	if err := os.MkdirAll(thumbDir, 0o755); err != nil {
		t.Fatalf("mkdir thumb dir: %v", err)
	}
	thumbPath := filepath.Join(thumbDir, "clip.jpg")
	if err := os.WriteFile(thumbPath, []byte("fake-thumb"), 0o644); err != nil {
		t.Fatalf("write thumb: %v", err)
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

	md := "[Demo video](/attachments/" + noteID + "/" + videoRel + ")"
	html, err := srv.renderMarkdown(ctx, []byte(md))
	if err != nil {
		t.Fatalf("render markdown: %v", err)
	}
	if !strings.Contains(html, `class="video-card"`) {
		t.Fatalf("expected video card, got %s", html)
	}
	if !strings.Contains(html, "/assets/"+noteID+"/clip.jpg") {
		t.Fatalf("expected thumbnail url, got %s", html)
	}
	if !strings.Contains(html, "Demo video") {
		t.Fatalf("expected title, got %s", html)
	}
}
