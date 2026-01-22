package web

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gwiki/internal/auth"
	"gwiki/internal/config"
	"gwiki/internal/index"
)

func TestAttachmentAccessByNoteID(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	noteID := "xxxx-yyyy"
	noteRel := "test.md"
	notePath := filepath.Join(notesDir, noteRel)
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
	noteIndexPath := filepath.ToSlash(filepath.Join(owner, noteRel))
	if err := idx.IndexNote(ctx, noteIndexPath, []byte(noteContent), info.ModTime(), info.Size()); err != nil {
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
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
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

	noteContent := "---\n" +
		"id: " + noteID + "\n" +
		"title: Video Note\n" +
		"visibility: public\n" +
		"---\n\n" +
		"Video\n"
	noteRel := "video.md"
	notePath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(notePath, []byte(noteContent), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(notePath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	noteIndexPath := filepath.ToSlash(filepath.Join(owner, noteRel))
	if err := idx.IndexNote(ctx, noteIndexPath, []byte(noteContent), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
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

func TestAttachmentAndAssetAccessControl(t *testing.T) {
	repo := t.TempDir()
	owner := "alice"
	notesDir := filepath.Join(repo, owner, "notes")
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	authHash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	authFile := filepath.Join(dataDir, "auth.txt")
	if err := os.WriteFile(authFile, []byte("alice:"+authHash+"\n"), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	publicID := "public-note"
	privateID := "private-note"
	publicContent := "---\n" +
		"id: " + publicID + "\n" +
		"title: Public Note\n" +
		"visibility: public\n" +
		"---\n\n" +
		"Public\n"
	privateContent := "---\n" +
		"id: " + privateID + "\n" +
		"title: Private Note\n" +
		"visibility: private\n" +
		"---\n\n" +
		"Private\n"

	publicRel := "public.md"
	privateRel := "private.md"
	publicPath := filepath.Join(notesDir, publicRel)
	privatePath := filepath.Join(notesDir, privateRel)
	if err := os.WriteFile(publicPath, []byte(publicContent), 0o644); err != nil {
		t.Fatalf("write public note: %v", err)
	}
	if err := os.WriteFile(privatePath, []byte(privateContent), 0o644); err != nil {
		t.Fatalf("write private note: %v", err)
	}

	publicAttachment := filepath.Join(notesDir, "attachments", publicID, "public.txt")
	privateAttachment := filepath.Join(notesDir, "attachments", privateID, "private.txt")
	if err := os.MkdirAll(filepath.Dir(publicAttachment), 0o755); err != nil {
		t.Fatalf("mkdir public attachment dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(privateAttachment), 0o755); err != nil {
		t.Fatalf("mkdir private attachment dir: %v", err)
	}
	if err := os.WriteFile(publicAttachment, []byte("public-attachment"), 0o644); err != nil {
		t.Fatalf("write public attachment: %v", err)
	}
	if err := os.WriteFile(privateAttachment, []byte("private-attachment"), 0o644); err != nil {
		t.Fatalf("write private attachment: %v", err)
	}

	publicAsset := filepath.Join(dataDir, "assets", publicID, "thumb.jpg")
	privateAsset := filepath.Join(dataDir, "assets", privateID, "thumb.jpg")
	if err := os.MkdirAll(filepath.Dir(publicAsset), 0o755); err != nil {
		t.Fatalf("mkdir public asset dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(privateAsset), 0o755); err != nil {
		t.Fatalf("mkdir private asset dir: %v", err)
	}
	if err := os.WriteFile(publicAsset, []byte("public-asset"), 0o644); err != nil {
		t.Fatalf("write public asset: %v", err)
	}
	if err := os.WriteFile(privateAsset, []byte("private-asset"), 0o644); err != nil {
		t.Fatalf("write private asset: %v", err)
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

	publicIndexPath := filepath.ToSlash(filepath.Join(owner, publicRel))
	privateIndexPath := filepath.ToSlash(filepath.Join(owner, privateRel))
	if info, err := os.Stat(publicPath); err == nil {
		if err := idx.IndexNote(ctx, publicIndexPath, []byte(publicContent), info.ModTime(), info.Size()); err != nil {
			t.Fatalf("index public note: %v", err)
		}
	}
	if info, err := os.Stat(privatePath); err == nil {
		if err := idx.IndexNote(ctx, privateIndexPath, []byte(privateContent), info.ModTime(), info.Size()); err != nil {
			t.Fatalf("index private note: %v", err)
		}
	}
	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0", AuthFile: authFile}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	loginClient := func() *http.Client {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatalf("cookie jar: %v", err)
		}
		client := &http.Client{Jar: jar}
		form := url.Values{}
		form.Set("username", "alice")
		form.Set("password", "secret")
		resp, err := client.PostForm(ts.URL+"/login", form)
		if err != nil {
			t.Fatalf("login request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusOK {
			t.Fatalf("login status: %d", resp.StatusCode)
		}
		return client
	}

	authClient := loginClient()

	assertStatus := func(path string, want int, withAuth bool) {
		client := http.DefaultClient
		if withAuth {
			client = authClient
		}
		resp, err := client.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("expected %d for %s (auth=%v), got %d", want, path, withAuth, resp.StatusCode)
		}
	}

	assertStatus("/attachments/"+publicID+"/public.txt", http.StatusOK, false)
	assertStatus("/attachments/"+privateID+"/private.txt", http.StatusNotFound, false)
	assertStatus("/attachments/missing-id/missing.txt", http.StatusNotFound, false)
	assertStatus("/assets/"+publicID+"/thumb.jpg", http.StatusOK, false)
	assertStatus("/assets/"+privateID+"/thumb.jpg", http.StatusNotFound, false)
	assertStatus("/assets/missing-id/thumb.jpg", http.StatusNotFound, false)

	assertStatus("/attachments/"+privateID+"/private.txt", http.StatusOK, true)
	assertStatus("/assets/"+privateID+"/thumb.jpg", http.StatusOK, true)
	assertStatus("/attachments/missing-id/missing.txt", http.StatusNotFound, true)
	assertStatus("/assets/missing-id/thumb.jpg", http.StatusNotFound, true)
}
