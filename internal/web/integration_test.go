//go:build http_test
// +build http_test

package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/index"
)

func TestIntegrationFlow(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	if err := os.MkdirAll(filepath.Join(repo, owner, "notes"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	idx, err := index.Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	form := url.Values{}
	form.Set("content", "# My Note\n\nHello world")
	resp, err := http.PostForm(ts.URL+"/notes/new", form)
	if err != nil {
		t.Fatalf("post new: %v", err)
	}
	resp.Body.Close()

	notePath := owner + "/my-note.md"
	noteURL := "/notes/@" + notePath
	resp, err = http.Get(ts.URL + noteURL + "/edit")
	if err != nil {
		t.Fatalf("get edit: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get edit status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	resp.Body.Close()

	save := url.Values{}
	save.Set("content", "# My Note\n\nHello world")
	resp, err = http.PostForm(ts.URL+noteURL+"/save", save)
	if err != nil {
		t.Fatalf("post save: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + noteURL)
	if err != nil {
		t.Fatalf("get view: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get view status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/notes/" + notePath)
	if err != nil {
		t.Fatalf("get legacy view: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get legacy view status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	resp.Body.Close()

	resp, err = http.Get(ts.URL + "/search?q=Hello")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "My Note") {
		t.Fatalf("expected search results to include note title")
	}
}

func TestCollapsedSectionsRenderFromStore(t *testing.T) {
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

	noteRel := "bookmark.md"
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	content := strings.Join([]string{
		"---",
		"id: note-1",
		"created: 2026-01-14T01:00:00Z",
		"updated: 2026-01-14T01:00:00Z",
		"visibility: private",
		"collapsed_h2: [4]",
		"---",
		"",
		"# Bookmark",
		"Intro line.",
		"",
		"## Homelab",
		"Proxmox",
	}, "\n")
	fullPath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/notes/@" + notePath + "/detail")
	if err != nil {
		t.Fatalf("get detail: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	html := string(body)
	if !strings.Contains(html, `data-line-no="4"`) {
		t.Fatalf("expected homelab section to render, got %s", html)
	}
	tag := detailsTagForLine(html, `data-line-no="4"`)
	if tag == "" {
		t.Fatalf("expected details tag for homelab, got %s", html)
	}
	if strings.Contains(tag, "open") {
		t.Fatalf("expected homelab section to be collapsed, got %s", tag)
	}
}

func detailsTagForLine(html, lineAttr string) string {
	idx := strings.Index(html, lineAttr)
	if idx == -1 {
		return ""
	}
	start := strings.LastIndex(html[:idx], "<details")
	if start == -1 {
		return ""
	}
	end := strings.Index(html[idx:], ">")
	if end == -1 {
		return ""
	}
	return html[start : idx+end+1]
}
