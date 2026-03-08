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

func TestHomeNotesPageETagInvalidatesAfterDelete(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "alpha.md"), []byte("# Alpha\n\nhello\n"), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
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

	url := ts.URL + "/notes/page?offset=0"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get home notes page: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	html := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("home notes page status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "Alpha") {
		t.Fatalf("expected initial home notes page to include note title, got %s", html)
	}
	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	if etag == "" {
		t.Fatalf("expected ETag header on home notes page")
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("If-None-Match", etag)
	notModifiedResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("conditional get home notes page: %v", err)
	}
	_, _ = io.Copy(io.Discard, notModifiedResp.Body)
	_ = notModifiedResp.Body.Close()
	if notModifiedResp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected conditional home notes page status %d, got %d", http.StatusNotModified, notModifiedResp.StatusCode)
	}

	time.Sleep(1100 * time.Millisecond)
	if err := os.Remove(filepath.Join(notesDir, "alpha.md")); err != nil {
		t.Fatalf("remove note: %v", err)
	}
	_, _, cleaned, err := idx.ReconcileFilesFromDBWithStats(context.Background(), repo)
	if err != nil {
		t.Fatalf("reconcile files: %v", err)
	}
	if cleaned == 0 {
		t.Fatalf("expected reconcile to clean removed note from index")
	}

	reqAfterDelete, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request after delete: %v", err)
	}
	reqAfterDelete.Header.Set("If-None-Match", etag)
	updatedResp, err := http.DefaultClient.Do(reqAfterDelete)
	if err != nil {
		t.Fatalf("conditional get home notes page after delete: %v", err)
	}
	updatedBody, _ := io.ReadAll(updatedResp.Body)
	_ = updatedResp.Body.Close()
	updatedHTML := string(updatedBody)
	if updatedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected conditional home notes page after delete status %d, got %d: %s", http.StatusOK, updatedResp.StatusCode, strings.TrimSpace(updatedHTML))
	}
	if strings.Contains(updatedHTML, "Alpha") {
		t.Fatalf("expected deleted note to disappear from home notes page, got %s", updatedHTML)
	}
}
