//go:build http_test
// +build http_test

package web

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/index"
)

func newLoopbackServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	ts.Listener = ln
	ts.Start()
	return ts
}

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
	ts := newLoopbackServer(t, srv.Handler())
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

func TestEditDeleteRequireOwnerScopedRoute(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	content := "# Strict route\n\ncontent\n"
	noteRel := "strict-route.md"
	fullPath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := newLoopbackServer(t, srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/notes/" + noteRel + "/edit")
	if err != nil {
		t.Fatalf("legacy edit request failed: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("legacy edit status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	resp.Body.Close()

	deleteReq, err := http.NewRequest(http.MethodPost, ts.URL+"/notes/"+noteRel+"/delete", nil)
	if err != nil {
		t.Fatalf("legacy delete request build failed: %v", err)
	}
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err != nil {
		t.Fatalf("legacy delete request failed: %v", err)
	}
	if deleteResp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(deleteResp.Body)
		deleteResp.Body.Close()
		t.Fatalf("legacy delete status %d: %s", deleteResp.StatusCode, strings.TrimSpace(string(body)))
	}
	deleteResp.Body.Close()

	scopedResp, err := http.Get(ts.URL + "/notes/@" + notePath + "/edit")
	if err != nil {
		t.Fatalf("scoped edit request failed: %v", err)
	}
	if scopedResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(scopedResp.Body)
		scopedResp.Body.Close()
		t.Fatalf("scoped edit status %d: %s", scopedResp.StatusCode, strings.TrimSpace(string(body)))
	}
	scopedResp.Body.Close()
}

func TestSearchHashQueryUsesTagFuzzyOnly(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	files := map[string]string{
		"tagged.md": `# Tagged Note

Tagged via #wellness only.
`,
		"body.md": `# Body Note

This has wellness in body but no tag.
`,
	}
	for name, content := range files {
		full := filepath.Join(notesDir, name)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		info, err := os.Stat(full)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		notePath := filepath.ToSlash(filepath.Join(owner, name))
		if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
			t.Fatalf("index %s: %v", name, err)
		}
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := newLoopbackServer(t, srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/search?q=%23wlns")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)
	if !strings.Contains(html, "#wellness") {
		t.Fatalf("expected tag suggestion in results, got %s", html)
	}
	if strings.Contains(html, "Tagged Note") || strings.Contains(html, "Body Note") {
		t.Fatalf("expected tag-only results when query starts with #, got %s", html)
	}
}

func TestQuickLauncherSlashQueryUsesPathTitleNotesOnly(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	files := map[string]string{
		"routes/demo-path.md": `# Demo Route

This matches by title/path.
`,
		"body-only.md": `# Body Note

Contains demo in body only.
`,
	}
	for relPath, content := range files {
		full := filepath.Join(notesDir, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", relPath, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", relPath, err)
		}
		info, err := os.Stat(full)
		if err != nil {
			t.Fatalf("stat %s: %v", relPath, err)
		}
		notePath := filepath.ToSlash(filepath.Join(owner, relPath))
		if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
			t.Fatalf("index %s: %v", relPath, err)
		}
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/quick/launcher?q=%2Fdemo&uri=%2F")
	if err != nil {
		t.Fatalf("quick launcher: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, `data-note-path="local/routes/demo-path.md"`) {
		t.Fatalf("expected slash query to return title/path note, got %s", html)
	}
	if strings.Contains(html, `data-note-path="local/body-only.md"`) {
		t.Fatalf("expected slash query to exclude body-only note, got %s", html)
	}
	if strings.Contains(html, `data-tag=`) {
		t.Fatalf("expected slash query to hide tags, got %s", html)
	}
	if strings.Contains(html, `>Folder</span>`) {
		t.Fatalf("expected slash query to hide folders, got %s", html)
	}
	if strings.Contains(html, `href="/notes/new"`) || strings.Contains(html, `href="/todo"`) {
		t.Fatalf("expected slash query to hide actions, got %s", html)
	}
}

func TestDevNotesPageShowsParsedBlocks(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	noteRel := "debug-blocks.md"
	content := strings.Join([]string{
		"# Root",
		"line one",
		"  nested detail",
		"---",
		"  indented block",
		" dedent split",
	}, "\n")
	fullPath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/dev/notes/@" + notePath)
	if err != nil {
		t.Fatalf("get dev blocks: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get dev blocks status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)
	if !strings.Contains(html, "Debug Note Blocks") {
		t.Fatalf("expected debug page title, got %s", html)
	}
	if !strings.Contains(html, "block #1") {
		t.Fatalf("expected block metadata, got %s", html)
	}
	if !strings.Contains(html, "parent=") {
		t.Fatalf("expected parent metadata, got %s", html)
	}
	if !strings.Contains(html, "line one") {
		t.Fatalf("expected raw markdown content, got %s", html)
	}
}

func TestDevTagPageShowsMatchAndAncestorPrefix(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	noteRel := "debug-tag.md"
	content := strings.Join([]string{
		"# demo",
		"",
		"- data",
		"  xx",
		"  - other",
		"    should-hide",
		"  - sub-data",
		"    this is yyy #tag1",
		"",
		"  #tag2",
	}, "\n")
	fullPath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/dev/tag/tag1")
	if err != nil {
		t.Fatalf("get dev tag: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get dev tag status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, "Debug Tag Blocks") {
		t.Fatalf("expected debug tag page title, got %s", html)
	}
	if !strings.Contains(html, "selected lines:") {
		t.Fatalf("expected selected line metadata, got %s", html)
	}
	if !strings.Contains(html, "note-body") {
		t.Fatalf("expected rendered markdown container, got %s", html)
	}
	if !strings.Contains(html, "<li>data") || !strings.Contains(html, "xx") {
		t.Fatalf("expected ancestor prefix rendered lines, got %s", html)
	}
	if !strings.Contains(html, "this is yyy #tag1") {
		t.Fatalf("expected matching block lines, got %s", html)
	}
	if !strings.Contains(html, "sub-data") {
		t.Fatalf("expected matching block parent line, got %s", html)
	}
	if !strings.Contains(html, "<h1") || !strings.Contains(html, "demo</h1>") {
		t.Fatalf("expected ancestor heading context, got %s", html)
	}
	if strings.Contains(html, ">other<") || strings.Contains(html, "should-hide") {
		t.Fatalf("expected non-matching sibling block excluded, got %s", html)
	}
	if strings.Contains(html, "#tag2") {
		t.Fatalf("expected suffix lines after matched block excluded, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/dev/tag/%23tag1")
	if err != nil {
		t.Fatalf("get dev tag encoded hash: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get dev tag encoded hash status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	resp.Body.Close()
}

func TestNoteCardTagFilterRendersContextAndHidesMentionOnly(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	noteRel := "filter-card.md"
	content := strings.Join([]string{
		"# demo",
		"",
		"- data",
		"  xx",
		"  - other",
		"    should-hide",
		"  - sub-data",
		"    this is yyy #tag1",
		"",
		"  #tag2",
	}, "\n")
	fullPath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/notes/@" + notePath + "/card?t=tag1")
	if err != nil {
		t.Fatalf("get card hashtag: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get card hashtag status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, "Metadata") {
		t.Fatalf("expected note card metadata section, got %s", html)
	}
	if !strings.Contains(html, "this is yyy #tag1") {
		t.Fatalf("expected matching tag context in card body, got %s", html)
	}
	if strings.Contains(html, "should-hide") || strings.Contains(html, "#tag2") {
		t.Fatalf("expected non-matching/suffix lines excluded from filtered card body, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/notes/@" + notePath + "/card?t=%40dev")
	if err != nil {
		t.Fatalf("get card mention-only: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get card mention-only status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	html = string(body)

	if !strings.Contains(html, "Metadata") {
		t.Fatalf("expected note card metadata section for mention-only filter, got %s", html)
	}
	if strings.Contains(html, "this is yyy #tag1") || strings.Contains(html, "should-hide") {
		t.Fatalf("expected mention-only filter to hide note body content, got %s", html)
	}
}

func TestNoteCardTagFilterMovesCompletedToHiding(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	noteRel := "filter-card-completed.md"
	content := strings.Join([]string{
		"# demo",
		"",
		"- [x] done tagged #tag1",
		"- [ ] open tagged #tag1",
	}, "\n")
	fullPath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/notes/@" + notePath + "/card?t=tag1")
	if err != nil {
		t.Fatalf("get card hashtag: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get card hashtag status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	if !strings.Contains(html, "open tagged #tag1") {
		t.Fatalf("expected open tagged task visible in filtered card body, got %s", html)
	}
	if !strings.Contains(html, "Hiding (1 completed task)") {
		t.Fatalf("expected completed tagged task moved to hiding section, got %s", html)
	}
	if !strings.Contains(html, "done tagged #tag1") {
		t.Fatalf("expected completed tagged task rendered in hiding section, got %s", html)
	}
}

func TestTodoTagFiltersUseHybridAndHideMentionOnly(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	files := map[string]string{
		"hybrid.md": strings.Join([]string{
			"# hybrid note",
			"",
			"prefix-before",
			"",
			"- [ ] task root #tag1 #inbox",
			"  detail line",
			"- [x] done task #tag1",
		}, "\n"),
		"mention.md": strings.Join([]string{
			"# mention note",
			"",
			"- [ ] ping @dev #inbox",
		}, "\n"),
	}
	for relPath, content := range files {
		full := filepath.Join(notesDir, relPath)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", relPath, err)
		}
		info, err := os.Stat(full)
		if err != nil {
			t.Fatalf("stat %s: %v", relPath, err)
		}
		notePath := filepath.ToSlash(filepath.Join(owner, relPath))
		if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
			t.Fatalf("index %s: %v", relPath, err)
		}
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/todo?t=tag1")
	if err != nil {
		t.Fatalf("get todo hashtag: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get todo hashtag status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)
	if strings.Contains(html, "prefix-before") {
		t.Fatalf("expected sibling context to be excluded in todo body, got %s", html)
	}
	if !strings.Contains(html, "task root #tag1 #inbox") {
		t.Fatalf("expected todo task snippet retained in hybrid mode, got %s", html)
	}
	if strings.Count(html, "task root #tag1 #inbox") != 1 {
		t.Fatalf("expected tagged todo line rendered once in hybrid mode, got %s", html)
	}
	if !strings.Contains(html, `hx-post="/tasks/toggle"`) {
		t.Fatalf("expected todo checkbox to be clickable, got %s", html)
	}
	taskIDLine := regexp.MustCompile(`task-\d+-(\d+)-[0-9a-f]{64}`)
	match := taskIDLine.FindStringSubmatch(html)
	if len(match) < 2 {
		t.Fatalf("expected task id with source line mapping, got %s", html)
	}
	if match[1] != "5" {
		t.Fatalf("expected task id to keep source line 5, got %s in %s", match[1], html)
	}
	if strings.Contains(html, "done task #tag1") {
		t.Fatalf("expected completed tagged tasks hidden in todo tag-filter context, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/todo?t=%40dev")
	if err != nil {
		t.Fatalf("get todo mention-only: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("get todo mention-only status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	html = string(body)
	if !strings.Contains(html, "mention note") {
		t.Fatalf("expected mention note card title, got %s", html)
	}
	if strings.Contains(html, "ping @dev") || strings.Contains(html, "task root #tag1 #inbox") {
		t.Fatalf("expected mention-only todo filter to hide note body content, got %s", html)
	}
}

func TestTagFilteredPagesShowHiddenExclusiveSeparator(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	files := map[string]string{
		"hidden.md": strings.Join([]string{
			"# Hidden Exclusive Note",
			"",
			"#tag1 #place!",
			"- [ ] hidden open #tag1",
			"- [x] hidden done #tag1",
		}, "\n"),
		"visible.md": strings.Join([]string{
			"# Visible Note",
			"",
			"#tag1",
			"- [ ] visible open #tag1",
			"- [x] visible done #tag1",
		}, "\n"),
	}
	for relPath, content := range files {
		full := filepath.Join(notesDir, relPath)
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", relPath, err)
		}
		info, err := os.Stat(full)
		if err != nil {
			t.Fatalf("stat %s: %v", relPath, err)
		}
		notePath := filepath.ToSlash(filepath.Join(owner, relPath))
		if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
			t.Fatalf("index %s: %v", relPath, err)
		}
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := newLoopbackServer(t, srv.Handler())
	defer ts.Close()

	cases := []struct {
		name string
		path string
	}{
		{name: "home", path: "/?t=tag1"},
		{name: "todo", path: "/todo?t=tag1"},
		{name: "completed", path: "/completed?t=tag1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("get %s: %v", tc.path, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			html := string(body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s status %d: %s", tc.path, resp.StatusCode, strings.TrimSpace(html))
			}
			if !strings.Contains(html, "Hidden note exclusive") {
				t.Fatalf("expected hidden-exclusive separator in %s, got %s", tc.path, html)
			}
			if !strings.Contains(html, "#place") {
				t.Fatalf("expected hidden-exclusive tag link in %s, got %s", tc.path, html)
			}
			if !strings.Contains(html, "t=tag1%2Cplace") {
				t.Fatalf("expected hidden-exclusive add-tag link in %s, got %s", tc.path, html)
			}
		})
	}
}

func TestCompletedPageArchiveTaskFlow(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	content := strings.Join([]string{
		"# Work",
		"",
		"- [ ] open task #tag1",
		"- [x] done task one #tag1",
		"  details done",
		"- [x] done task two #tag2",
	}, "\n")
	noteRel := "tasks.md"
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	fullNotePath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullNotePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullNotePath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	completedTasks, err := idx.CompletedTasksWithMentions(ctx, nil, nil, owner, 20, false, "", "", false, false)
	if err != nil {
		t.Fatalf("completed tasks: %v", err)
	}
	var target index.TaskItem
	found := false
	for _, item := range completedTasks {
		if strings.Contains(item.Text, "done task one") {
			target = item
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected completed task 'done task one', got %+v", completedTasks)
	}
	targetTaskID := taskCheckboxID(target.FileID, target.LineNo, target.Hash)

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := newLoopbackServer(t, srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/completed")
	if err != nil {
		t.Fatalf("get completed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("completed status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "done task one #tag1") {
		t.Fatalf("expected completed task in page, got %s", html)
	}
	if strings.Contains(html, "open task #tag1") {
		t.Fatalf("expected open task hidden from completed page, got %s", html)
	}
	if !strings.Contains(html, `hx-post="/tasks/archive"`) {
		t.Fatalf("expected archive action in completed page, got %s", html)
	}

	form := url.Values{}
	form.Set("task_id", targetTaskID)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/tasks/archive", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new archive request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post archive task: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("archive status %d", resp.StatusCode)
	}
	if strings.TrimSpace(resp.Header.Get("HX-Refresh")) != "true" {
		t.Fatalf("expected HX-Refresh header, got %q", resp.Header.Get("HX-Refresh"))
	}

	updatedSource, err := os.ReadFile(fullNotePath)
	if err != nil {
		t.Fatalf("read updated source note: %v", err)
	}
	updatedText := string(updatedSource)
	if strings.Contains(updatedText, "done task one #tag1") {
		t.Fatalf("expected archived task removed from source note: %s", updatedText)
	}
	if !strings.Contains(updatedText, "done task two #tag2") {
		t.Fatalf("expected other completed task to remain: %s", updatedText)
	}

	archivePath := filepath.Join(repo, owner, "archive", noteRel)
	archiveContent, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("read archive file: %v", err)
	}
	archiveText := string(archiveContent)
	if !strings.Contains(archiveText, "done task one #tag1") {
		t.Fatalf("expected archived task in archive file: %s", archiveText)
	}
	if !strings.Contains(archiveText, "details done") {
		t.Fatalf("expected archived task block continuation preserved: %s", archiveText)
	}

	inIndex, err := idx.NoteExists(ctx, filepath.ToSlash(filepath.Join(owner, "archive", noteRel)))
	if err != nil {
		t.Fatalf("archive note exists check: %v", err)
	}
	if inIndex {
		t.Fatalf("expected archive file not indexed")
	}

	resp, err = http.Get(ts.URL + "/archived")
	if err != nil {
		t.Fatalf("get archived list: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	html = string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("archived list status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "local/tasks.md") {
		t.Fatalf("expected archived list to include path, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/archived/@local/tasks.md")
	if err != nil {
		t.Fatalf("get archived detail: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	html = string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("archived detail status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "done task one #tag1") {
		t.Fatalf("expected archived detail content, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/completed")
	if err != nil {
		t.Fatalf("get completed after archive: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	html = string(body)
	if strings.Contains(html, "done task one #tag1") {
		t.Fatalf("expected archived task removed from completed page: %s", html)
	}
}

func TestQuickLauncherHashQueryReturnsTagsOnly(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(filepath.Join(notesDir, "demo-folder"), 0o755); err != nil {
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

	files := map[string]string{
		"demo-tagged.md": `# Demo Tag Note

Tagged with #demo.
`,
		"demo-folder/demo-body.md": `# Demo Body Note

Contains demo text in body.
`,
	}
	for relPath, content := range files {
		full := filepath.Join(notesDir, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", relPath, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", relPath, err)
		}
		info, err := os.Stat(full)
		if err != nil {
			t.Fatalf("stat %s: %v", relPath, err)
		}
		notePath := filepath.ToSlash(filepath.Join(owner, relPath))
		if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
			t.Fatalf("index %s: %v", relPath, err)
		}
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/quick/launcher?q=%23dmo&uri=%2F")
	if err != nil {
		t.Fatalf("quick launcher: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)
	if !strings.Contains(html, `data-tag="demo"`) {
		t.Fatalf("expected tag entry in quick launcher, got %s", html)
	}
	if strings.Contains(html, `data-note-path=`) {
		t.Fatalf("expected no note entries when query starts with #, got %s", html)
	}
	if strings.Contains(html, ">Folder</span>") {
		t.Fatalf("expected no folder entries when query starts with #, got %s", html)
	}
}

func TestSaveNoteNoChangeHTMXReturnsRedirectLocation(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
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

	frontmatter := strings.Join([]string{
		"---",
		"id: e099db2a-8706-4492-9983-d2d7c1465715",
		"title: Bookmark",
		"created: 2026-02-10T13:53:31+07:00",
		"updated: 2026-02-17T10:27:28+07:00",
		"priority: 2",
		"visibility: inherited",
		"---",
		"",
	}, "\n")
	body := strings.Join([]string{
		"# Bookmark",
		"",
		"[[@seno/place/solo.md]]",
		"",
		"[[@seno/place/yogyakarta.md]]",
		"",
		"[[healing/magelang.md]]",
		"",
		"[[healing/salatiga.md]]",
		"",
		"[[healing/traveling/banyuwangi.md]]",
		"",
	}, "\n")
	content := frontmatter + body
	noteRel := "bookmark.md"
	fullPath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	if err := idx.IndexNote(ctx, notePath, []byte(content), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	form := url.Values{}
	form.Set("frontmatter", frontmatter)
	form.Set("content", body)
	form.Set("owner", owner)
	form.Set("visibility", "inherited")
	form.Set("folder", "")
	form.Set("priority", "2")
	form.Set("return_url", "/@local")
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/notes/@"+notePath+"/save", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	req.Header.Set("HX-Current-Url", ts.URL+"/notes/@"+notePath+"/edit")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post save: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 204, got %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	if got := strings.TrimSpace(resp.Header.Get("X-Redirect-Location")); got != "/@local" {
		t.Fatalf("expected X-Redirect-Location /@local, got %q", got)
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
