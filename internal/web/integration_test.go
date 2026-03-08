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

func TestNewNoteWithoutTitleUsesSplitJournalPathPattern(t *testing.T) {
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
	form.Set("content", "plain journal entry without heading")
	resp, err := http.PostForm(ts.URL+"/notes/new", form)
	if err != nil {
		t.Fatalf("post new note without title: %v", err)
	}
	defer resp.Body.Close()

	if resp.Request == nil || resp.Request.URL == nil {
		t.Fatalf("expected final request URL after redirect")
	}
	finalPath := resp.Request.URL.Path
	relPath := strings.TrimPrefix(finalPath, "/notes/@"+owner+"/")
	if relPath == finalPath {
		relPath = strings.TrimPrefix(finalPath, "/notes/")
	}
	pathRe := regexp.MustCompile(`^(\d{4}-\d{2})/(\d{2})-(\d{2})-(\d{2})(?:-\d+)?\.md$`)
	matches := pathRe.FindStringSubmatch(relPath)
	if len(matches) != 5 {
		t.Fatalf("expected split journal path, got %q", finalPath)
	}
	fullPath := filepath.Join(repo, owner, "notes", filepath.FromSlash(relPath))
	contentBytes, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("read created split journal note: %v", err)
	}
	content := string(contentBytes)

	dayDate, err := time.ParseInLocation("2006-01-02", matches[1]+"-"+matches[2], time.Local)
	if err != nil {
		t.Fatalf("parse journal date from path: %v", err)
	}
	expectedDateHeading := "# " + dayDate.Format("2 Jan 2006")
	if strings.Contains(content, expectedDateHeading) {
		t.Fatalf("did not expect date heading %q in note content, got %q", expectedDateHeading, content)
	}
	if strings.Contains(content, "## "+matches[3]+":"+matches[4]) {
		t.Fatalf("did not expect injected time heading in note content, got %q", content)
	}
	if !strings.Contains(content, "plain journal entry without heading") {
		t.Fatalf("expected journal body text preserved, got %q", content)
	}
}

func TestDailyShowsAllJournalNotesUpdatedOnSelectedDate(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes", "2026-02")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	if err := os.WriteFile(filepath.Join(notesDir, "22-09-35.md"), []byte("journal entry one\n"), 0o644); err != nil {
		t.Fatalf("write split journal one: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "22-10-10.md"), []byte("journal entry two\n"), 0o644); err != nil {
		t.Fatalf("write split journal two: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "23-09-00.md"), []byte("journal entry next day\n"), 0o644); err != nil {
		t.Fatalf("write split journal next day: %v", err)
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

	resp, err := http.Get(ts.URL + "/daily/2026-02-22")
	if err != nil {
		t.Fatalf("get daily: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("daily status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "22 Feb 2026 09:35") {
		t.Fatalf("expected first split journal title, got %s", html)
	}
	if !strings.Contains(html, "22 Feb 2026 10:10") {
		t.Fatalf("expected second split journal title, got %s", html)
	}
	if strings.Contains(html, "23 Feb 2026 09:00") {
		t.Fatalf("did not expect next-day split journal title, got %s", html)
	}
	dayOneLinkRE := regexp.MustCompile(`/notes/(?:@local/)?2026-02/22-09-35\.md`)
	dayTwoLinkRE := regexp.MustCompile(`/notes/(?:@local/)?2026-02/22-10-10\.md`)
	if got := len(dayOneLinkRE.FindAllStringIndex(html, -1)); got != 1 {
		t.Fatalf("expected journal link rendered once for 22-09-35, got %d", got)
	}
	if got := len(dayTwoLinkRE.FindAllStringIndex(html, -1)); got != 1 {
		t.Fatalf("expected journal link rendered once for 22-10-10, got %d", got)
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

func TestNoteDetailLinksExposeDoubleClickOwnership(t *testing.T) {
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

	content := "# Dblclick Contract\n\nbody\n"
	noteRel := "dblclick-contract.md"
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

	resp, err := http.Get(ts.URL + "/notes/@" + owner + "/" + noteRel)
	if err != nil {
		t.Fatalf("get note view: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("view status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	body := string(bodyBytes)
	if !strings.Contains(body, `class="text-sky-300 hover:text-sky-200 js-note-actions"`) {
		t.Fatalf("expected note action link in rendered detail, got %s", body)
	}
	if !strings.Contains(body, `data-dblclick-own="true"`) {
		t.Fatalf("expected data-dblclick-own on note action link, got %s", body)
	}
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
	ts := newLoopbackServer(t, srv.Handler())
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

func TestNoteCardTagFilterPreservesInboxSourceLineMapping(t *testing.T) {
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

	noteRel := "filter-card-inbox-mapping.md"
	content := strings.Join([]string{
		"---",
		"id: card-inbox-mapping",
		"---",
		"",
		"- [ ] task root #tag1 #inbox #signal",
		"  detail line",
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

	if !strings.Contains(html, `js-inbox-action`) {
		t.Fatalf("expected inbox link action class, got %s", html)
	}
	if !strings.Contains(html, "line=2-") {
		t.Fatalf("expected inbox create link to keep source start line 2, got %s", html)
	}
	taskIDLine := regexp.MustCompile(`task-\d+-(\d+)-[0-9a-f]{64}`)
	match := taskIDLine.FindStringSubmatch(html)
	if len(match) < 2 {
		t.Fatalf("expected inbox task id with source line mapping, got %s", html)
	}
	if match[1] != "2" {
		t.Fatalf("expected inbox task id to keep source line 2, got %s in %s", match[1], html)
	}
}

func TestNoteCardMissingFileRemovesStaleDBEntry(t *testing.T) {
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

	noteRel := "stale-card.md"
	content := "# stale\n\nbody"
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

	userCtx := WithUser(ctx, User{Name: owner, Authenticated: true})
	exists, err := idx.NoteExists(userCtx, notePath)
	if err != nil {
		t.Fatalf("note exists before delete: %v", err)
	}
	if !exists {
		t.Fatalf("expected indexed note to exist before file removal")
	}

	if err := os.Remove(fullPath); err != nil {
		t.Fatalf("remove note file: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := newLoopbackServer(t, srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/notes/@" + notePath + "/card")
	if err != nil {
		t.Fatalf("get missing note card: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected missing note card status %d, got %d body=%s", http.StatusNotFound, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	exists, err = idx.NoteExists(userCtx, notePath)
	if err != nil {
		t.Fatalf("note exists after missing card request: %v", err)
	}
	if exists {
		t.Fatalf("expected stale DB entry removed after missing note card request")
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

	resp, err := http.Get(ts.URL + "/todo/page?offset=0&t=tag1")
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
	if !strings.Contains(html, "task root #tag1") {
		t.Fatalf("expected todo task snippet retained in hybrid mode, got %s", html)
	}
	if strings.Count(html, "task root #tag1") != 1 {
		t.Fatalf("expected tagged todo line rendered once in hybrid mode, got %s", html)
	}
	if !strings.Contains(html, `data-inbox-create-href="`) {
		t.Fatalf("expected todo task inbox tag rendered as action link, got %s", html)
	}
	if !strings.Contains(html, `hx-post="/tasks/toggle"`) {
		t.Fatalf("expected todo checkbox to be clickable, got %s", html)
	}
	if !strings.Contains(html, `js-inbox-action`) {
		t.Fatalf("expected inbox link to expose inbox action class, got %s", html)
	}
	if !strings.Contains(html, `data-inbox-task-id="task-`) {
		t.Fatalf("expected inbox link to carry task id metadata, got %s", html)
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

	resp, err = http.Get(ts.URL + "/todo/page?offset=0&t=%40dev")
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
	if strings.Contains(html, "ping @dev") || strings.Contains(html, "task root #tag1") {
		t.Fatalf("expected mention-only todo filter to hide note body content, got %s", html)
	}
}

func TestConvertInboxTaskToPlainListItem(t *testing.T) {
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
		"# Inbox",
		"",
		"- [ ] triage this #inbox #signal #dev",
		"  context line",
	}, "\n")
	relPath := "inbox.md"
	notePath := filepath.ToSlash(filepath.Join(owner, relPath))
	fullPath := filepath.Join(notesDir, relPath)
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
	fileID, err := idx.FileIDByPath(ctx, notePath)
	if err != nil {
		t.Fatalf("file id: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := newLoopbackServer(t, srv.Handler())
	defer ts.Close()

	hash := index.TaskLineHash("- [ ] triage this #inbox #signal #dev")
	form := url.Values{}
	form.Set("task_id", taskCheckboxID(fileID, 3, hash))
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/tasks/convert-inbox", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post convert inbox: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("convert status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	rendered := string(body)
	if !strings.Contains(rendered, "triage this #dev") {
		t.Fatalf("expected converted task text in rendered note body, got %s", rendered)
	}
	if strings.Contains(rendered, "#inbox") || strings.Contains(rendered, "#signal") {
		t.Fatalf("expected inbox and signal tags stripped from rendered note body, got %s", rendered)
	}

	updatedBytes, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("read updated note: %v", err)
	}
	updated := string(updatedBytes)
	if !strings.Contains(updated, "- triage this #dev") {
		t.Fatalf("expected converted markdown list item in source note, got %s", updated)
	}
	if strings.Contains(updated, "- [ ] triage this #inbox #signal #dev") {
		t.Fatalf("expected checkbox form removed from source note, got %s", updated)
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

func TestSidebarTagLinksUseIndexOnNoteDetailAndStayOnListPages(t *testing.T) {
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

	noteRel := "sidebar-tags.md"
	notePath := filepath.ToSlash(filepath.Join(owner, noteRel))
	noteContent := "# Sidebar Tags\n\ncontent #demo\n"
	fullPath := filepath.Join(notesDir, noteRel)
	if err := os.WriteFile(fullPath, []byte(noteContent), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		t.Fatalf("stat note: %v", err)
	}
	if err := idx.IndexNote(ctx, notePath, []byte(noteContent), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index note: %v", err)
	}
	archiveDir := filepath.Join(repo, owner, "archive")
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatalf("mkdir archive: %v", err)
	}
	archiveContent := "- [x] archived #demo\n"
	if err := os.WriteFile(filepath.Join(archiveDir, "sidebar-tags.md"), []byte(archiveContent), 0o644); err != nil {
		t.Fatalf("write archive note: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := newLoopbackServer(t, srv.Handler())
	defer ts.Close()

	cases := []struct {
		name       string
		currentURL string
		wantHref   string
	}{
		{name: "note detail owner scoped routes to owner index", currentURL: "/notes/@local/sidebar-tags.md", wantHref: `href="/@local?t=demo"`},
		{name: "todo stays on todo", currentURL: "/todo", wantHref: `href="/todo?t=demo"`},
		{name: "completed stays on completed", currentURL: "/completed", wantHref: `href="/completed?t=demo"`},
		{name: "archived stays on archived", currentURL: "/archived", wantHref: `href="/archived?t=demo"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/sidebar", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("HX-Current-URL", ts.URL+tc.currentURL)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("do request: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			html := string(body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("sidebar status %d: %s", resp.StatusCode, strings.TrimSpace(html))
			}
			if !strings.Contains(html, tc.wantHref) {
				t.Fatalf("expected sidebar tag href %s, got %s", tc.wantHref, html)
			}
			if !strings.Contains(html, `href="/daily"`) {
				t.Fatalf("expected sidebar daily link href=\"/daily\", got %s", html)
			}
		})
	}
}

func TestCompletedPageArchiveTaskFlow(t *testing.T) {
	requireGit(t)

	repo := t.TempDir()
	owner := "local"
	ownerRepo := filepath.Join(repo, owner)
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
	runGit(t, ownerRepo, "init")
	runGit(t, ownerRepo, "config", "user.name", owner)
	runGit(t, ownerRepo, "config", "user.email", owner+"@example.com")
	runGit(t, ownerRepo, "add", ".")
	runGit(t, ownerRepo, "commit", "-m", "initial note")

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
	headBeforeArchive := runGit(t, ownerRepo, "rev-parse", "HEAD")
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
	headAfterArchive := runGit(t, ownerRepo, "rev-parse", "HEAD")
	if headAfterArchive == headBeforeArchive {
		t.Fatalf("expected new commit after archive, head unchanged at %s", headAfterArchive)
	}
	lastMessage := runGit(t, ownerRepo, "log", "-1", "--format=%s")
	wantMessage := "archive task " + notePath
	if lastMessage != wantMessage {
		t.Fatalf("last commit message=%q want %q", lastMessage, wantMessage)
	}
	lastFiles := runGit(t, ownerRepo, "show", "--name-only", "--pretty=format:", "HEAD")
	if !strings.Contains(lastFiles, filepath.ToSlash(filepath.Join("notes", noteRel))) {
		t.Fatalf("expected source note in archive commit files, got %q", lastFiles)
	}
	if !strings.Contains(lastFiles, filepath.ToSlash(filepath.Join("archive", noteRel))) {
		t.Fatalf("expected archive note in archive commit files, got %q", lastFiles)
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

func TestArchivedJournalTitlesUsePath(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	if err := os.MkdirAll(filepath.Join(repo, owner, "notes"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, owner, "archive", "2026-02"), 0o755); err != nil {
		t.Fatalf("mkdir archive: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	dailyContent := strings.Join([]string{
		"---",
		"title: Manual Daily Title",
		"---",
		"",
		"daily archived body",
	}, "\n")
	splitContent := strings.Join([]string{
		"---",
		"title: Manual Split Title",
		"---",
		"",
		"split archived body",
	}, "\n")
	suffixContent := strings.Join([]string{
		"---",
		"title: Manual Split Suffix Title",
		"---",
		"",
		"suffix archived body",
	}, "\n")
	if err := os.WriteFile(filepath.Join(repo, owner, "archive", "2026-02", "22.md"), []byte(dailyContent), 0o644); err != nil {
		t.Fatalf("write daily archive note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, owner, "archive", "2026-02", "22-09-35.md"), []byte(splitContent), 0o644); err != nil {
		t.Fatalf("write split archive note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, owner, "archive", "2026-02", "22-09-35-2.md"), []byte(suffixContent), 0o644); err != nil {
		t.Fatalf("write split suffix archive note: %v", err)
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

	resp, err := http.Get(ts.URL + "/archived")
	if err != nil {
		t.Fatalf("get archived list: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("archived list status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "22 Feb 2026") {
		t.Fatalf("expected archived list daily journal title, got %s", html)
	}
	if !strings.Contains(html, "22 Feb 2026 09:35") {
		t.Fatalf("expected archived list split journal title, got %s", html)
	}
	if strings.Contains(html, "Manual Daily Title") || strings.Contains(html, "Manual Split Title") || strings.Contains(html, "Manual Split Suffix Title") {
		t.Fatalf("expected archived list journal path title override, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/archived/@local/2026-02/22.md")
	if err != nil {
		t.Fatalf("get archived daily detail: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	html = string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("archived daily detail status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "Archived - 22 Feb 2026") {
		t.Fatalf("expected archived daily page title from path, got %s", html)
	}
	if strings.Contains(html, "Archived - Manual Daily Title") {
		t.Fatalf("expected archived daily explicit title ignored, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/archived/@local/2026-02/22-09-35.md")
	if err != nil {
		t.Fatalf("get archived split detail: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	html = string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("archived split detail status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "Archived - 22 Feb 2026 09:35") {
		t.Fatalf("expected archived split page title from path, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/archived/@local/2026-02/22-09-35-2.md")
	if err != nil {
		t.Fatalf("get archived split suffix detail: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	html = string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("archived split suffix detail status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "Archived - 22 Feb 2026 09:35") {
		t.Fatalf("expected archived split suffix page title from path, got %s", html)
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
