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

func TestSplitSpecialTagsKeepsJournalAsRegularTag(t *testing.T) {
	activeTodo, activeDue, activeJournal, tags := splitSpecialTags([]string{"todo", "JOURNAL", "due", "dev"})
	if !activeTodo {
		t.Fatalf("expected todo special tag to remain active")
	}
	if !activeDue {
		t.Fatalf("expected due special tag to remain active")
	}
	if activeJournal {
		t.Fatalf("expected journal to no longer be a special tag")
	}
	if len(tags) != 2 || tags[0] != "JOURNAL" || tags[1] != "dev" {
		t.Fatalf("unexpected regular tags: %#v", tags)
	}
}

func TestDailyIndexBehavesLikeHomeWithForcedJournalTag(t *testing.T) {
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

	if err := os.WriteFile(filepath.Join(notesDir, "journal-note.md"), []byte("# Journal Note\n\n#JOURNAL\n"), 0o644); err != nil {
		t.Fatalf("write journal note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "work-note.md"), []byte("# Work Note\n\n#work\n"), 0o644); err != nil {
		t.Fatalf("write work note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "journal-work-note.md"), []byte("# Journal Work Note\n\n#JOURNAL #work\n"), 0o644); err != nil {
		t.Fatalf("write journal work note: %v", err)
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

	resp, err := http.Get(ts.URL + "/daily")
	if err != nil {
		t.Fatalf("get /daily: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	html := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/daily status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "id=\"notes-feed\"") {
		t.Fatalf("expected /daily to render home layout, got %s", html)
	}
	if strings.Contains(html, "No journal notes updated on this day.") {
		t.Fatalf("expected /daily to not render /daily/{date} template, got %s", html)
	}
	if !strings.Contains(html, "t=JOURNAL") {
		t.Fatalf("expected forced JOURNAL tag query on /daily, got %s", html)
	}

	resp, err = http.Get(ts.URL + "/daily?t=work")
	if err != nil {
		t.Fatalf("get /daily?t=work: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	html = string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/daily?t=work status %d: %s", resp.StatusCode, strings.TrimSpace(html))
	}
	if !strings.Contains(html, "t=work,JOURNAL") && !strings.Contains(html, "t=JOURNAL,work") {
		t.Fatalf("expected forced JOURNAL merged with existing tags, got %s", html)
	}
	if strings.Contains(html, "JOURNAL,JOURNAL") {
		t.Fatalf("expected JOURNAL tag deduplication, got %s", html)
	}
}
