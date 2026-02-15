package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gwiki/internal/auth"
	"gwiki/internal/config"
	"gwiki/internal/index"
)

func TestIndexAndTodoRequireAuth(t *testing.T) {
	repo := t.TempDir()
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "local", "notes"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}

	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	authFile := filepath.Join(dataDir, "auth.txt")
	if err := os.WriteFile(authFile, []byte("dev:"+hash+":2099-01-01\n"), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
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

	cfg := config.Config{
		RepoPath:   repo,
		DataPath:   dataDir,
		ListenAddr: "127.0.0.1:0",
		AuthFile:   authFile,
	}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	paths := []string{
		"/",
		"/todo",
		"/notes/page",
		"/notes/section?name=planned",
		"/todo/page",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected status %d, got %d", p, http.StatusUnauthorized, rec.Code)
		}
		body := strings.ToLower(rec.Body.String())
		if !strings.Contains(body, "login") {
			t.Fatalf("%s: expected login prompt body, got %q", p, rec.Body.String())
		}
	}
}

