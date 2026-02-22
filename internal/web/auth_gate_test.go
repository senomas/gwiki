package web

import (
	"context"
	"net/http"
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
		"/completed",
		"/archived",
		"/notes/page",
		"/notes/section?name=planned",
		"/todo/page",
		"/completed/page",
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

func TestLoginRateLimitReturnsTooManyRequests(t *testing.T) {
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
		RepoPath:                      repo,
		DataPath:                      dataDir,
		ListenAddr:                    "127.0.0.1:0",
		AuthFile:                      authFile,
		LoginRateLimitIPWindow:        time.Minute,
		LoginRateLimitIPBlock:         2 * time.Minute,
		LoginRateLimitIPMaxAttempts:   2,
		LoginRateLimitUserWindow:      10 * time.Minute,
		LoginRateLimitUserBlock:       10 * time.Minute,
		LoginRateLimitUserBlockAfter:  99,
		LoginRateLimitDelayStartAfter: 99,
		LoginRateLimitDelayMax:        30 * time.Second,
		LoginRateLimitSweep:           time.Minute,
	}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	doLogin := func(password string) *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set("username", "dev")
		form.Set("password", password)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "127.0.0.1:34567"
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	first := doLogin("wrong-1")
	if first.Code != http.StatusOK {
		t.Fatalf("expected first invalid login to return 200, got %d", first.Code)
	}
	second := doLogin("wrong-2")
	if second.Code != http.StatusOK {
		t.Fatalf("expected second invalid login to return 200, got %d", second.Code)
	}
	third := doLogin("wrong-3")
	if third.Code != http.StatusTooManyRequests {
		t.Fatalf("expected third login to be rate limited, got %d", third.Code)
	}
	if strings.TrimSpace(third.Header().Get("Retry-After")) == "" {
		t.Fatalf("expected Retry-After header on rate-limited login")
	}
	body := strings.ToLower(third.Body.String())
	if !strings.Contains(body, "too many login attempts") {
		t.Fatalf("expected rate-limit message, got %q", third.Body.String())
	}
}
