package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gwiki/internal/auth"
	"gwiki/internal/config"
	"gwiki/internal/index"
)

func TestEditForeignNoteWithAccess(t *testing.T) {
	repo := t.TempDir()
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}

	devHash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	authFile := filepath.Join(dataDir, "auth.txt")
	if err := os.WriteFile(authFile, []byte("dev:"+devHash+":2099-01-01\n"), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	owner := "tani"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	noteUID := "63333a78-1030-46ee-9485-0cb236d3efa4"
	notePath := filepath.Join(notesDir, "test-18.md")
	content := `---
id: ` + noteUID + `
---
# Test 18

Foreign note body.
`
	if err := os.WriteFile(notePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}

	accessFile := filepath.Join(notesDir, ".access.txt")
	if err := os.WriteFile(accessFile, []byte("dev:rw\n"), 0o644); err != nil {
		t.Fatalf("write access file: %v", err)
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
	if info, err := os.Stat(notePath); err == nil {
		if err := idx.IndexNote(ctx, filepath.ToSlash(filepath.Join(owner, "test-18.md")), []byte(content), info.ModTime(), info.Size()); err != nil {
			t.Fatalf("index note: %v", err)
		}
	}
	access, err := auth.LoadAccessFromRepo(repo)
	if err != nil {
		t.Fatalf("load access: %v", err)
	}
	accessRules := make(map[string][]index.AccessPathRule, len(access))
	for ownerName, rules := range access {
		converted := make([]index.AccessPathRule, 0, len(rules))
		for _, rule := range rules {
			members := make([]index.AccessMember, 0, len(rule.Members))
			for _, member := range rule.Members {
				members = append(members, index.AccessMember{
					User:   member.User,
					Access: member.Access,
				})
			}
			converted = append(converted, index.AccessPathRule{
				Path:    rule.Path,
				Members: members,
			})
		}
		accessRules[ownerName] = converted
	}
	if _, err := idx.SyncPathAccessWithStats(ctx, accessRules); err != nil {
		t.Fatalf("sync access: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0", AuthFile: authFile}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/notes/"+noteUID+"/edit", nil)
	req = req.WithContext(WithUser(req.Context(), User{Name: "dev", Authenticated: true}))
	rec := httptest.NewRecorder()
	srv.handleNotes(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected edit status 200, got %d", rec.Code)
	}
}
