package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"gwiki/internal/auth"
)

func TestPublicVisibilityFilter(t *testing.T) {
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

	publicContent := `---
id: public-note
visibility: public
---
# Public Note

Shared content with #publictag.
`
	privateContent := `---
id: private-note
visibility: private
---
# Private Note

Secret bananas with #privatetag.
`
	if err := os.WriteFile(filepath.Join(notesDir, "public.md"), []byte(publicContent), 0o644); err != nil {
		t.Fatalf("write public note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "private.md"), []byte(privateContent), 0o644); err != nil {
		t.Fatalf("write private note: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	publicCtx := WithPublicVisibility(ctx)
	notes, err := idx.NoteList(publicCtx, NoteListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("note list: %v", err)
	}
	if len(notes) != 1 || notes[0].Path != "local/public.md" {
		t.Fatalf("expected only public note, got %+v", notes)
	}

	results, err := idx.Search(publicCtx, "bananas", 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no private search results, got %+v", results)
	}

	tags, err := idx.ListTags(publicCtx, 100, "", false, false, "")
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	for _, tag := range tags {
		if tag.Name == "privatetag" {
			t.Fatalf("private tag leaked: %+v", tags)
		}
	}

	exists, err := idx.NoteExists(publicCtx, "local/private.md")
	if err != nil {
		t.Fatalf("note exists: %v", err)
	}
	if exists {
		t.Fatalf("expected private note to be hidden from public access")
	}

	if err := os.Remove(filepath.Join(notesDir, "public.md")); err != nil {
		t.Fatalf("remove public note: %v", err)
	}
	if err := os.Remove(filepath.Join(notesDir, "private.md")); err != nil {
		t.Fatalf("remove private note: %v", err)
	}
	if _, _, _, err := idx.RecheckFromFS(ctx, repo); err != nil {
		t.Fatalf("recheck after delete: %v", err)
	}
	notes, err = idx.NoteList(publicCtx, NoteListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("note list after delete: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("expected no notes after delete, got %+v", notes)
	}
}

func TestProtectedFolderVisibilityWithInheritedFileVisibility(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(filepath.Join(notesDir, "work"), 0o755); err != nil {
		t.Fatalf("mkdir notes/work: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	if err := os.WriteFile(filepath.Join(notesDir, "work", ".access.txt"), []byte("protected\n"), 0o644); err != nil {
		t.Fatalf("write .access.txt: %v", err)
	}

	inheritedContent := `---
id: inherited-protected
visibility: inherited
---
# Inherited Protected
`
	forcedPublicContent := `---
id: forced-public
visibility: public
---
# Forced Public
`
	forcedPrivateContent := `---
id: forced-private
visibility: private
---
# Forced Private
`

	if err := os.WriteFile(filepath.Join(notesDir, "work", "inherited.md"), []byte(inheritedContent), 0o644); err != nil {
		t.Fatalf("write inherited note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "work", "forced-public.md"), []byte(forcedPublicContent), 0o644); err != nil {
		t.Fatalf("write forced public note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "work", "forced-private.md"), []byte(forcedPrivateContent), 0o644); err != nil {
		t.Fatalf("write forced private note: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	accessFile, err := auth.LoadAccessFromRepo(repo)
	if err != nil {
		t.Fatalf("load access: %v", err)
	}
	if _, err := idx.SyncPathAccessWithStats(ctx, convertAccessRules(accessFile)); err != nil {
		t.Fatalf("sync access: %v", err)
	}
	if _, _, _, err := idx.RebuildFromFSWithStats(ctx, repo); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	publicCtx := WithPublicVisibility(ctx)
	exists, err := idx.NoteExists(publicCtx, "local/work/inherited.md")
	if err != nil {
		t.Fatalf("public note exists inherited: %v", err)
	}
	if exists {
		t.Fatalf("expected inherited protected note hidden from public users")
	}
	exists, err = idx.NoteExists(publicCtx, "local/work/forced-public.md")
	if err != nil {
		t.Fatalf("public note exists forced-public: %v", err)
	}
	if !exists {
		t.Fatalf("expected forced public note visible to public users")
	}

	viewerID, err := idx.EnsureUser(ctx, "viewer")
	if err != nil {
		t.Fatalf("ensure viewer: %v", err)
	}
	authCtx := WithAccessFilter(ctx, viewerID)
	exists, err = idx.NoteExists(authCtx, "local/work/inherited.md")
	if err != nil {
		t.Fatalf("auth note exists inherited: %v", err)
	}
	if !exists {
		t.Fatalf("expected inherited protected note visible to authenticated user")
	}
	exists, err = idx.NoteExists(authCtx, "local/work/forced-private.md")
	if err != nil {
		t.Fatalf("auth note exists forced-private: %v", err)
	}
	if exists {
		t.Fatalf("expected forced private note hidden from authenticated user without grants")
	}
}

func convertAccessRules(accessFile auth.AccessFile) map[string][]AccessPathRule {
	converted := make(map[string][]AccessPathRule, len(accessFile))
	for owner, rules := range accessFile {
		ownerRules := make([]AccessPathRule, 0, len(rules))
		for _, rule := range rules {
			members := make([]AccessMember, 0, len(rule.Members))
			for _, member := range rule.Members {
				members = append(members, AccessMember{
					User:   member.User,
					Access: member.Access,
				})
			}
			ownerRules = append(ownerRules, AccessPathRule{
				Path:       rule.Path,
				Visibility: rule.Visibility,
				Members:    members,
			})
		}
		converted[owner] = ownerRules
	}
	return converted
}
