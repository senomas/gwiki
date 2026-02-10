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
	videoAltRel := "clip-webm.webm"
	videoAltPath := filepath.Join(notesDir, "attachments", noteID, videoAltRel)
	if err := os.WriteFile(videoAltPath, []byte("fake-video"), 0o644); err != nil {
		t.Fatalf("write webm: %v", err)
	}
	thumbAltPath := filepath.Join(thumbDir, "clip-webm.jpg")
	if err := os.WriteFile(thumbAltPath, []byte("fake-thumb"), 0o644); err != nil {
		t.Fatalf("write webm thumb: %v", err)
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

	md = "![Demo video](/attachments/" + noteID + "/" + videoRel + ")"
	html, err = srv.renderMarkdown(ctx, []byte(md))
	if err != nil {
		t.Fatalf("render markdown image: %v", err)
	}
	if !strings.Contains(html, `class="video-card"`) {
		t.Fatalf("expected video card from image, got %s", html)
	}
	if !strings.Contains(html, "Demo video") {
		t.Fatalf("expected image alt title, got %s", html)
	}

	md = "![Demo video](attachments/" + noteID + "/" + videoRel + ")"
	html, err = srv.renderMarkdown(ctx, []byte(md))
	if err != nil {
		t.Fatalf("render markdown relative image: %v", err)
	}
	if !strings.Contains(html, `class="video-card"`) {
		t.Fatalf("expected video card from relative image, got %s", html)
	}

	md = "Before ![Demo video](/attachments/" + noteID + "/" + videoRel + ") after"
	html, err = srv.renderMarkdown(ctx, []byte(md))
	if err != nil {
		t.Fatalf("render markdown inline image: %v", err)
	}
	if !strings.Contains(html, `class="video-card"`) {
		t.Fatalf("expected video card from inline image, got %s", html)
	}
	if !strings.Contains(html, "Before") || !strings.Contains(html, "after") {
		t.Fatalf("expected inline text preserved, got %s", html)
	}

	md = "![WebM video](/attachments/" + noteID + "/" + videoAltRel + ")"
	html, err = srv.renderMarkdown(ctx, []byte(md))
	if err != nil {
		t.Fatalf("render markdown webm image: %v", err)
	}
	if !strings.Contains(html, `class="video-card"`) {
		t.Fatalf("expected video card from webm image, got %s", html)
	}
	if !strings.Contains(html, "/assets/"+noteID+"/clip-webm.jpg") {
		t.Fatalf("expected webm thumbnail url, got %s", html)
	}
}

func TestCleanupUnusedAttachments(t *testing.T) {
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

	noteID := "note-attach"
	attachmentsDir := filepath.Join(notesDir, "attachments", noteID)
	if err := os.MkdirAll(filepath.Join(attachmentsDir, "dir"), 0o755); err != nil {
		t.Fatalf("mkdir attachments: %v", err)
	}
	keep := filepath.Join(attachmentsDir, "keep.png")
	keepNested := filepath.Join(attachmentsDir, "dir", "keep2.png")
	remove := filepath.Join(attachmentsDir, "remove.png")
	for _, path := range []string{keep, keepNested, remove} {
		if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
			t.Fatalf("write attachment: %v", err)
		}
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

	content := strings.Join([]string{
		"![](/attachments/" + noteID + "/keep.png)",
		"![](/attachments/" + noteID + "/dir/keep2.png)",
		"",
	}, "\n")
	if err := srv.cleanupUnusedAttachments(context.Background(), owner, noteID, content); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("expected keep to remain: %v", err)
	}
	if _, err := os.Stat(keepNested); err != nil {
		t.Fatalf("expected keep nested to remain: %v", err)
	}
	if _, err := os.Stat(remove); err != nil {
		t.Fatalf("expected remove to remain (deferred cleanup), got err=%v", err)
	}
	expired, err := idx.ListExpiredFileCleanup(context.Background(), owner, time.Now().Add(48*time.Hour), 10)
	if err != nil {
		t.Fatalf("list cleanup: %v", err)
	}
	found := false
	for _, path := range expired {
		if strings.Contains(path, "remove.png") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected remove.png to be queued for cleanup, got %v", expired)
	}
}

func TestLocalizeAttachmentLinks(t *testing.T) {
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

	sourceID := "src-note"
	sourceRel := "image.png"
	sourcePath := filepath.Join(notesDir, "attachments", sourceID, sourceRel)
	if err := os.MkdirAll(filepath.Dir(sourcePath), 0o755); err != nil {
		t.Fatalf("mkdir source: %v", err)
	}
	if err := os.WriteFile(sourcePath, []byte("source-data"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	targetID := "target-note"
	frontmatter := strings.Join([]string{
		"---",
		"id: " + targetID,
		"title: Target",
		"---",
		"",
	}, "\n")
	content := "See ![](/attachments/" + sourceID + "/" + sourceRel + ")\n"

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

	noteCtx := WithUser(context.Background(), User{Name: owner, Authenticated: true})
	_, apiErr := srv.saveNoteCommon(noteCtx, saveNoteInput{
		NotePath:       filepath.ToSlash(filepath.Join(owner, "test.md")),
		TargetOwner:    owner,
		Content:        content,
		Frontmatter:    frontmatter,
		RenameDecision: "cancel",
	})
	if apiErr != nil {
		t.Fatalf("save note: %v", apiErr)
	}

	updatedPath := filepath.Join(notesDir, "test.md")
	raw, err := os.ReadFile(updatedPath)
	if err != nil {
		t.Fatalf("read note: %v", err)
	}
	if !strings.Contains(string(raw), "/attachments/"+targetID+"/"+sourceRel) {
		t.Fatalf("expected link to be localized, got:\n%s", string(raw))
	}
	copied := filepath.Join(notesDir, "attachments", targetID, sourceRel)
	if _, err := os.Stat(copied); err != nil {
		t.Fatalf("expected copied attachment, got err=%v", err)
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatalf("expected source to remain, got err=%v", err)
	}
}

func TestSaveNoteCrossOwnerOverwritesExistingAttachments(t *testing.T) {
	repo := t.TempDir()
	dataDir := filepath.Join(repo, ".wiki")
	sourceOwner := "seno"
	targetOwner := "healing"
	sourceNotesDir := filepath.Join(repo, sourceOwner, "notes")
	targetNotesDir := filepath.Join(repo, targetOwner, "notes")
	if err := os.MkdirAll(sourceNotesDir, 0o755); err != nil {
		t.Fatalf("mkdir source notes: %v", err)
	}
	if err := os.MkdirAll(targetNotesDir, 0o755); err != nil {
		t.Fatalf("mkdir target notes: %v", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}

	noteID := "976ff36c-c2e5-4e6f-a29f-3cc615951f35"
	noteRel := "moved-note.md"
	sourceNotePath := filepath.Join(sourceNotesDir, noteRel)
	sourceNoteContent := strings.Join([]string{
		"---",
		"id: " + noteID,
		"title: Moved Note",
		"visibility: public",
		"---",
		"",
		"# Moved Note",
		"",
		"![](/attachments/" + noteID + "/from-source.jpg)",
		"",
	}, "\n")
	if err := os.WriteFile(sourceNotePath, []byte(sourceNoteContent), 0o644); err != nil {
		t.Fatalf("write source note: %v", err)
	}

	sourceAttachDir := filepath.Join(sourceNotesDir, "attachments", noteID)
	if err := os.MkdirAll(sourceAttachDir, 0o755); err != nil {
		t.Fatalf("mkdir source attachments: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceAttachDir, "from-source.jpg"), []byte("source-new"), 0o644); err != nil {
		t.Fatalf("write source attachment: %v", err)
	}

	targetAttachDir := filepath.Join(targetNotesDir, "attachments", noteID)
	if err := os.MkdirAll(targetAttachDir, 0o755); err != nil {
		t.Fatalf("mkdir target attachments: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetAttachDir, "from-source.jpg"), []byte("target-old"), 0o644); err != nil {
		t.Fatalf("write target conflicting attachment: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetAttachDir, "old-only.jpg"), []byte("target-only"), 0o644); err != nil {
		t.Fatalf("write target attachment: %v", err)
	}

	accessFile := filepath.Join(targetNotesDir, ".access.txt")
	if err := os.WriteFile(accessFile, []byte(sourceOwner+":rw\n"), 0o644); err != nil {
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

	info, err := os.Stat(sourceNotePath)
	if err != nil {
		t.Fatalf("stat source note: %v", err)
	}
	sourceIndexPath := filepath.ToSlash(filepath.Join(sourceOwner, noteRel))
	if err := idx.IndexNote(ctx, sourceIndexPath, []byte(sourceNoteContent), info.ModTime(), info.Size()); err != nil {
		t.Fatalf("index source note: %v", err)
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
				Path:       rule.Path,
				Visibility: rule.Visibility,
				Members:    members,
			})
		}
		accessRules[ownerName] = converted
	}
	if _, err := idx.SyncPathAccessWithStats(ctx, accessRules); err != nil {
		t.Fatalf("sync access: %v", err)
	}

	cfg := config.Config{RepoPath: repo, DataPath: dataDir, ListenAddr: "127.0.0.1:0"}
	srv, err := NewServer(cfg, idx)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	noteCtx := WithUser(context.Background(), User{Name: sourceOwner, Authenticated: true})
	result, apiErr := srv.saveNoteCommon(noteCtx, saveNoteInput{
		NotePath:    sourceIndexPath,
		TargetOwner: targetOwner,
		Content: strings.Join([]string{
			"# Moved Note",
			"",
			"![](/attachments/" + noteID + "/from-source.jpg)",
			"",
		}, "\n"),
	})
	if apiErr != nil {
		t.Fatalf("save note returned api error: status=%d message=%s", apiErr.status, apiErr.message)
	}

	expectedTargetPath := filepath.ToSlash(filepath.Join(targetOwner, noteRel))
	if result.TargetPath != expectedTargetPath {
		t.Fatalf("unexpected target path: got %s want %s", result.TargetPath, expectedTargetPath)
	}

	if _, err := os.Stat(sourceNotePath); !os.IsNotExist(err) {
		t.Fatalf("expected source note removed, err=%v", err)
	}
	targetNotePath := filepath.Join(targetNotesDir, noteRel)
	if _, err := os.Stat(targetNotePath); err != nil {
		t.Fatalf("expected target note exists, err=%v", err)
	}
	if _, err := os.Stat(sourceAttachDir); !os.IsNotExist(err) {
		t.Fatalf("expected source attachment dir removed, err=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(targetAttachDir, "from-source.jpg"))
	if err != nil {
		t.Fatalf("read target attachment: %v", err)
	}
	if string(data) != "source-new" {
		t.Fatalf("expected overwritten attachment content, got %q", string(data))
	}
	if _, err := os.Stat(filepath.Join(targetAttachDir, "old-only.jpg")); !os.IsNotExist(err) {
		t.Fatalf("expected stale target attachment removed, err=%v", err)
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
	if err := os.WriteFile(authFile, []byte("alice:"+authHash+":2099-01-01\n"), 0o600); err != nil {
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
