package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/index"
)

func TestRenderMarkdownEmbeds(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes")
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

	now := time.Now()
	youtubeURL := "https://youtu.be/abc123"
	youtubeURL2 := "https://youtube.com/watch?v=def456"
	if !isYouTubeURL(youtubeURL) || !isYouTubeURL(youtubeURL2) {
		t.Fatalf("expected youtube urls to be recognized")
	}
	if err := idx.UpsertEmbedCache(ctx, index.EmbedCacheEntry{
		URL:       youtubeURL,
		Kind:      youtubeEmbedCacheKind,
		EmbedURL:  "https://img.youtube.com/vi/abc123/hqdefault.jpg",
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  "Example Video",
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert youtube cache: %v", err)
	}
	if err := idx.UpsertEmbedCache(ctx, index.EmbedCacheEntry{
		URL:       youtubeURL2,
		Kind:      youtubeEmbedCacheKind,
		EmbedURL:  "https://img.youtube.com/vi/def456/hqdefault.jpg",
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  "Example Video 2",
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert youtube cache 2: %v", err)
	}
	if status, _, _, _ := lookupYouTubeEmbed(ctx, youtubeURL2); status != youtubeEmbedStatusFound {
		t.Fatalf("expected youtube cache hit for second url")
	}

	mapsURL := "https://maps.app.goo.gl/abcdef"
	if err := idx.UpsertEmbedCache(ctx, index.EmbedCacheEntry{
		URL:       mapsURL,
		Kind:      mapsEmbedCacheKind,
		EmbedURL:  "https://www.google.com/maps?output=embed&q=Paris",
		Status:    index.EmbedCacheStatusFound,
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert maps cache: %v", err)
	}

	tiktokURL := "https://www.tiktok.com/@example/video/123456"
	if !isTikTokURL(tiktokURL) {
		t.Fatalf("expected tiktok url to be recognized")
	}
	if err := idx.UpsertEmbedCache(ctx, index.EmbedCacheEntry{
		URL:       tiktokURL,
		Kind:      tiktokEmbedCacheKind,
		EmbedURL:  "https://example.com/tiktok-thumb.jpg",
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  "Example TikTok",
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert tiktok cache: %v", err)
	}

	instagramURL := "https://www.instagram.com/reel/abc123/"
	instagramProfileURL := "https://www.instagram.com/jjs_kitchensolo/"
	if !isInstagramURL(instagramURL) {
		t.Fatalf("expected instagram reel url to be recognized")
	}
	if !isInstagramURL(instagramProfileURL) {
		t.Fatalf("expected instagram profile url to be recognized")
	}
	if err := idx.UpsertEmbedCache(ctx, index.EmbedCacheEntry{
		URL:       instagramURL,
		Kind:      instagramEmbedCacheKind,
		EmbedURL:  "https://example.com/instagram-thumb.jpg",
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  "Example Reel",
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert instagram cache: %v", err)
	}
	if err := idx.UpsertEmbedCache(ctx, index.EmbedCacheEntry{
		URL:       instagramProfileURL,
		Kind:      instagramEmbedCacheKind,
		EmbedURL:  "https://example.com/instagram-profile-thumb.jpg",
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  "Example Profile",
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert instagram profile cache: %v", err)
	}

	chatgptURL := "https://chatgpt.com/s/abc123"
	if !isChatGPTShareURL(chatgptURL) {
		t.Fatalf("expected chatgpt share url to be recognized")
	}
	if err := idx.UpsertEmbedCache(ctx, index.EmbedCacheEntry{
		URL:       chatgptURL,
		Kind:      chatgptEmbedCacheKind,
		EmbedURL:  "Example preview text",
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  "Example ChatGPT",
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert chatgpt cache: %v", err)
	}

	whatsappURL := "https://wa.me/628123456789"
	if _, ok := whatsAppNumber(whatsappURL); !ok {
		t.Fatalf("expected whatsapp url to be recognized")
	}

	html, err := srv.renderMarkdown(ctx, []byte(youtubeURL))
	if err != nil {
		t.Fatalf("render youtube: %v", err)
	}
	if !strings.Contains(html, `class="youtube-card"`) {
		t.Fatalf("expected youtube card, got %s", html)
	}
	if strings.Contains(html, "<p>") {
		t.Fatalf("expected youtube card to replace paragraph, got %s", html)
	}

	taskEmbed := "- [ ] " + youtubeURL + "\n"
	html, err = srv.renderMarkdown(ctx, []byte(taskEmbed))
	if err != nil {
		t.Fatalf("render task youtube: %v", err)
	}
	if !strings.Contains(html, `type="checkbox"`) {
		t.Fatalf("expected checkbox, got %s", html)
	}
	if !strings.Contains(html, `class="youtube-card"`) {
		t.Fatalf("expected youtube card for task, got %s", html)
	}

	inlineAfter := youtubeURL + " random text\n"
	html, err = srv.renderMarkdown(ctx, []byte(inlineAfter))
	if err != nil {
		t.Fatalf("render youtube inline text: %v", err)
	}
	if !strings.Contains(html, `class="youtube-card"`) {
		t.Fatalf("expected youtube card for inline text, got %s", html)
	}
	if !strings.Contains(html, "random text") {
		t.Fatalf("expected inline text to remain, got %s", html)
	}
	cardIndex := strings.Index(html, `class="youtube-card"`)
	textIndex := strings.Index(html, "random text")
	if cardIndex == -1 || textIndex == -1 || cardIndex > textIndex {
		t.Fatalf("expected inline text after embed card, got %s", html)
	}

	inlineBefore := "random text " + youtubeURL + "\n"
	html, err = srv.renderMarkdown(ctx, []byte(inlineBefore))
	if err != nil {
		t.Fatalf("render youtube inline text before: %v", err)
	}
	if !strings.Contains(html, `class="youtube-card"`) {
		t.Fatalf("expected youtube card for inline text before, got %s", html)
	}
	if !strings.Contains(html, "random text") {
		t.Fatalf("expected inline text to remain before embed, got %s", html)
	}
	cardIndex = strings.Index(html, `class="youtube-card"`)
	textIndex = strings.Index(html, "random text")
	if cardIndex == -1 || textIndex == -1 || textIndex > cardIndex {
		t.Fatalf("expected inline text before embed card, got %s", html)
	}

	html, err = srv.renderMarkdown(ctx, []byte(mapsURL))
	if err != nil {
		t.Fatalf("render maps: %v", err)
	}
	if !strings.Contains(html, "<iframe") {
		t.Fatalf("expected maps iframe, got %s", html)
	}
	if strings.Contains(html, "<p>") {
		t.Fatalf("expected maps embed to replace paragraph, got %s", html)
	}

	multi := youtubeURL + "\n\n" + youtubeURL2 + "\n\n" + tiktokURL + "\n\n" + instagramURL + "\n\n" + instagramProfileURL + "\n\n" + chatgptURL + "\n\n" + whatsappURL + "\n\n" + mapsURL + "\n"
	html, err = srv.renderMarkdown(ctx, []byte(multi))
	if err != nil {
		t.Fatalf("render multi: %v", err)
	}
	if count := strings.Count(html, `class="youtube-card"`); count != 2 {
		t.Fatalf("expected two youtube cards, got %d in %s", count, html)
	}
	if count := strings.Count(html, `class="tiktok-card"`); count != 1 {
		t.Fatalf("expected one tiktok card, got %d in %s", count, html)
	}
	if count := strings.Count(html, `class="instagram-card"`); count != 2 {
		t.Fatalf("expected two instagram cards, got %d in %s", count, html)
	}
	if count := strings.Count(html, `class="chatgpt-card"`); count != 1 {
		t.Fatalf("expected one chatgpt card, got %d in %s", count, html)
	}
	if count := strings.Count(html, `class="whatsapp-link"`); count != 1 {
		t.Fatalf("expected one whatsapp link, got %d in %s", count, html)
	}
	if count := strings.Count(html, "<iframe"); count != 1 {
		t.Fatalf("expected one map iframe, got %d in %s", count, html)
	}
}

func TestRenderMarkdownLinkTitleCache(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes")
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

	now := time.Now()
	linkURL := "https://example.com/demo"
	if err := idx.UpsertEmbedCache(ctx, index.EmbedCacheEntry{
		URL:       linkURL,
		Kind:      linkTitleCacheKind,
		EmbedURL:  "Example Domain",
		Status:    index.EmbedCacheStatusFound,
		UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert link title cache: %v", err)
	}

	html, err := srv.renderMarkdown(ctx, []byte(linkURL))
	if err != nil {
		t.Fatalf("render link: %v", err)
	}
	if !strings.Contains(html, ">Example Domain<") {
		t.Fatalf("expected link title to be used, got %s", html)
	}
	if strings.Contains(html, ">"+linkURL+"<") {
		t.Fatalf("expected raw url to be replaced, got %s", html)
	}

	html, err = srv.renderMarkdown(ctx, []byte("[Custom](https://example.com/demo)"))
	if err != nil {
		t.Fatalf("render custom label: %v", err)
	}
	if !strings.Contains(html, ">Custom<") {
		t.Fatalf("expected custom label to remain, got %s", html)
	}
	if strings.Contains(html, ">Example Domain<") {
		t.Fatalf("expected cached title to not override custom label, got %s", html)
	}
}

func TestIsIPHost(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"http://192.168.1.10", true},
		{"https://192.168.88.1:8443/path", true},
		{"http://[2001:db8::1]/", true},
		{"https://example.com", false},
		{"/notes/foo", false},
	}
	for _, tc := range cases {
		if got := isIPHost(tc.raw); got != tc.want {
			t.Fatalf("isIPHost(%q)=%v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestIsIgnoredLinkTitle(t *testing.T) {
	cases := []struct {
		title string
		want  bool
	}{
		{"Login - Sonarr", true},
		{"login", true},
		{"Sign In - Radarr", true},
		{"sign-in portal", true},
		{"Sign up", false},
		{"Dashboard", false},
	}
	for _, tc := range cases {
		if got := isIgnoredLinkTitle(tc.title); got != tc.want {
			t.Fatalf("isIgnoredLinkTitle(%q)=%v, want %v", tc.title, got, tc.want)
		}
	}
}

func TestRenderMarkdownCollapsedSections(t *testing.T) {
	repo := t.TempDir()
	notesDir := filepath.Join(repo, "notes")
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

	md := strings.Join([]string{
		"## Alpha",
		"Alpha body.",
		"",
		"## Beta",
		"Beta body.",
		"",
		"Tail.",
	}, "\n")

	collapsedAlpha := withCollapsibleSectionState(ctx, collapsibleSectionRenderState{
		NoteID: "note-1",
		Collapsed: map[int]struct{}{
			1: {},
		},
	})
	html, err := srv.renderMarkdown(collapsedAlpha, []byte(md))
	if err != nil {
		t.Fatalf("render markdown: %v", err)
	}
	if strings.Count(html, `class="note-section" open`) != 1 {
		t.Fatalf("expected one open section, got %s", html)
	}
	if !strings.Contains(html, `data-line-no="1"`) {
		t.Fatalf("expected alpha section to be marked, got %s", html)
	}

	collapsedBeta := withCollapsibleSectionState(ctx, collapsibleSectionRenderState{
		NoteID: "note-1",
		Collapsed: map[int]struct{}{
			4: {},
		},
	})
	html, err = srv.renderMarkdown(collapsedBeta, []byte(md))
	if err != nil {
		t.Fatalf("render markdown: %v", err)
	}
	if strings.Count(html, `class="note-section" open`) != 1 {
		t.Fatalf("expected one open section after beta collapse, got %s", html)
	}
	if !strings.Contains(html, `data-line-no="4"`) {
		t.Fatalf("expected beta section to be marked, got %s", html)
	}
}
