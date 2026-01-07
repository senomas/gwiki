package web

import (
	"context"
	"html"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	"gwiki/internal/index"
	"gwiki/internal/storage/fs"
)

var linkifyURLRegexp = regexp.MustCompile(`^(?:http|https|ftp)://(?:[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-z]+|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/#?][-a-zA-Z0-9@:%_+.~#$!?&/=\(\);,'">\^{}\[\]]*)?`)

var mdRenderer = goldmark.New(
	goldmark.WithExtensions(extension.NewLinkify(
		extension.WithLinkifyURLRegexp(linkifyURLRegexp),
	)),
	goldmark.WithExtensions(&linkTargetBlank{}),
	goldmark.WithExtensions(&mapsEmbedExtension{}),
)

type linkTargetBlank struct{}

func (e *linkTargetBlank) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&linkTargetBlankTransformer{}, 100),
	))
}

type linkTargetBlankTransformer struct{}

func (t *linkTargetBlankTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch link := n.(type) {
		case *ast.Link:
			if shouldOpenNewTab(link.Destination) {
				link.SetAttributeString("target", []byte("_blank"))
				link.SetAttributeString("rel", []byte("noopener noreferrer"))
			}
		case *ast.AutoLink:
			if link.AutoLinkType == ast.AutoLinkURL && shouldOpenNewTab(link.URL(reader.Source())) {
				link.SetAttributeString("target", []byte("_blank"))
				link.SetAttributeString("rel", []byte("noopener noreferrer"))
			}
		}
		return ast.WalkContinue, nil
	})
}

func shouldOpenNewTab(dest []byte) bool {
	s := strings.ToLower(strings.TrimSpace(string(dest)))
	if s == "" {
		return false
	}
	return strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "ftp://") ||
		strings.HasPrefix(s, "//")
}

const mapsAppShortLinkPrefix = "https://maps.app.goo.gl/"
const mapsAppShortLinkPrefixInsecure = "http://maps.app.goo.gl/"

var (
	mapsEmbedKind         = ast.NewNodeKind("MapsEmbed")
	mapsEmbedCoordsRegexp = regexp.MustCompile(`@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)`)
	mapsEmbedHTTPClient   = &http.Client{Timeout: 3 * time.Second}
	mapsEmbedCacheKind    = "maps"
)

const (
	mapsEmbedSuccessTTL  = 90 * 24 * time.Hour
	mapsEmbedFailureTTL  = 10 * time.Minute
	mapsEmbedPendingTTL  = 15 * time.Second
	mapsEmbedSyncTimeout = 1200 * time.Millisecond
)

var embedCacheStore *index.Index

var mapsEmbedInFlight = struct {
	mu   sync.Mutex
	data map[string]time.Time
}{
	data: map[string]time.Time{},
}

type mapsEmbedStatus int

const (
	mapsEmbedStatusPending mapsEmbedStatus = iota
	mapsEmbedStatusFound
	mapsEmbedStatusFailed
)

type mapsEmbed struct {
	ast.BaseBlock
	URL             string
	OriginalURL     string
	FallbackMessage string
}

func (n *mapsEmbed) Kind() ast.NodeKind {
	return mapsEmbedKind
}

func (n *mapsEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"URL":      n.URL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type mapsEmbedExtension struct{}

func (e *mapsEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&mapsEmbedTransformer{}, 110),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newMapsEmbedHTMLRenderer(), 500),
	))
}

type mapsEmbedTransformer struct{}

func (t *mapsEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	source := reader.Source()
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var url string
		switch link := n.(type) {
		case *ast.Link:
			url = string(link.Destination)
		case *ast.AutoLink:
			if link.AutoLinkType != ast.AutoLinkURL {
				return ast.WalkContinue, nil
			}
			url = string(link.URL(source))
		default:
			return ast.WalkContinue, nil
		}
		url = strings.TrimSpace(url)
		if !isMapsAppShortLink(url) {
			return ast.WalkContinue, nil
		}

		status, embedURL, errMsg := lookupMapsEmbed(url)
		switch status {
		case mapsEmbedStatusFound:
			embed := &mapsEmbed{URL: embedURL, OriginalURL: url}
			parent := n.Parent()
			if parent == nil {
				return ast.WalkContinue, nil
			}
			if para, ok := parent.(*ast.Paragraph); ok {
				grand := para.Parent()
				if grand == nil {
					return ast.WalkContinue, nil
				}
				if para.FirstChild() == n && para.LastChild() == n {
					grand.ReplaceChild(grand, para, embed)
					return ast.WalkContinue, nil
				}
				grand.InsertAfter(grand, para, embed)
				return ast.WalkContinue, nil
			}

			grand := parent.Parent()
			if grand != nil {
				grand.InsertAfter(grand, parent, embed)
			}
			return ast.WalkContinue, nil
		case mapsEmbedStatusFailed:
			embed := &mapsEmbed{
				OriginalURL:     url,
				FallbackMessage: errMsg,
			}
			parent := n.Parent()
			if parent == nil {
				return ast.WalkContinue, nil
			}
			if para, ok := parent.(*ast.Paragraph); ok {
				grand := para.Parent()
				if grand == nil {
					return ast.WalkContinue, nil
				}
				grand.InsertAfter(grand, para, embed)
				return ast.WalkContinue, nil
			}

			grand := parent.Parent()
			if grand != nil {
				grand.InsertAfter(grand, parent, embed)
			}
			return ast.WalkContinue, nil
		default:
			embed := &mapsEmbed{
				OriginalURL:     url,
				FallbackMessage: "Map preview loading. Reload to display the embed.",
			}
			parent := n.Parent()
			if parent == nil {
				return ast.WalkContinue, nil
			}
			if para, ok := parent.(*ast.Paragraph); ok {
				grand := para.Parent()
				if grand == nil {
					return ast.WalkContinue, nil
				}
				grand.InsertAfter(grand, para, embed)
				return ast.WalkContinue, nil
			}

			grand := parent.Parent()
			if grand != nil {
				grand.InsertAfter(grand, parent, embed)
			}
			return ast.WalkContinue, nil
		}
		return ast.WalkContinue, nil
	})
}

type mapsEmbedHTMLRenderer struct{}

func newMapsEmbedHTMLRenderer() renderer.NodeRenderer {
	return &mapsEmbedHTMLRenderer{}
}

func (r *mapsEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(mapsEmbedKind, r.renderMapsEmbed)
}

func (r *mapsEmbedHTMLRenderer) renderMapsEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*mapsEmbed)
	if n.URL != "" {
		escapedURL := html.EscapeString(n.URL)
		_, _ = w.WriteString(`<div class="map-embed">`)
		_, _ = w.WriteString(`<iframe src="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" loading="lazy" referrerpolicy="no-referrer-when-downgrade"`)
		_, _ = w.WriteString(` style="border:0;" width="100%" height="360" allowfullscreen></iframe>`)
		_, _ = w.WriteString(`</div>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="map-embed map-embed-fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open in Google Maps</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

func isMapsAppShortLink(url string) bool {
	lower := strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(lower, mapsAppShortLinkPrefix) ||
		strings.HasPrefix(lower, mapsAppShortLinkPrefixInsecure)
}

func lookupMapsEmbed(shortURL string) (mapsEmbedStatus, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(context.Background(), shortURL, mapsEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return mapsEmbedStatusFound, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "Map preview unavailable."
				}
				return mapsEmbedStatusFailed, "", message
			}
		}
	}

	if mapsEmbedIsInFlight(shortURL) {
		return mapsEmbedStatusPending, "", ""
	}
	mapsEmbedMarkInFlight(shortURL)

	if embedURL, ok := resolveMapsEmbedNow(shortURL, mapsEmbedSyncTimeout); ok {
		mapsEmbedStoreFound(shortURL, embedURL)
		mapsEmbedClearInFlight(shortURL)
		return mapsEmbedStatusFound, embedURL, ""
	}

	go resolveMapsEmbedAsync(shortURL)
	return mapsEmbedStatusPending, "", ""
}

func resolveMapsEmbedNow(shortURL string, timeout time.Duration) (string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveMapsEmbedWithClient(shortURL, client)
}

func resolveMapsEmbedAsync(shortURL string) {
	embedURL, ok := resolveMapsEmbedWithClient(shortURL, mapsEmbedHTTPClient)
	if !ok {
		mapsEmbedStoreFailure(shortURL, "Map preview unavailable.")
		mapsEmbedClearInFlight(shortURL)
		return
	}

	mapsEmbedStoreFound(shortURL, embedURL)
	mapsEmbedClearInFlight(shortURL)
}

func resolveMapsEmbedWithClient(shortURL string, client *http.Client) (string, bool) {
	req, err := http.NewRequest(http.MethodGet, shortURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	_ = resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if embedURL, ok := buildMapsEmbedURL(finalURL); ok {
		return embedURL, true
	}

	if linkValue := strings.TrimSpace(resp.Request.URL.Query().Get("link")); linkValue != "" {
		if decoded, err := url.QueryUnescape(linkValue); err == nil {
			if embedURL, ok := buildMapsEmbedURL(decoded); ok {
				return embedURL, true
			}
		}
	}

	return "", false
}

func mapsEmbedIsInFlight(shortURL string) bool {
	now := time.Now()
	mapsEmbedInFlight.mu.Lock()
	defer mapsEmbedInFlight.mu.Unlock()
	if until, ok := mapsEmbedInFlight.data[shortURL]; ok {
		if until.After(now) {
			return true
		}
		delete(mapsEmbedInFlight.data, shortURL)
	}
	return false
}

func mapsEmbedMarkInFlight(shortURL string) {
	mapsEmbedInFlight.mu.Lock()
	mapsEmbedInFlight.data[shortURL] = time.Now().Add(mapsEmbedPendingTTL)
	mapsEmbedInFlight.mu.Unlock()
}

func mapsEmbedClearInFlight(shortURL string) {
	mapsEmbedInFlight.mu.Lock()
	delete(mapsEmbedInFlight.data, shortURL)
	mapsEmbedInFlight.mu.Unlock()
}

func mapsEmbedStoreFound(shortURL, embedURL string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       shortURL,
		Kind:      mapsEmbedCacheKind,
		EmbedURL:  embedURL,
		Status:    index.EmbedCacheStatusFound,
		UpdatedAt: now,
		ExpiresAt: now.Add(mapsEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(context.Background(), entry)
}

func mapsEmbedStoreFailure(shortURL, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       shortURL,
		Kind:      mapsEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(mapsEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(context.Background(), entry)
}

func buildMapsEmbedURL(finalURL string) (string, bool) {
	parsed, err := url.Parse(finalURL)
	if err != nil || parsed.Host == "" {
		return "", false
	}

	if coords := mapsEmbedCoordsRegexp.FindStringSubmatch(finalURL); len(coords) == 3 {
		return mapsEmbedQueryURL(coords[1] + "," + coords[2]), true
	}

	queryValue := strings.TrimSpace(parsed.Query().Get("q"))
	if queryValue != "" {
		return mapsEmbedQueryURL(queryValue), true
	}

	if ll := strings.TrimSpace(parsed.Query().Get("ll")); ll != "" {
		return mapsEmbedQueryURL(ll), true
	}

	path := parsed.EscapedPath()
	if strings.HasPrefix(path, "/maps/place/") {
		trimmed := strings.TrimPrefix(path, "/maps/place/")
		segment := strings.SplitN(trimmed, "/", 2)[0]
		if segment != "" {
			if decoded, err := url.PathUnescape(segment); err == nil {
				segment = decoded
			}
			segment = strings.TrimSpace(segment)
			if segment != "" {
				return mapsEmbedQueryURL(segment), true
			}
		}
	}

	if strings.HasPrefix(path, "/maps/search/") {
		trimmed := strings.TrimPrefix(path, "/maps/search/")
		segment := strings.SplitN(trimmed, "/", 2)[0]
		if segment != "" {
			if decoded, err := url.PathUnescape(segment); err == nil {
				segment = decoded
			}
			segment = strings.TrimSpace(segment)
			if segment != "" {
				return mapsEmbedQueryURL(segment), true
			}
		}
	}

	return "", false
}

func mapsEmbedQueryURL(value string) string {
	return "https://www.google.com/maps?output=embed&q=" + url.QueryEscape(value)
}

const homeNotesPageSize = 6

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	tags, err := s.idx.ListTags(r.Context(), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	calendar := buildCalendarMonth(time.Now(), updateDays)
	homeNotes, nextOffset, hasMore, err := s.loadHomeNotes(r.Context(), 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{
		Title:           "Home",
		ContentTemplate: "home",
		HomeNotes:       homeNotes,
		HomeHasMore:     hasMore,
		NextHomeOffset:  nextOffset,
		Tags:            tags,
		UpdateDays:      updateDays,
		CalendarMonth:   calendar,
	}
	s.views.RenderPage(w, data)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	results, err := s.idx.Search(r.Context(), query, 50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{
		SearchQuery:   query,
		SearchResults: results,
	}
	if r.Header.Get("HX-Request") == "true" {
		s.views.RenderTemplate(w, "search_results", data)
		return
	}

	data.Title = "Search"
	data.ContentTemplate = "search_results"
	s.views.RenderPage(w, data)
}

func (s *Server) handleHomeNotesPage(w http.ResponseWriter, r *http.Request) {
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	homeNotes, nextOffset, hasMore, err := s.loadHomeNotes(r.Context(), offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{
		HomeNotes:      homeNotes,
		HomeHasMore:    hasMore,
		NextHomeOffset: nextOffset,
	}
	s.views.RenderTemplate(w, "home_notes", data)
}

func (s *Server) loadHomeNotes(ctx context.Context, offset int) ([]NoteCard, int, bool, error) {
	notes, err := s.idx.RecentNotesPage(ctx, homeNotesPageSize+1, offset)
	if err != nil {
		return nil, offset, false, err
	}
	hasMore := len(notes) > homeNotesPageSize
	if hasMore {
		notes = notes[:homeNotesPageSize]
	}
	cards := make([]NoteCard, 0, len(notes))
	for _, note := range notes {
		fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, note.Path)
		if err != nil {
			return nil, offset, false, err
		}
		content, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, offset, false, err
		}
		htmlStr, err := renderMarkdown(content)
		if err != nil {
			return nil, offset, false, err
		}
		label := note.MTime.Local().Format("Mon, Jan 2, 2006")
		cards = append(cards, NoteCard{
			Path:         note.Path,
			Title:        note.Title,
			RenderedHTML: template.HTML(htmlStr),
			UpdatedLabel: label,
		})
	}
	return cards, offset + len(notes), hasMore, nil
}

func (s *Server) handleNewNote(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := ViewData{Title: "New note", ContentTemplate: "new"}
		s.views.RenderPage(w, data)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	title := strings.TrimSpace(r.Form.Get("title"))
	if title == "" {
		http.Error(w, "title required", http.StatusBadRequest)
		return
	}

	slug := slugify(title)
	notePath, err := s.uniqueNotePath(slug)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	content := "# " + title + "\n\n"
	if err := fs.WriteFileAtomic(fullPath, []byte(content), 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info, err := os.Stat(fullPath)
	if err == nil {
		_ = s.idx.IndexNote(r.Context(), notePath, []byte(content), info.ModTime(), info.Size())
	}

	http.Redirect(w, r, "/notes/"+notePath+"/edit", http.StatusSeeOther)
}

func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	pathPart := strings.TrimPrefix(r.URL.Path, "/notes/")
	pathPart = strings.TrimSuffix(pathPart, "/")
	if pathPart == "" {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(pathPart, "/edit") {
		s.handleEditNote(w, r, strings.TrimSuffix(pathPart, "/edit"))
		return
	}
	if strings.HasSuffix(pathPart, "/save") {
		s.handleSaveNote(w, r, strings.TrimSuffix(pathPart, "/save"))
		return
	}
	if strings.HasSuffix(pathPart, "/preview") {
		s.handlePreview(w, r, strings.TrimSuffix(pathPart, "/preview"))
		return
	}

	s.handleViewNote(w, r, pathPart)
}

func (s *Server) handleViewNote(w http.ResponseWriter, r *http.Request, notePath string) {
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	meta := index.ParseContent(string(content))
	htmlStr, err := renderMarkdown(content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := ViewData{
		Title:           meta.Title,
		ContentTemplate: "view",
		NotePath:        notePath,
		NoteTitle:       meta.Title,
		RenderedHTML:    template.HTML(htmlStr),
	}
	s.views.RenderPage(w, data)
}

func (s *Server) handleEditNote(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	meta := index.ParseContent(string(content))
	data := ViewData{
		Title:           "Edit: " + meta.Title,
		ContentTemplate: "edit",
		NotePath:        notePath,
		NoteTitle:       meta.Title,
		RawContent:      string(content),
	}
	s.views.RenderPage(w, data)
}

func (s *Server) handleSaveNote(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	content := r.Form.Get("content")
	if content == "" {
		http.Error(w, "content required", http.StatusBadRequest)
		return
	}

	content, err := index.EnsureFrontmatter(content, time.Now(), s.cfg.UpdatedHistoryMax)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	unlock := s.locker.Lock(notePath)
	defer unlock()

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := fs.WriteFileAtomic(fullPath, []byte(content), 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info, err := os.Stat(fullPath)
	if err == nil {
		_ = s.idx.IndexNote(context.Background(), notePath, []byte(content), info.ModTime(), info.Size())
	}

	http.Redirect(w, r, "/notes/"+notePath, http.StatusSeeOther)
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	content := r.Form.Get("content")
	if content == "" {
		http.Error(w, "content required", http.StatusBadRequest)
		return
	}

	htmlStr, err := renderMarkdown([]byte(content))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := ViewData{RenderedHTML: template.HTML(htmlStr)}
	s.views.RenderTemplate(w, "note_content", data)
}

func renderMarkdown(data []byte) (string, error) {
	body := index.StripFrontmatter(string(data))
	var b strings.Builder
	if err := mdRenderer.Convert([]byte(body), &b); err != nil {
		return "", err
	}
	return b.String(), nil
}

func slugify(input string) string {
	input = strings.ToLower(input)
	var b strings.Builder
	lastDash := false
	for _, r := range input {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		slug = "note"
	}
	return slug
}

func (s *Server) uniqueNotePath(slug string) (string, error) {
	base := slug
	for i := 1; ; i++ {
		candidate := base
		if i > 1 {
			candidate = base + "-" + strconv.Itoa(i)
		}
		candidate = fs.EnsureMDExt(candidate)
		fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, candidate)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return candidate, nil
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
}
