package web

import (
	"context"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yuin/goldmark"

	"gwiki/internal/index"
	"gwiki/internal/storage/fs"
)

var mdRenderer = goldmark.New()

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	recent, err := s.idx.RecentNotes(r.Context(), 20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	data := ViewData{
		Title:           "Home",
		ContentTemplate: "home",
		RecentNotes:     recent,
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

	recent, err := s.idx.RecentNotes(r.Context(), 6)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tags, err := s.idx.ListTags(r.Context(), 30)
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

	data := ViewData{
		Title:           meta.Title,
		ContentTemplate: "view",
		NotePath:        notePath,
		NoteTitle:       meta.Title,
		RenderedHTML:    template.HTML(htmlStr),
		RecentNotes:     recent,
		Tags:            tags,
		UpdateDays:      updateDays,
		CalendarMonth:   calendar,
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
