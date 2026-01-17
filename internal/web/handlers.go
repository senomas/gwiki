package web

import (
	"bytes"
	"container/list"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
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

	"github.com/google/uuid"
)

var (
	linkifyURLRegexp = regexp.MustCompile(`^(?:http|https|ftp)://(?:[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-z]+|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/#?][-a-zA-Z0-9@:%_+.~#$!?&/=\(\);,'">\^{}\[\]]*)?`)
	journalFolderRE  = regexp.MustCompile(`^\d{4}-\d{2}$`)
	journalNoteRE    = regexp.MustCompile(`^\d{4}-\d{2}/\d{2}\.md$`)
	wikiLinkRe       = regexp.MustCompile(`\[\[([^\]]+)\]\]`)
	taskCheckboxRe   = regexp.MustCompile(`(?i)<input\b[^>]*type="checkbox"[^>]*>`)
	taskToggleLineRe = regexp.MustCompile(`^(\s*- \[)( |x|X)(\] .+)$`)
)

var mdRenderer = goldmark.New(
	goldmark.WithExtensions(extension.NewLinkify(
		extension.WithLinkifyURLRegexp(linkifyURLRegexp),
	)),
	goldmark.WithExtensions(&linkTargetBlank{}),
	goldmark.WithExtensions(&collapsibleSectionExtension{}),
	goldmark.WithExtensions(&mapsEmbedExtension{}),
	goldmark.WithExtensions(&youtubeEmbedExtension{}),
	goldmark.WithExtensions(&tiktokEmbedExtension{}),
	goldmark.WithExtensions(&instagramEmbedExtension{}),
	goldmark.WithExtensions(&attachmentVideoEmbedExtension{}),
	goldmark.WithExtensions(extension.TaskList),
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

func (s *Server) attachViewData(r *http.Request, data *ViewData) {
	data.AuthEnabled = s.auth != nil
	if user, ok := CurrentUser(r.Context()); ok {
		data.CurrentUser = user
		data.IsAuthenticated = user.Authenticated
	}
}

func historyUser(ctx context.Context) string {
	if user, ok := CurrentUser(ctx); ok {
		if name := strings.TrimSpace(user.Name); name != "" {
			return name
		}
	}
	return "system"
}

type collapsibleSectionRenderState struct {
	NoteID    string
	Collapsed map[int]struct{}
	Lines     map[string]struct{}
}

type collapsibleSectionStateKey struct{}

func withCollapsibleSectionState(ctx context.Context, state collapsibleSectionRenderState) context.Context {
	return context.WithValue(ctx, collapsibleSectionStateKey{}, state)
}

func collapsibleSectionStateFromContext(ctx context.Context) (collapsibleSectionRenderState, bool) {
	value := ctx.Value(collapsibleSectionStateKey{})
	state, ok := value.(collapsibleSectionRenderState)
	return state, ok
}

func (s *Server) collapsedSectionState(ctx context.Context, noteID string) (collapsibleSectionRenderState, bool, error) {
	if strings.TrimSpace(noteID) == "" {
		return collapsibleSectionRenderState{}, false, nil
	}
	sections, err := s.idx.CollapsedSections(ctx, noteID)
	if err != nil {
		return collapsibleSectionRenderState{}, false, err
	}
	return collapsedSectionStateFromSections(noteID, sections)
}

func collapsedSectionStateFromSections(noteID string, sections []index.CollapsedSection) (collapsibleSectionRenderState, bool, error) {
	if len(sections) == 0 {
		return collapsibleSectionRenderState{}, false, nil
	}
	collapsed := make(map[int]struct{}, len(sections))
	lines := make(map[string]struct{}, len(sections))
	for _, section := range sections {
		if section.LineNo <= 0 {
			continue
		}
		collapsed[section.LineNo] = struct{}{}
		if line := strings.TrimSpace(section.Line); line != "" {
			lines[line] = struct{}{}
		}
	}
	if len(collapsed) == 0 && len(lines) == 0 {
		return collapsibleSectionRenderState{}, false, nil
	}
	return collapsibleSectionRenderState{
		NoteID:    noteID,
		Collapsed: collapsed,
		Lines:     lines,
	}, true, nil
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.auth == nil {
		return true
	}
	if IsAuthenticated(r.Context()) {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="gwiki"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	return false
}

func normalizeLineEndings(input string) string {
	normalized := strings.ReplaceAll(input, "\r\n", "\n")
	return strings.ReplaceAll(normalized, "\r", "\n")
}

func normalizeFolderPath(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil
	}
	if strings.ContainsRune(input, 0) {
		return "", fs.ErrUnsafePath
	}
	input = strings.ReplaceAll(input, "\\", "/")
	if strings.HasPrefix(input, "/") {
		return "", fs.ErrUnsafePath
	}
	clean := path.Clean(input)
	if clean == "." {
		return "", nil
	}
	if strings.HasPrefix(clean, "..") {
		return "", fs.ErrUnsafePath
	}
	return clean, nil
}

func isJournalNotePath(notePath string) bool {
	return journalNoteRE.MatchString(strings.TrimPrefix(notePath, "/"))
}

func listAttachmentNames(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *Server) attachmentsRoot() string {
	return filepath.Join(s.cfg.RepoPath, "notes", "attachments")
}

func (s *Server) tempAttachmentsDir(token string) string {
	return filepath.Join(s.attachmentsRoot(), ".tmp", token)
}

func (s *Server) noteAttachmentsDir(noteID string) string {
	return filepath.Join(s.attachmentsRoot(), noteID)
}

func (s *Server) assetsRoot() string {
	if s.cfg.DataPath == "" {
		return ""
	}
	return filepath.Join(s.cfg.DataPath, "assets")
}

func parseTagsParam(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		if strings.EqualFold(tag, "todo") {
			tag = "TODO"
		} else if strings.EqualFold(tag, "due") {
			tag = "DUE"
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out
}

func parseFolderParam(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.EqualFold(raw, "root") {
		return "", true
	}
	folder, err := normalizeFolderPath(raw)
	if err != nil {
		return "", false
	}
	return folder, false
}

func parseDateParam(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if _, err := time.Parse("2006-01-02", raw); err != nil {
		return ""
	}
	return raw
}

func splitSpecialTags(tags []string) (bool, bool, []string) {
	out := make([]string, 0, len(tags))
	hasTodo := false
	hasDue := false
	for _, tag := range tags {
		switch {
		case strings.EqualFold(tag, "todo"):
			hasTodo = true
		case strings.EqualFold(tag, "due"):
			hasDue = true
		default:
			out = append(out, tag)
		}
	}
	return hasTodo, hasDue, out
}

const taskIDPrefix = "task-"

func taskCheckboxID(fileID, lineNo int, hash string) string {
	return fmt.Sprintf("%s%d-%d-%s", taskIDPrefix, fileID, lineNo, hash)
}

func taskCheckboxHTML(fileID, lineNo int, hash string, checked bool) string {
	id := html.EscapeString(taskCheckboxID(fileID, lineNo, hash))
	checkedAttr := ""
	if checked {
		checkedAttr = " checked"
	}
	return fmt.Sprintf(
		`<input type="checkbox"%s data-task-id="%s" id="%s" hx-post="/tasks/toggle" hx-trigger="change" hx-swap="outerHTML" hx-vals='{"task_id":"%s"}'>`,
		checkedAttr,
		id,
		id,
		id,
	)
}

func parseTaskID(raw string) (int, int, string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, taskIDPrefix) {
		return 0, 0, "", fmt.Errorf("invalid task id")
	}
	parts := strings.Split(strings.TrimPrefix(raw, taskIDPrefix), "-")
	if len(parts) < 3 {
		return 0, 0, "", fmt.Errorf("invalid task id")
	}
	fileID, err := strconv.Atoi(parts[0])
	if err != nil || fileID <= 0 {
		return 0, 0, "", fmt.Errorf("invalid task id")
	}
	lineNo, err := strconv.Atoi(parts[1])
	if err != nil || lineNo <= 0 {
		return 0, 0, "", fmt.Errorf("invalid task id")
	}
	hash := strings.Join(parts[2:], "-")
	if len(hash) != 64 {
		return 0, 0, "", fmt.Errorf("invalid task id")
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return 0, 0, "", fmt.Errorf("invalid task id")
	}
	return fileID, lineNo, hash, nil
}

func decorateTaskCheckboxes(htmlStr string, fileID int, tasks []index.Task) string {
	if fileID <= 0 || len(tasks) == 0 {
		return htmlStr
	}
	idx := 0
	return taskCheckboxRe.ReplaceAllStringFunc(htmlStr, func(tag string) string {
		if idx >= len(tasks) {
			return tag
		}
		task := tasks[idx]
		idx++
		return taskCheckboxHTML(fileID, task.LineNo, task.Hash, task.Done)
	})
}

func buildTagLinks(active []string, tags []index.TagSummary, allowed map[string]struct{}, basePath string, todoCount int, dueCount int, activeDate string, activeSearch string, includeSpecial bool, activeFolder string, activeRoot bool) []TagLink {
	activeSet := map[string]struct{}{}
	activeList := make([]string, 0, len(active))
	for _, tag := range active {
		activeSet[tag] = struct{}{}
		activeList = append(activeList, tag)
	}
	links := make([]TagLink, 0, len(tags)+2)
	if includeSpecial {
		links = append(links, buildDueTagLink(activeList, activeSet, allowed, basePath, dueCount, activeDate, activeSearch, activeFolder, activeRoot))
		links = append(links, buildTodoTagLink(activeList, activeSet, allowed, basePath, todoCount, activeDate, activeSearch, activeFolder, activeRoot))
	}
	for _, tag := range tags {
		_, isActive := activeSet[tag.Name]
		disabled := false
		if len(active) > 0 && !isActive && allowed != nil {
			if _, ok := allowed[tag.Name]; !ok {
				disabled = true
			}
		}
		next := make([]string, 0, len(activeList)+1)
		if isActive {
			for _, item := range activeList {
				if item != tag.Name {
					next = append(next, item)
				}
			}
		} else {
			next = append(next, activeList...)
			next = append(next, tag.Name)
		}
		url := ""
		if !disabled {
			url = buildTagsURL(basePath, next, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot))
		}
		links = append(links, TagLink{
			Name:     tag.Name,
			Count:    tag.Count,
			URL:      url,
			Active:   isActive,
			Disabled: disabled,
		})
	}
	return links
}

func buildTagsQuery(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	escaped := make([]string, 0, len(tags))
	for _, tag := range tags {
		escaped = append(escaped, url.QueryEscape(tag))
	}
	return strings.Join(escaped, ",")
}

func buildDateQuery(date string) string {
	if date == "" {
		return ""
	}
	return url.QueryEscape(date)
}

func buildSearchQuery(query string) string {
	if query == "" {
		return ""
	}
	return url.QueryEscape(query)
}

func buildTagsURL(basePath string, tags []string, activeDate string, activeSearch string, folderQuery string) string {
	if basePath == "" {
		basePath = "/"
	}
	params := make([]string, 0, 2)
	if tagQuery := buildTagsQuery(tags); tagQuery != "" {
		params = append(params, "t="+tagQuery)
	}
	if folderQuery != "" {
		params = append(params, "f="+url.QueryEscape(folderQuery))
	}
	if activeDate != "" {
		params = append(params, "d="+url.QueryEscape(activeDate))
	}
	if activeSearch != "" {
		params = append(params, "s="+url.QueryEscape(activeSearch))
	}
	if len(params) == 0 {
		return basePath
	}
	return basePath + "?" + strings.Join(params, "&")
}

func buildFolderQuery(folder string, rootOnly bool) string {
	if rootOnly {
		return "root"
	}
	return strings.TrimSpace(folder)
}

func buildFolderURL(basePath string, folder string, rootOnly bool, activeTags []string, activeDate string, activeSearch string) string {
	if basePath == "" {
		basePath = "/"
	}
	params := make([]string, 0, 3)
	if tagQuery := buildTagsQuery(activeTags); tagQuery != "" {
		params = append(params, "t="+tagQuery)
	}
	if folderQuery := buildFolderQuery(folder, rootOnly); folderQuery != "" {
		params = append(params, "f="+url.QueryEscape(folderQuery))
	}
	if activeDate != "" {
		params = append(params, "d="+url.QueryEscape(activeDate))
	}
	if activeSearch != "" {
		params = append(params, "s="+url.QueryEscape(activeSearch))
	}
	if len(params) == 0 {
		return basePath
	}
	return basePath + "?" + strings.Join(params, "&")
}

func buildFilterQuery(activeTags []string, activeDate string, activeSearch string, activeFolder string, activeRoot bool) string {
	params := make([]string, 0, 4)
	if tagQuery := buildTagsQuery(activeTags); tagQuery != "" {
		params = append(params, "t="+tagQuery)
	}
	if folderQuery := buildFolderQuery(activeFolder, activeRoot); folderQuery != "" {
		params = append(params, "f="+url.QueryEscape(folderQuery))
	}
	if activeDate != "" {
		params = append(params, "d="+url.QueryEscape(activeDate))
	}
	if activeSearch != "" {
		params = append(params, "s="+url.QueryEscape(activeSearch))
	}
	return strings.Join(params, "&")
}

func (s *Server) folderOptions(ctx context.Context) []string {
	folders, _, err := s.idx.ListFolders(ctx)
	if err != nil {
		return nil
	}
	return folders
}

type folderNode struct {
	Name     string
	Path     string
	URL      string
	Active   bool
	Children []*folderNode
}

func buildFolderTree(folders []string, hasRoot bool, activeFolder string, activeRoot bool, basePath string, activeTags []string, activeDate string, activeSearch string) []FolderNode {
	filtered := make([]string, 0, len(folders))
	for _, folder := range folders {
		if journalFolderRE.MatchString(folder) {
			continue
		}
		filtered = append(filtered, folder)
	}
	if !hasRoot && len(filtered) == 0 {
		return nil
	}
	allURL := buildFolderURL(basePath, "", false, activeTags, activeDate, activeSearch)
	rootURL := buildFolderURL(basePath, "", true, activeTags, activeDate, activeSearch)
	if activeRoot {
		rootURL = allURL
	}
	root := &folderNode{
		Name:   "Root",
		Path:   "root",
		URL:    rootURL,
		Active: activeRoot,
	}

	nodes := map[string]*folderNode{}
	for _, folder := range filtered {
		nodes[folder] = &folderNode{
			Name: path.Base(folder),
			Path: folder,
		}
	}

	for _, folder := range filtered {
		parent := path.Dir(folder)
		if parent == "." {
			parent = ""
		}
		if parent == "" {
			root.Children = append(root.Children, nodes[folder])
			continue
		}
		parentNode, ok := nodes[parent]
		if !ok {
			parentNode = &folderNode{Name: path.Base(parent), Path: parent}
			nodes[parent] = parentNode
			root.Children = append(root.Children, parentNode)
		}
		parentNode.Children = append(parentNode.Children, nodes[folder])
	}

	var assign func(node *folderNode)
	assign = func(node *folderNode) {
		if node.Path != "root" && node.Path != "" {
			node.URL = buildFolderURL(basePath, node.Path, false, activeTags, activeDate, activeSearch)
			if !activeRoot && strings.EqualFold(activeFolder, node.Path) {
				node.Active = true
				node.URL = allURL
			}
		}
		for _, child := range node.Children {
			assign(child)
		}
	}
	assign(root)

	var materialize func(node *folderNode) FolderNode
	materialize = func(node *folderNode) FolderNode {
		out := FolderNode{
			Name:   node.Name,
			Path:   node.Path,
			URL:    node.URL,
			Active: node.Active,
		}
		if len(node.Children) > 0 {
			out.Children = make([]FolderNode, 0, len(node.Children))
			for _, child := range node.Children {
				out.Children = append(out.Children, materialize(child))
			}
		}
		return out
	}
	if len(root.Children) == 0 {
		return nil
	}
	out := make([]FolderNode, 0, len(root.Children))
	for _, child := range root.Children {
		out = append(out, materialize(child))
	}
	return out
}

func buildDueTagLink(activeList []string, activeSet map[string]struct{}, allowed map[string]struct{}, basePath string, count int, activeDate string, activeSearch string, activeFolder string, activeRoot bool) TagLink {
	const name = "DUE"
	_, isActive := activeSet[name]
	disabled := false
	if len(activeList) > 0 && !isActive && allowed != nil {
		if _, ok := allowed[name]; !ok {
			disabled = true
		}
	}
	next := make([]string, 0, len(activeList)+1)
	if isActive {
		for _, tag := range activeList {
			if tag != name {
				next = append(next, tag)
			}
		}
	} else {
		next = append(next, activeList...)
		next = append(next, name)
	}
	url := ""
	if !disabled {
		url = buildTagsURL(basePath, next, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot))
	}
	return TagLink{
		Name:     name,
		Count:    count,
		URL:      url,
		Active:   isActive,
		Disabled: disabled,
	}
}

func (s *Server) loadSpecialTagCounts(r *http.Request, noteTags []string, activeTodo bool, activeDue bool, activeDate string, folder string, rootOnly bool) (int, int, error) {
	todoCount := 0
	dueCount := 0
	dueDate := time.Now().Format("2006-01-02")

	if activeDate != "" {
		if activeTodo || len(noteTags) > 0 {
			count, err := s.idx.CountNotesWithOpenTasksByDate(r.Context(), noteTags, activeDate, folder, rootOnly)
			if err != nil {
				return 0, 0, err
			}
			todoCount = count
		} else {
			count, err := s.idx.CountNotesWithOpenTasksByDate(r.Context(), nil, activeDate, folder, rootOnly)
			if err != nil {
				return 0, 0, err
			}
			todoCount = count
		}
	} else if activeTodo || len(noteTags) > 0 {
		count, err := s.idx.CountNotesWithOpenTasks(r.Context(), noteTags, folder, rootOnly)
		if err != nil {
			return 0, 0, err
		}
		todoCount = count
	} else {
		count, err := s.idx.CountNotesWithOpenTasks(r.Context(), nil, folder, rootOnly)
		if err != nil {
			return 0, 0, err
		}
		todoCount = count
	}

	if activeDate != "" {
		if activeDue || len(noteTags) > 0 {
			count, err := s.idx.CountNotesWithDueTasksByDate(r.Context(), noteTags, activeDate, dueDate, folder, rootOnly)
			if err != nil {
				return 0, 0, err
			}
			dueCount = count
		} else {
			count, err := s.idx.CountNotesWithDueTasksByDate(r.Context(), nil, activeDate, dueDate, folder, rootOnly)
			if err != nil {
				return 0, 0, err
			}
			dueCount = count
		}
	} else if activeDue || len(noteTags) > 0 {
		count, err := s.idx.CountNotesWithDueTasks(r.Context(), noteTags, dueDate, folder, rootOnly)
		if err != nil {
			return 0, 0, err
		}
		dueCount = count
	} else {
		count, err := s.idx.CountNotesWithDueTasks(r.Context(), nil, dueDate, folder, rootOnly)
		if err != nil {
			return 0, 0, err
		}
		dueCount = count
	}

	return todoCount, dueCount, nil
}

func (s *Server) loadFilteredTags(r *http.Request, noteTags []string, activeTodo bool, activeDue bool, activeDate string, folder string, rootOnly bool) ([]index.TagSummary, error) {
	dueDate := time.Now().Format("2006-01-02")
	if activeDate != "" {
		if activeDue {
			return s.idx.ListTagsWithDueTasksByDate(r.Context(), noteTags, activeDate, dueDate, 100, folder, rootOnly)
		}
		if activeTodo {
			return s.idx.ListTagsWithOpenTasksByDate(r.Context(), noteTags, activeDate, 100, folder, rootOnly)
		}
		return s.idx.ListTagsFilteredByDate(r.Context(), noteTags, activeDate, 100, folder, rootOnly)
	}
	if activeDue {
		return s.idx.ListTagsWithDueTasks(r.Context(), noteTags, dueDate, 100, folder, rootOnly)
	}
	if activeTodo {
		return s.idx.ListTagsWithOpenTasks(r.Context(), noteTags, 100, folder, rootOnly)
	}
	return s.idx.ListTagsFiltered(r.Context(), noteTags, 100, folder, rootOnly)
}

func buildTodoTagLink(activeList []string, activeSet map[string]struct{}, allowed map[string]struct{}, basePath string, count int, activeDate string, activeSearch string, activeFolder string, activeRoot bool) TagLink {
	const name = "TODO"
	_, isActive := activeSet[name]
	disabled := false
	if len(activeList) > 0 && !isActive && allowed != nil {
		if _, ok := allowed[name]; !ok {
			disabled = true
		}
	}
	next := make([]string, 0, len(activeList)+1)
	if isActive {
		for _, tag := range activeList {
			if tag != name {
				next = append(next, tag)
			}
		}
	} else {
		next = append(next, activeList...)
		next = append(next, name)
	}
	url := ""
	if !disabled {
		url = buildTagsURL(basePath, next, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot))
	}
	return TagLink{
		Name:     name,
		Count:    count,
		URL:      url,
		Active:   isActive,
		Disabled: disabled,
	}
}

const mapsAppShortLinkPrefix = "https://maps.app.goo.gl/"
const mapsAppShortLinkPrefixInsecure = "http://maps.app.goo.gl/"

var (
	mapsEmbedKind         = ast.NewNodeKind("MapsEmbed")
	mapsEmbedCoordsRegexp = regexp.MustCompile(`@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)`)
	mapsEmbedHTTPClient   = &http.Client{Timeout: 3 * time.Second}
	mapsEmbedCacheKind    = "maps"
	mapsEmbedContextKey   = parser.NewContextKey()
)

const (
	mapsEmbedSuccessTTL  = 90 * 24 * time.Hour
	mapsEmbedFailureTTL  = 10 * time.Minute
	mapsEmbedPendingTTL  = 15 * time.Second
	mapsEmbedSyncTimeout = 1200 * time.Millisecond
)

var embedCacheStore *index.Index

var mapsEmbedInFlight = newTTLCache(512)

var (
	collapsibleSectionKind       = ast.NewNodeKind("CollapsibleSection")
	collapsibleSectionContextKey = parser.NewContextKey()
)

var (
	youtubeEmbedKind       = ast.NewNodeKind("YouTubeEmbed")
	youtubeEmbedHTTPClient = &http.Client{Timeout: 3 * time.Second}
	youtubeEmbedCacheKind  = "youtube"
	youtubeEmbedContextKey = parser.NewContextKey()
)

const (
	youtubeEmbedSuccessTTL  = 7 * 24 * time.Hour
	youtubeEmbedFailureTTL  = 30 * time.Minute
	youtubeEmbedPendingTTL  = 20 * time.Second
	youtubeEmbedSyncTimeout = 1200 * time.Millisecond
)

var youtubeEmbedInFlight = newTTLCache(512)

var (
	tiktokEmbedKind       = ast.NewNodeKind("TikTokEmbed")
	tiktokEmbedHTTPClient = &http.Client{Timeout: 3 * time.Second}
	tiktokEmbedCacheKind  = "tiktok"
	tiktokEmbedContextKey = parser.NewContextKey()
)

const (
	tiktokEmbedSuccessTTL  = 7 * 24 * time.Hour
	tiktokEmbedFailureTTL  = 30 * time.Minute
	tiktokEmbedPendingTTL  = 20 * time.Second
	tiktokEmbedSyncTimeout = 1200 * time.Millisecond
)

var tiktokEmbedInFlight = newTTLCache(512)

var (
	instagramEmbedKind       = ast.NewNodeKind("InstagramEmbed")
	instagramEmbedHTTPClient = &http.Client{Timeout: 3 * time.Second}
	instagramEmbedCacheKind  = "instagram"
	instagramEmbedContextKey = parser.NewContextKey()
)

const (
	instagramEmbedSuccessTTL  = 7 * 24 * time.Hour
	instagramEmbedFailureTTL  = 30 * time.Minute
	instagramEmbedPendingTTL  = 20 * time.Second
	instagramEmbedSyncTimeout = 1200 * time.Millisecond
)

var instagramEmbedInFlight = newTTLCache(512)

var (
	attachmentVideoEmbedKind       = ast.NewNodeKind("AttachmentVideoEmbed")
	attachmentVideoEmbedContextKey = parser.NewContextKey()
)

type mapsEmbedStatus int

const (
	mapsEmbedStatusPending mapsEmbedStatus = iota
	mapsEmbedStatusFound
	mapsEmbedStatusFailed
)

type youtubeEmbedStatus int

const (
	youtubeEmbedStatusPending youtubeEmbedStatus = iota
	youtubeEmbedStatusFound
	youtubeEmbedStatusFailed
)

type tiktokEmbedStatus int

const (
	tiktokEmbedStatusPending tiktokEmbedStatus = iota
	tiktokEmbedStatusFound
	tiktokEmbedStatusFailed
)

type instagramEmbedStatus int

const (
	instagramEmbedStatusPending instagramEmbedStatus = iota
	instagramEmbedStatusFound
	instagramEmbedStatusFailed
)

type collapsibleSection struct {
	ast.BaseBlock
	Title    string
	LineNo   int
	LineText string
	Open     bool
}

func (n *collapsibleSection) Kind() ast.NodeKind {
	return collapsibleSectionKind
}

func (n *collapsibleSection) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":  n.Title,
		"LineNo": strconv.Itoa(n.LineNo),
	}, nil)
}

type collapsibleSectionExtension struct{}

func (e *collapsibleSectionExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&collapsibleSectionTransformer{}, 105),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newCollapsibleSectionHTMLRenderer(), 480),
	))
}

type collapsibleSectionTransformer struct{}

func (t *collapsibleSectionTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	source := reader.Source()
	state := collapsibleSectionRenderState{}
	if value := pc.Get(collapsibleSectionContextKey); value != nil {
		if resolved, ok := value.(collapsibleSectionRenderState); ok {
			state = resolved
		}
	}
	for current := node.FirstChild(); current != nil; {
		next := current.NextSibling()
		heading, ok := current.(*ast.Heading)
		if !ok || heading.Level != 2 || heading.Parent() != node {
			current = next
			continue
		}
		title := headingPlainText(heading, source)
		if strings.TrimSpace(title) == "" {
			title = "Section"
		}
		lineNo, lineText := headingLineInfo(heading, source)
		normalizedLine := strings.TrimSpace(lineText)
		open := true
		if lineNo > 0 && state.Collapsed != nil {
			if _, ok := state.Collapsed[lineNo]; ok {
				open = false
			}
		}
		if open && normalizedLine != "" && state.Lines != nil {
			if _, ok := state.Lines[normalizedLine]; ok {
				open = false
			}
		}
		section := &collapsibleSection{
			Title:    title,
			LineNo:   lineNo,
			LineText: normalizedLine,
			Open:     open,
		}
		node.ReplaceChild(node, current, section)
		for child := next; child != nil; {
			childNext := child.NextSibling()
			if h2, ok := child.(*ast.Heading); ok && h2.Level == 2 && h2.Parent() == node {
				break
			}
			node.RemoveChild(node, child)
			section.AppendChild(section, child)
			child = childNext
		}
		current = section.NextSibling()
	}
}

func headingPlainText(node *ast.Heading, source []byte) string {
	var b strings.Builder
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch v := n.(type) {
		case *ast.Text:
			b.Write(v.Segment.Value(source))
		case *ast.String:
			b.Write(v.Text(source))
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(b.String())
}

func headingLineInfo(node *ast.Heading, source []byte) (int, string) {
	lines := node.Lines()
	if lines == nil || lines.Len() == 0 {
		return 0, ""
	}
	segment := lines.At(0)
	if segment.Start < 0 || segment.Start > len(source) {
		return 0, ""
	}
	lineStart := bytes.LastIndex(source[:segment.Start], []byte("\n")) + 1
	lineEnd := len(source)
	if nextBreak := bytes.Index(source[segment.Start:], []byte("\n")); nextBreak >= 0 {
		lineEnd = segment.Start + nextBreak
	}
	lineNo := bytes.Count(source[:lineStart], []byte("\n")) + 1
	lineText := strings.TrimSpace(string(source[lineStart:lineEnd]))
	return lineNo, lineText
}

type collapsibleSectionHTMLRenderer struct{}

func newCollapsibleSectionHTMLRenderer() renderer.NodeRenderer {
	return &collapsibleSectionHTMLRenderer{}
}

func (r *collapsibleSectionHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(collapsibleSectionKind, r.renderCollapsibleSection)
}

func (r *collapsibleSectionHTMLRenderer) renderCollapsibleSection(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if entering {
		section := node.(*collapsibleSection)
		title := html.EscapeString(section.Title)
		_, _ = w.WriteString(`<details class="note-section"`)
		if section.Open {
			_, _ = w.WriteString(` open`)
		}
		if section.LineNo > 0 {
			_, _ = w.WriteString(` data-line-no="`)
			_, _ = w.WriteString(strconv.Itoa(section.LineNo))
			_, _ = w.WriteString(`"`)
		}
		if section.LineText != "" {
			_, _ = w.WriteString(` data-line="`)
			_, _ = w.WriteString(html.EscapeString(section.LineText))
			_, _ = w.WriteString(`"`)
		}
		_, _ = w.WriteString(`>`)
		_, _ = w.WriteString(`<summary class="note-section__summary">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</summary>`)
		return ast.WalkContinue, nil
	}
	_, _ = w.WriteString(`</details>`)
	return ast.WalkContinue, nil
}

type attachmentVideoEmbed struct {
	ast.BaseBlock
	Title           string
	ThumbnailURL    string
	OriginalURL     string
	FallbackMessage string
}

func (n *attachmentVideoEmbed) Kind() ast.NodeKind {
	return attachmentVideoEmbedKind
}

func (n *attachmentVideoEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Thumb":    n.ThumbnailURL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

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

type youtubeEmbed struct {
	ast.BaseBlock
	Title           string
	ThumbnailURL    string
	OriginalURL     string
	FallbackMessage string
}

func (n *youtubeEmbed) Kind() ast.NodeKind {
	return youtubeEmbedKind
}

func (n *youtubeEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Thumb":    n.ThumbnailURL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type youtubeEmbedExtension struct{}

func (e *youtubeEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&youtubeEmbedTransformer{}, 115),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newYouTubeEmbedHTMLRenderer(), 510),
	))
}

type tiktokEmbed struct {
	ast.BaseBlock
	Title           string
	ThumbnailURL    string
	OriginalURL     string
	FallbackMessage string
}

func (n *tiktokEmbed) Kind() ast.NodeKind {
	return tiktokEmbedKind
}

func (n *tiktokEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Thumb":    n.ThumbnailURL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type tiktokEmbedExtension struct{}

func (e *tiktokEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&tiktokEmbedTransformer{}, 120),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newTikTokEmbedHTMLRenderer(), 520),
	))
}

type instagramEmbed struct {
	ast.BaseBlock
	Title           string
	ThumbnailURL    string
	OriginalURL     string
	FallbackMessage string
}

func (n *instagramEmbed) Kind() ast.NodeKind {
	return instagramEmbedKind
}

func (n *instagramEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Thumb":    n.ThumbnailURL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type instagramEmbedExtension struct{}

func (e *instagramEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&instagramEmbedTransformer{}, 125),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newInstagramEmbedHTMLRenderer(), 530),
	))
}

type attachmentVideoEmbedExtension struct{}

func (e *attachmentVideoEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&attachmentVideoEmbedTransformer{}, 130),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newAttachmentVideoEmbedHTMLRenderer(), 540),
	))
}

type mapsEmbedTransformer struct{}

func (t *mapsEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := mapsEmbedContext(pc)
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

		status, embedURL, errMsg := lookupMapsEmbed(ctx, url)
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
				if paragraphHasOnlyLink(para, source, url) {
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
				if paragraphHasOnlyLink(para, source, url) {
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
				if paragraphHasOnlyLink(para, source, url) {
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
		}
		return ast.WalkContinue, nil
	})
}

type youtubeEmbedTransformer struct{}

func (t *youtubeEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := youtubeEmbedContext(pc)
	source := reader.Source()
	var paragraphs []*ast.Paragraph
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			paragraphs = append(paragraphs, para)
		}
		return ast.WalkContinue, nil
	})

	for _, para := range paragraphs {
		if _, ok := para.Parent().(*ast.Document); !ok {
			// Skip paragraphs already replaced during link processing.
			continue
		}
		urlText, ok := paragraphOnlyURL(para, source)
		if !ok || !isYouTubeURL(urlText) {
			continue
		}
		status, title, thumb, errMsg := lookupYouTubeEmbed(ctx, urlText)
		embed := &youtubeEmbed{
			Title:        title,
			ThumbnailURL: thumb,
			OriginalURL:  urlText,
		}
		switch status {
		case youtubeEmbedStatusFailed:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = errMsg
		case youtubeEmbedStatusPending:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = "YouTube preview loading. Reload to display the card."
		}
		parent := para.Parent()
		if parent != nil {
			parent.ReplaceChild(parent, para, embed)
		}
	}
}

type tiktokEmbedTransformer struct{}

func (t *tiktokEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := tiktokEmbedContext(pc)
	source := reader.Source()
	var paragraphs []*ast.Paragraph
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			paragraphs = append(paragraphs, para)
		}
		return ast.WalkContinue, nil
	})

	for _, para := range paragraphs {
		if _, ok := para.Parent().(*ast.Document); !ok {
			continue
		}
		urlText, ok := paragraphOnlyURL(para, source)
		if !ok || !isTikTokURL(urlText) {
			continue
		}
		status, title, thumb, errMsg := lookupTikTokEmbed(ctx, urlText)
		embed := &tiktokEmbed{
			Title:        title,
			ThumbnailURL: thumb,
			OriginalURL:  urlText,
		}
		switch status {
		case tiktokEmbedStatusFailed:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = errMsg
		case tiktokEmbedStatusPending:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = "TikTok preview loading. Reload to display the card."
		}
		parent := para.Parent()
		if parent != nil {
			parent.ReplaceChild(parent, para, embed)
		}
	}
}

type instagramEmbedTransformer struct{}

func (t *instagramEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := instagramEmbedContext(pc)
	source := reader.Source()
	var paragraphs []*ast.Paragraph
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			paragraphs = append(paragraphs, para)
		}
		return ast.WalkContinue, nil
	})

	for _, para := range paragraphs {
		if _, ok := para.Parent().(*ast.Document); !ok {
			continue
		}
		urlText, ok := paragraphOnlyURL(para, source)
		if !ok || !isInstagramURL(urlText) {
			continue
		}
		status, title, thumb, errMsg := lookupInstagramEmbed(ctx, urlText)
		embed := &instagramEmbed{
			Title:        title,
			ThumbnailURL: thumb,
			OriginalURL:  urlText,
		}
		switch status {
		case instagramEmbedStatusFailed:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = errMsg
		case instagramEmbedStatusPending:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = "Instagram preview loading. Reload to display the card."
		}
		parent := para.Parent()
		if parent != nil {
			parent.ReplaceChild(parent, para, embed)
		}
	}
}

type attachmentVideoEmbedTransformer struct{}

func (t *attachmentVideoEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	_, srv := attachmentVideoEmbedContext(pc)
	if srv == nil {
		return
	}
	source := reader.Source()
	var paragraphs []*ast.Paragraph
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			paragraphs = append(paragraphs, para)
		}
		return ast.WalkContinue, nil
	})

	for _, para := range paragraphs {
		if _, ok := para.Parent().(*ast.Document); !ok {
			continue
		}
		urlText, label, ok := paragraphOnlyLink(para, source)
		if !ok {
			continue
		}
		noteID, relPath, ok := attachmentVideoFromURL(urlText)
		if !ok {
			continue
		}
		thumbURL, ok := srv.ensureVideoThumbnail(noteID, relPath)
		title := strings.TrimSpace(label)
		if title == "" {
			title = path.Base(relPath)
		}
		embed := &attachmentVideoEmbed{
			Title:        title,
			ThumbnailURL: thumbURL,
			OriginalURL:  urlText,
		}
		if !ok {
			embed.ThumbnailURL = ""
			embed.FallbackMessage = "Video preview unavailable."
		}
		parent := para.Parent()
		if parent != nil {
			parent.ReplaceChild(parent, para, embed)
		}
	}
}

func paragraphHasOnlyLink(para *ast.Paragraph, source []byte, rawURL string) bool {
	rawURL = strings.TrimSpace(strings.Trim(rawURL, "<>"))
	linkCount := 0
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Link:
			linkCount++
			if linkCount > 1 {
				return false
			}
			linkURL := strings.TrimSpace(string(node.Destination))
			if rawURL != "" && !textMatchesURL(linkURL, rawURL) {
				return false
			}
		case *ast.AutoLink:
			linkCount++
			if linkCount > 1 {
				return false
			}
			linkURL := strings.TrimSpace(string(node.URL(source)))
			if rawURL != "" && !textMatchesURL(linkURL, rawURL) {
				return false
			}
		case *ast.Text:
			text := strings.TrimSpace(strings.Trim(string(node.Segment.Value(source)), "<>"))
			if text == "" {
				continue
			}
			if rawURL != "" && textMatchesURL(text, rawURL) {
				continue
			}
			return false
		default:
			return false
		}
	}
	return linkCount == 1
}

func textMatchesURL(text string, rawURL string) bool {
	trimmed := strings.TrimSpace(text)
	rawURL = strings.TrimSpace(rawURL)
	if strings.EqualFold(trimmed, rawURL) {
		return true
	}
	if strings.EqualFold(strings.TrimSuffix(trimmed, "/"), strings.TrimSuffix(rawURL, "/")) {
		return true
	}
	trimmed = strings.Trim(trimmed, ".,)")
	if strings.EqualFold(trimmed, rawURL) {
		return true
	}
	return false
}

func paragraphOnlyURL(para *ast.Paragraph, source []byte) (string, bool) {
	var b strings.Builder
	hasLink := false
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Link:
			if hasLink {
				return "", false
			}
			hasLink = true
			b.Reset()
			b.WriteString(strings.TrimSpace(string(node.Destination)))
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", false
			}
			if hasLink {
				return "", false
			}
			hasLink = true
			b.Reset()
			b.WriteString(strings.TrimSpace(string(node.URL(source))))
		case *ast.Text:
			text := strings.TrimSpace(string(node.Segment.Value(source)))
			if text == "" {
				continue
			}
			if hasLink {
				if textMatchesURL(text, b.String()) {
					continue
				}
				return "", false
			}
			if b.Len() > 0 {
				return "", false
			}
			b.WriteString(text)
		default:
			return "", false
		}
	}
	value := strings.TrimSpace(string(b.String()))
	if value == "" {
		return "", false
	}
	return strings.Trim(value, "<>"), true
}

func paragraphOnlyLink(para *ast.Paragraph, source []byte) (string, string, bool) {
	var (
		foundLink ast.Node
		urlText   string
	)
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Link:
			if foundLink != nil {
				return "", "", false
			}
			foundLink = node
			urlText = strings.TrimSpace(string(node.Destination))
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", "", false
			}
			if foundLink != nil {
				return "", "", false
			}
			foundLink = node
			urlText = strings.TrimSpace(string(node.URL(source)))
		case *ast.Text:
			if strings.TrimSpace(string(node.Segment.Value(source))) == "" {
				continue
			}
			return "", "", false
		default:
			return "", "", false
		}
	}
	if foundLink == nil || urlText == "" {
		return "", "", false
	}
	label := ""
	if linkNode, ok := foundLink.(*ast.Link); ok {
		label = extractTextFromNode(linkNode, source)
	} else {
		label = urlText
	}
	return strings.Trim(urlText, "<>"), label, true
}

func extractTextFromNode(node ast.Node, source []byte) string {
	var b strings.Builder
	_ = ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if textNode, ok := n.(*ast.Text); ok {
			b.Write(textNode.Segment.Value(source))
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(b.String())
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
		_, _ = w.WriteString(`<div class="map-card">`)
		_, _ = w.WriteString(`<div class="map-card__meta">`)
		_, _ = w.WriteString(`<div class="map-card__title">Map preview</div>`)
		_, _ = w.WriteString(`<div class="map-card__host">google.com/maps</div>`)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="map-card__embed">`)
		_, _ = w.WriteString(`<iframe src="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" loading="lazy" referrerpolicy="no-referrer-when-downgrade"`)
		_, _ = w.WriteString(` style="border:0;" width="100%" height="360" allowfullscreen></iframe>`)
		_, _ = w.WriteString(`</div></div>`)
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

type youtubeEmbedHTMLRenderer struct{}

func newYouTubeEmbedHTMLRenderer() renderer.NodeRenderer {
	return &youtubeEmbedHTMLRenderer{}
}

func (r *youtubeEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(youtubeEmbedKind, r.renderYouTubeEmbed)
}

func (r *youtubeEmbedHTMLRenderer) renderYouTubeEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*youtubeEmbed)
	if n.ThumbnailURL != "" && n.OriginalURL != "" {
		thumb := html.EscapeString(n.ThumbnailURL)
		title := html.EscapeString(n.Title)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="youtube-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="youtube-card__thumb"><img src="`)
		_, _ = w.WriteString(thumb)
		_, _ = w.WriteString(`" alt="`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`"></div>`)
		_, _ = w.WriteString(`<div class="youtube-card__meta">`)
		_, _ = w.WriteString(`<div class="youtube-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="youtube-card__host">youtube.com</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="youtube-card youtube-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open on YouTube</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type tiktokEmbedHTMLRenderer struct{}

func newTikTokEmbedHTMLRenderer() renderer.NodeRenderer {
	return &tiktokEmbedHTMLRenderer{}
}

func (r *tiktokEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(tiktokEmbedKind, r.renderTikTokEmbed)
}

func (r *tiktokEmbedHTMLRenderer) renderTikTokEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*tiktokEmbed)
	if n.ThumbnailURL != "" && n.OriginalURL != "" {
		thumb := html.EscapeString(n.ThumbnailURL)
		title := html.EscapeString(n.Title)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="tiktok-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="tiktok-card__thumb"><img src="`)
		_, _ = w.WriteString(thumb)
		_, _ = w.WriteString(`" alt="`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`"></div>`)
		_, _ = w.WriteString(`<div class="tiktok-card__meta">`)
		_, _ = w.WriteString(`<div class="tiktok-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="tiktok-card__host">tiktok.com</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="tiktok-card tiktok-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open on TikTok</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type instagramEmbedHTMLRenderer struct{}

func newInstagramEmbedHTMLRenderer() renderer.NodeRenderer {
	return &instagramEmbedHTMLRenderer{}
}

func (r *instagramEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(instagramEmbedKind, r.renderInstagramEmbed)
}

func (r *instagramEmbedHTMLRenderer) renderInstagramEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*instagramEmbed)
	if n.ThumbnailURL != "" && n.OriginalURL != "" {
		thumb := html.EscapeString(n.ThumbnailURL)
		title := html.EscapeString(n.Title)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="instagram-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="instagram-card__thumb"><img src="`)
		_, _ = w.WriteString(thumb)
		_, _ = w.WriteString(`" alt="`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`"></div>`)
		_, _ = w.WriteString(`<div class="instagram-card__meta">`)
		_, _ = w.WriteString(`<div class="instagram-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="instagram-card__host">instagram.com</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="instagram-card instagram-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open on Instagram</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type attachmentVideoEmbedHTMLRenderer struct{}

func newAttachmentVideoEmbedHTMLRenderer() renderer.NodeRenderer {
	return &attachmentVideoEmbedHTMLRenderer{}
}

func (r *attachmentVideoEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(attachmentVideoEmbedKind, r.renderAttachmentVideoEmbed)
}

func (r *attachmentVideoEmbedHTMLRenderer) renderAttachmentVideoEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*attachmentVideoEmbed)
	if n.ThumbnailURL != "" && n.OriginalURL != "" {
		thumb := html.EscapeString(n.ThumbnailURL)
		title := html.EscapeString(n.Title)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="video-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="video-card__thumb"><img src="`)
		_, _ = w.WriteString(thumb)
		_, _ = w.WriteString(`" alt="`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`"></div>`)
		_, _ = w.WriteString(`<div class="video-card__meta">`)
		_, _ = w.WriteString(`<div class="video-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="video-card__host">mp4</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="video-card video-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open video</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

func isMapsAppShortLink(url string) bool {
	lower := strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(lower, mapsAppShortLinkPrefix) ||
		strings.HasPrefix(lower, mapsAppShortLinkPrefixInsecure)
}

func mapsEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.TODO()
	}
	if value := pc.Get(mapsEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.TODO()
}

func youtubeEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.TODO()
	}
	if value := pc.Get(youtubeEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.TODO()
}

func tiktokEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.TODO()
	}
	if value := pc.Get(tiktokEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.TODO()
}

func instagramEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.TODO()
	}
	if value := pc.Get(instagramEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.TODO()
}

type attachmentVideoEmbedContextValue struct {
	ctx    context.Context
	server *Server
}

func attachmentVideoEmbedContext(pc parser.Context) (context.Context, *Server) {
	if pc == nil {
		return context.TODO(), nil
	}
	if value := pc.Get(attachmentVideoEmbedContextKey); value != nil {
		if ctxValue, ok := value.(attachmentVideoEmbedContextValue); ok {
			if ctxValue.ctx == nil {
				ctxValue.ctx = context.TODO()
			}
			return ctxValue.ctx, ctxValue.server
		}
	}
	return context.TODO(), nil
}

func isYouTubeURL(raw string) bool {
	_, ok := youtubeVideoID(raw)
	return ok
}

func isTikTokURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	if host == "tiktok.com" || host == "m.tiktok.com" {
		return true
	}
	if host == "vt.tiktok.com" || host == "vm.tiktok.com" {
		return true
	}
	return false
}

func isInstagramURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	if host != "instagram.com" && host != "m.instagram.com" {
		return false
	}
	pathValue := strings.TrimSpace(strings.Trim(parsed.Path, "/"))
	return pathValue != ""
}

func attachmentVideoFromURL(raw string) (string, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", false
	}
	pathValue := parsed.Path
	if pathValue == "" {
		return "", "", false
	}
	clean := path.Clean(pathValue)
	if !strings.HasPrefix(clean, "/attachments/") {
		return "", "", false
	}
	rel := strings.TrimPrefix(clean, "/attachments/")
	parts := strings.Split(rel, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	noteID := strings.TrimSpace(parts[0])
	if noteID == "" {
		return "", "", false
	}
	relPath := path.Clean(strings.Join(parts[1:], "/"))
	if relPath == "." || strings.HasPrefix(relPath, "..") || strings.Contains(relPath, "\\") {
		return "", "", false
	}
	if strings.ToLower(path.Ext(relPath)) != ".mp4" {
		return "", "", false
	}
	return noteID, relPath, true
}

func youtubeVideoID(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	if host == "youtu.be" {
		id := strings.Trim(parsed.Path, "/")
		if id == "" {
			return "", false
		}
		return id, true
	}
	if host == "youtube.com" || host == "m.youtube.com" {
		if strings.HasPrefix(parsed.Path, "/watch") {
			if id := parsed.Query().Get("v"); id != "" {
				return id, true
			}
		}
	}
	return "", false
}

func lookupTikTokEmbed(ctx context.Context, rawURL string) (tiktokEmbedStatus, string, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, tiktokEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return tiktokEmbedStatusFound, entry.ErrorMsg, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "TikTok preview unavailable."
				}
				return tiktokEmbedStatusFailed, "", "", message
			}
		}
	}

	if tiktokEmbedIsInFlight(rawURL) {
		return tiktokEmbedStatusPending, "", "", ""
	}
	tiktokEmbedMarkInFlight(rawURL)

	if title, thumb, ok := resolveTikTokEmbedNow(rawURL, tiktokEmbedSyncTimeout); ok {
		tiktokEmbedStoreFound(ctx, rawURL, title, thumb)
		tiktokEmbedClearInFlight(rawURL)
		return tiktokEmbedStatusFound, title, thumb, ""
	}

	go resolveTikTokEmbedAsync(context.WithoutCancel(ctx), rawURL)
	return tiktokEmbedStatusPending, "", "", ""
}

func lookupInstagramEmbed(ctx context.Context, rawURL string) (instagramEmbedStatus, string, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, instagramEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return instagramEmbedStatusFound, entry.ErrorMsg, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "Instagram preview unavailable."
				}
				return instagramEmbedStatusFailed, "", "", message
			}
		}
	}

	if instagramEmbedIsInFlight(rawURL) {
		return instagramEmbedStatusPending, "", "", ""
	}
	instagramEmbedMarkInFlight(rawURL)

	if title, thumb, ok := resolveInstagramEmbedNow(rawURL, instagramEmbedSyncTimeout); ok {
		instagramEmbedStoreFound(ctx, rawURL, title, thumb)
		instagramEmbedClearInFlight(rawURL)
		return instagramEmbedStatusFound, title, thumb, ""
	}

	go resolveInstagramEmbedAsync(context.WithoutCancel(ctx), rawURL)
	return instagramEmbedStatusPending, "", "", ""
}

func lookupYouTubeEmbed(ctx context.Context, rawURL string) (youtubeEmbedStatus, string, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, youtubeEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return youtubeEmbedStatusFound, entry.ErrorMsg, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "YouTube preview unavailable."
				}
				return youtubeEmbedStatusFailed, "", "", message
			}
		}
	}

	if youtubeEmbedIsInFlight(rawURL) {
		return youtubeEmbedStatusPending, "", "", ""
	}
	youtubeEmbedMarkInFlight(rawURL)

	if title, thumb, ok := resolveYouTubeEmbedNow(rawURL, youtubeEmbedSyncTimeout); ok {
		youtubeEmbedStoreFound(ctx, rawURL, title, thumb)
		youtubeEmbedClearInFlight(rawURL)
		return youtubeEmbedStatusFound, title, thumb, ""
	}

	go resolveYouTubeEmbedAsync(context.WithoutCancel(ctx), rawURL)
	return youtubeEmbedStatusPending, "", "", ""
}

func resolveTikTokEmbedNow(rawURL string, timeout time.Duration) (string, string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveTikTokEmbedWithClient(rawURL, client)
}

func resolveTikTokEmbedAsync(ctx context.Context, rawURL string) {
	title, thumb, ok := resolveTikTokEmbedWithClient(rawURL, tiktokEmbedHTTPClient)
	if !ok {
		tiktokEmbedStoreFailure(ctx, rawURL, "TikTok preview unavailable.")
		tiktokEmbedClearInFlight(rawURL)
		return
	}

	tiktokEmbedStoreFound(ctx, rawURL, title, thumb)
	tiktokEmbedClearInFlight(rawURL)
}

type tiktokOEmbed struct {
	Title        string `json:"title"`
	ThumbnailURL string `json:"thumbnail_url"`
}

func resolveTikTokEmbedWithClient(rawURL string, client *http.Client) (string, string, bool) {
	oembedURL := "https://www.tiktok.com/oembed?url=" + url.QueryEscape(rawURL)
	req, err := http.NewRequest(http.MethodGet, oembedURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	var payload tiktokOEmbed
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", false
	}
	title := strings.TrimSpace(payload.Title)
	thumb := strings.TrimSpace(payload.ThumbnailURL)
	if title == "" || thumb == "" {
		return "", "", false
	}
	return title, thumb, true
}

func resolveInstagramEmbedNow(rawURL string, timeout time.Duration) (string, string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveInstagramEmbedWithClient(rawURL, client)
}

func resolveInstagramEmbedAsync(ctx context.Context, rawURL string) {
	title, thumb, ok := resolveInstagramEmbedWithClient(rawURL, instagramEmbedHTTPClient)
	if !ok {
		instagramEmbedStoreFailure(ctx, rawURL, "Instagram preview unavailable.")
		instagramEmbedClearInFlight(rawURL)
		return
	}

	instagramEmbedStoreFound(ctx, rawURL, title, thumb)
	instagramEmbedClearInFlight(rawURL)
}

type instagramOEmbed struct {
	Title        string `json:"title"`
	ThumbnailURL string `json:"thumbnail_url"`
}

func resolveInstagramEmbedWithClient(rawURL string, client *http.Client) (string, string, bool) {
	accessToken := strings.TrimSpace(os.Getenv("WIKI_INSTAGRAM_OEMBED_TOKEN"))
	var oembedURL string
	if accessToken != "" {
		oembedURL = "https://graph.facebook.com/v19.0/instagram_oembed?url=" +
			url.QueryEscape(rawURL) + "&access_token=" + url.QueryEscape(accessToken)
	} else {
		oembedURL = "https://www.instagram.com/oembed?url=" + url.QueryEscape(rawURL)
	}
	req, err := http.NewRequest(http.MethodGet, oembedURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	var payload instagramOEmbed
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", false
	}
	title := strings.TrimSpace(payload.Title)
	thumb := strings.TrimSpace(payload.ThumbnailURL)
	if thumb == "" {
		return "", "", false
	}
	if title == "" {
		title = "Instagram Reel"
	}
	return title, thumb, true
}

func resolveYouTubeEmbedNow(rawURL string, timeout time.Duration) (string, string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveYouTubeEmbedWithClient(rawURL, client)
}

func resolveYouTubeEmbedAsync(ctx context.Context, rawURL string) {
	title, thumb, ok := resolveYouTubeEmbedWithClient(rawURL, youtubeEmbedHTTPClient)
	if !ok {
		youtubeEmbedStoreFailure(ctx, rawURL, "YouTube preview unavailable.")
		youtubeEmbedClearInFlight(rawURL)
		return
	}

	youtubeEmbedStoreFound(ctx, rawURL, title, thumb)
	youtubeEmbedClearInFlight(rawURL)
}

type youtubeOEmbed struct {
	Title        string `json:"title"`
	ThumbnailURL string `json:"thumbnail_url"`
}

func resolveYouTubeEmbedWithClient(rawURL string, client *http.Client) (string, string, bool) {
	oembedURL := "https://www.youtube.com/oembed?format=json&url=" + url.QueryEscape(rawURL)
	req, err := http.NewRequest(http.MethodGet, oembedURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	var payload youtubeOEmbed
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", false
	}
	title := strings.TrimSpace(payload.Title)
	thumb := strings.TrimSpace(payload.ThumbnailURL)
	if title == "" || thumb == "" {
		return "", "", false
	}
	return title, thumb, true
}

func tiktokEmbedIsInFlight(rawURL string) bool {
	return tiktokEmbedInFlight.IsActive(rawURL, time.Now())
}

func tiktokEmbedMarkInFlight(rawURL string) {
	tiktokEmbedInFlight.Upsert(rawURL, time.Now().Add(tiktokEmbedPendingTTL))
}

func tiktokEmbedClearInFlight(rawURL string) {
	tiktokEmbedInFlight.Delete(rawURL)
}

func tiktokEmbedStoreFound(ctx context.Context, rawURL string, title string, thumb string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      tiktokEmbedCacheKind,
		EmbedURL:  thumb,
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  title,
		UpdatedAt: now,
		ExpiresAt: now.Add(tiktokEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func tiktokEmbedStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      tiktokEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(tiktokEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func instagramEmbedIsInFlight(rawURL string) bool {
	return instagramEmbedInFlight.IsActive(rawURL, time.Now())
}

func instagramEmbedMarkInFlight(rawURL string) {
	instagramEmbedInFlight.Upsert(rawURL, time.Now().Add(instagramEmbedPendingTTL))
}

func instagramEmbedClearInFlight(rawURL string) {
	instagramEmbedInFlight.Delete(rawURL)
}

func instagramEmbedStoreFound(ctx context.Context, rawURL string, title string, thumb string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      instagramEmbedCacheKind,
		EmbedURL:  thumb,
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  title,
		UpdatedAt: now,
		ExpiresAt: now.Add(instagramEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func instagramEmbedStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      instagramEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(instagramEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func youtubeEmbedIsInFlight(rawURL string) bool {
	return youtubeEmbedInFlight.IsActive(rawURL, time.Now())
}

func youtubeEmbedMarkInFlight(rawURL string) {
	youtubeEmbedInFlight.Upsert(rawURL, time.Now().Add(youtubeEmbedPendingTTL))
}

func youtubeEmbedClearInFlight(rawURL string) {
	youtubeEmbedInFlight.Delete(rawURL)
}

func youtubeEmbedStoreFound(ctx context.Context, rawURL string, title string, thumb string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      youtubeEmbedCacheKind,
		EmbedURL:  thumb,
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  title,
		UpdatedAt: now,
		ExpiresAt: now.Add(youtubeEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func youtubeEmbedStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      youtubeEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(youtubeEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func lookupMapsEmbed(ctx context.Context, shortURL string) (mapsEmbedStatus, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, shortURL, mapsEmbedCacheKind)
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
		mapsEmbedStoreFound(ctx, shortURL, embedURL)
		mapsEmbedClearInFlight(shortURL)
		return mapsEmbedStatusFound, embedURL, ""
	}

	go resolveMapsEmbedAsync(context.WithoutCancel(ctx), shortURL)
	return mapsEmbedStatusPending, "", ""
}

func resolveMapsEmbedNow(shortURL string, timeout time.Duration) (string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveMapsEmbedWithClient(shortURL, client)
}

func resolveMapsEmbedAsync(ctx context.Context, shortURL string) {
	embedURL, ok := resolveMapsEmbedWithClient(shortURL, mapsEmbedHTTPClient)
	if !ok {
		mapsEmbedStoreFailure(ctx, shortURL, "Map preview unavailable.")
		mapsEmbedClearInFlight(shortURL)
		return
	}

	mapsEmbedStoreFound(ctx, shortURL, embedURL)
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
	return mapsEmbedInFlight.IsActive(shortURL, time.Now())
}

func mapsEmbedMarkInFlight(shortURL string) {
	mapsEmbedInFlight.Upsert(shortURL, time.Now().Add(mapsEmbedPendingTTL))
}

func mapsEmbedClearInFlight(shortURL string) {
	mapsEmbedInFlight.Delete(shortURL)
}

func mapsEmbedStoreFound(ctx context.Context, shortURL, embedURL string) {
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
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func mapsEmbedStoreFailure(ctx context.Context, shortURL, message string) {
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
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

type ttlLRUCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	lru      *list.List
}

type ttlLRUEntry struct {
	key     string
	expires time.Time
}

func newTTLCache(capacity int) *ttlLRUCache {
	if capacity < 1 {
		capacity = 1
	}
	return &ttlLRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

func (c *ttlLRUCache) IsActive(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return false
	}
	entry := elem.Value.(ttlLRUEntry)
	if entry.expires.After(now) {
		c.lru.MoveToFront(elem)
		return true
	}
	c.lru.Remove(elem)
	delete(c.items, key)
	return false
}

func (c *ttlLRUCache) Upsert(key string, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		elem.Value = ttlLRUEntry{key: key, expires: expires}
		c.lru.MoveToFront(elem)
		return
	}
	elem := c.lru.PushFront(ttlLRUEntry{key: key, expires: expires})
	c.items[key] = elem
	if c.lru.Len() > c.capacity {
		c.evictOldest()
	}
}

func (c *ttlLRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.lru.Remove(elem)
		delete(c.items, key)
	}
}

func (c *ttlLRUCache) evictOldest() {
	elem := c.lru.Back()
	if elem == nil {
		return
	}
	entry := elem.Value.(ttlLRUEntry)
	delete(c.items, entry.key)
	c.lru.Remove(elem)
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

	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := parseDateParam(r.URL.Query().Get("d"))
	activeTodo, activeDue, noteTags := splitSpecialTags(activeTags)
	isAuth := IsAuthenticated(r.Context())
	if !isAuth {
		activeTodo = false
		activeDue = false
		activeTags = noteTags
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allowed := map[string]struct{}{}
	todoCount := 0
	dueCount := 0
	if isAuth {
		todoCount, dueCount, err = s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		if isAuth && (todoCount > 0 || activeTodo) {
			allowed["TODO"] = struct{}{}
		}
		if isAuth && (dueCount > 0 || activeDue) {
			allowed["DUE"] = struct{}{}
		}
	}
	tagLinks := buildTagLinks(activeTags, tags, allowed, "/", todoCount, dueCount, activeDate, activeSearch, isAuth, activeFolder, activeRoot)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagQuery := buildTagsQuery(activeTags)
	filterQuery := buildFilterQuery(activeTags, activeDate, activeSearch, activeFolder, activeRoot)
	calendar := buildCalendarMonth(time.Now(), updateDays, "/", tagQuery, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot))
	homeNotes, nextOffset, hasMore, err := s.loadHomeNotes(r.Context(), 0, noteTags, activeTodo, activeDue, activeDate, activeSearch, activeFolder, activeRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	folders, hasRoot, err := s.idx.ListFolders(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, "/", activeTags, activeDate, activeSearch)
	data := ViewData{
		Title:            "Home",
		ContentTemplate:  "home",
		HomeNotes:        homeNotes,
		HomeHasMore:      hasMore,
		NextHomeOffset:   nextOffset,
		Tags:             tags,
		TagLinks:         tagLinks,
		ActiveTags:       activeTags,
		TagQuery:         tagQuery,
		FolderTree:       folderTree,
		ActiveFolder:     activeFolder,
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      filterQuery,
		HomeURL:          buildTagsURL("/", activeTags, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot)),
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
		UpdateDays:       updateDays,
		CalendarMonth:    calendar,
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleDaily(w http.ResponseWriter, r *http.Request) {
	date := strings.TrimPrefix(r.URL.Path, "/daily/")
	date = strings.TrimSuffix(date, "/")
	if _, err := time.Parse("2006-01-02", date); err != nil {
		http.NotFound(w, r)
		return
	}
	journalSummary, hasJournal, err := s.idx.JournalNoteByDate(r.Context(), date)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	journalCard := (*NoteCard)(nil)
	if hasJournal {
		card, err := s.buildNoteCard(r, journalSummary.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		journalCard = &card
	}
	excludeUID := ""
	if journalSummary.UID != "" {
		excludeUID = journalSummary.UID
	}
	notes, err := s.idx.NotesWithHistoryOnDate(r.Context(), date, excludeUID, 200, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	noteCards := make([]NoteCard, 0, len(notes))
	for _, note := range notes {
		card, err := s.buildNoteCard(r, note.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		noteCards = append(noteCards, card)
	}
	data := ViewData{
		Title:           "Daily",
		ContentTemplate: "daily",
		DailyDate:       date,
		DailyJournal:    journalCard,
		DailyNotes:      noteCards,
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.NotFound(w, r)
		return
	}
	if IsAuthenticated(r.Context()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		data := ViewData{
			Title:           "Login",
			ContentTemplate: "login",
		}
		s.attachViewData(r, &data)
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
	user := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	if user == "" || pass == "" {
		data := ViewData{
			Title:           "Login",
			ContentTemplate: "login",
			ErrorMessage:    "username and password required",
		}
		s.attachViewData(r, &data)
		s.views.RenderPage(w, data)
		return
	}
	if !s.auth.Authenticate(user, pass) {
		data := ViewData{
			Title:           "Login",
			ContentTemplate: "login",
			ErrorMessage:    "invalid username or password",
		}
		s.attachViewData(r, &data)
		s.views.RenderPage(w, data)
		return
	}
	token, err := s.auth.CreateToken(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "gwiki_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.NotFound(w, r)
		return
	}
	if cookie, err := r.Cookie("gwiki_session"); err == nil && cookie.Value != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "gwiki_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	s.attachViewData(r, &data)
	if r.Header.Get("HX-Request") == "true" {
		s.views.RenderTemplate(w, "search_results", data)
		return
	}

	data.Title = "Search"
	data.ContentTemplate = "search_results"
	s.views.RenderPage(w, data)
}

func (s *Server) handleTagSuggest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		s.views.RenderTemplate(w, "tag_suggest", ViewData{})
		return
	}
	tags, err := s.idx.ListTags(r.Context(), 200, "", false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	queryLower := strings.ToLower(query)
	suggestions := make([]string, 0, 8)
	seen := map[string]struct{}{}
	for _, tag := range tags {
		if strings.EqualFold(tag.Name, "todo") || strings.EqualFold(tag.Name, "due") {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(tag.Name), queryLower) {
			continue
		}
		if _, ok := seen[tag.Name]; ok {
			continue
		}
		seen[tag.Name] = struct{}{}
		suggestions = append(suggestions, tag.Name)
		if len(suggestions) >= 8 {
			break
		}
	}
	s.views.RenderTemplate(w, "tag_suggest", ViewData{TagSuggestions: suggestions})
}

func (s *Server) handleHomeNotesPage(w http.ResponseWriter, r *http.Request) {
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := parseDateParam(r.URL.Query().Get("d"))
	activeTodo, activeDue, noteTags := splitSpecialTags(activeTags)
	if !IsAuthenticated(r.Context()) {
		activeTodo = false
		activeDue = false
		activeTags = noteTags
	}
	homeNotes, nextOffset, hasMore, err := s.loadHomeNotes(r.Context(), offset, noteTags, activeTodo, activeDue, activeDate, activeSearch, activeFolder, activeRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{
		HomeNotes:        homeNotes,
		HomeHasMore:      hasMore,
		NextHomeOffset:   nextOffset,
		ActiveTags:       activeTags,
		TagQuery:         buildTagsQuery(activeTags),
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      buildFilterQuery(activeTags, activeDate, activeSearch, activeFolder, activeRoot),
		HomeURL:          buildTagsURL("/", activeTags, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot)),
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
	}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "home_notes", data)
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := parseDateParam(r.URL.Query().Get("d"))
	activeTodo, activeDue, noteTags := splitSpecialTags(activeTags)
	dueDate := ""
	if activeDue {
		dueDate = time.Now().Format("2006-01-02")
	}
	var tasks []index.TaskItem
	var err error
	if activeDate != "" {
		tasks, err = s.idx.OpenTasksByDate(r.Context(), noteTags, 300, activeDue, dueDate, activeDate, activeFolder, activeRoot)
	} else {
		tasks, err = s.idx.OpenTasks(r.Context(), noteTags, 300, activeDue, dueDate, activeFolder, activeRoot)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allowed := map[string]struct{}{}
	todoCount, dueCount, err := s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		if todoCount > 0 || activeTodo {
			allowed["TODO"] = struct{}{}
		}
		if dueCount > 0 || activeDue {
			allowed["DUE"] = struct{}{}
		}
	}
	tagLinks := buildTagLinks(activeTags, tags, allowed, "/tasks", todoCount, dueCount, activeDate, activeSearch, true, activeFolder, activeRoot)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagQuery := buildTagsQuery(activeTags)
	filterQuery := buildFilterQuery(activeTags, activeDate, activeSearch, activeFolder, activeRoot)
	calendar := buildCalendarMonth(time.Now(), updateDays, "/tasks", tagQuery, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot))
	folders, hasRoot, err := s.idx.ListFolders(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, "/tasks", activeTags, activeDate, activeSearch)
	data := ViewData{
		Title:            "Tasks",
		ContentTemplate:  "tasks",
		OpenTasks:        tasks,
		Tags:             tags,
		TagLinks:         tagLinks,
		ActiveTags:       activeTags,
		TagQuery:         tagQuery,
		FolderTree:       folderTree,
		ActiveFolder:     activeFolder,
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      filterQuery,
		HomeURL:          buildTagsURL("/", activeTags, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot)),
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
		UpdateDays:       updateDays,
		CalendarMonth:    calendar,
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleToggleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	taskID := r.Form.Get("task_id")
	fileID, lineNo, hash, err := parseTaskID(taskID)
	if err != nil {
		http.Error(w, "invalid task id", http.StatusBadRequest)
		return
	}
	notePath, err := s.idx.PathByFileID(r.Context(), fileID)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	contentBytes, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	content := normalizeLineEndings(string(contentBytes))
	body := index.StripFrontmatter(content)
	lines := strings.Split(body, "\n")
	if lineNo < 1 || lineNo > len(lines) {
		http.Error(w, "invalid task id", http.StatusBadRequest)
		return
	}
	line := lines[lineNo-1]
	if index.TaskLineHash(line) != hash {
		http.Error(w, "task changed, refresh the page", http.StatusConflict)
		return
	}
	match := taskToggleLineRe.FindStringSubmatch(line)
	if len(match) == 0 {
		http.Error(w, "invalid task line", http.StatusBadRequest)
		return
	}
	newMark := "x"
	if strings.ToLower(match[2]) == "x" {
		newMark = " "
	}
	newLine := match[1] + newMark + match[3]
	lines[lineNo-1] = newLine
	updatedBody := strings.Join(lines, "\n")
	updatedContent := updatedBody
	if fm := index.FrontmatterBlock(content); fm != "" {
		updatedContent = fm + "\n" + updatedBody
	}
	updatedContent = normalizeLineEndings(updatedContent)
	updatedContent, err = index.EnsureFrontmatterWithTitleAndUser(updatedContent, time.Now(), s.cfg.UpdatedHistoryMax, "", historyUser(r.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	unlock := s.locker.Lock(notePath)
	if err := fs.WriteFileAtomic(fullPath, []byte(updatedContent), 0o644); err != nil {
		unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	unlock()
	if info, err := os.Stat(fullPath); err == nil {
		_ = s.idx.IndexNote(r.Context(), notePath, []byte(updatedContent), info.ModTime(), info.Size())
	}
	newHash := index.TaskLineHash(newLine)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(taskCheckboxHTML(fileID, lineNo, newHash, strings.TrimSpace(newMark) != "")))
}

func (s *Server) loadHomeNotes(ctx context.Context, offset int, tags []string, onlyTodo bool, onlyDue bool, activeDate string, activeSearch string, folder string, rootOnly bool) ([]NoteCard, int, bool, error) {
	var notes []index.NoteSummary
	var err error
	switch {
	case activeDate != "" && onlyDue && len(tags) > 0:
		notes, err = s.idx.NotesWithDueTasksByDate(ctx, tags, activeDate, time.Now().Format("2006-01-02"), homeNotesPageSize+1, offset, folder, rootOnly)
	case activeDate != "" && onlyDue:
		notes, err = s.idx.NotesWithDueTasksByDate(ctx, nil, activeDate, time.Now().Format("2006-01-02"), homeNotesPageSize+1, offset, folder, rootOnly)
	case activeDate != "" && onlyTodo && len(tags) > 0:
		notes, err = s.idx.NotesWithOpenTasksByDate(ctx, tags, activeDate, homeNotesPageSize+1, offset, folder, rootOnly)
	case activeDate != "" && onlyTodo:
		notes, err = s.idx.NotesWithOpenTasksByDate(ctx, nil, activeDate, homeNotesPageSize+1, offset, folder, rootOnly)
	case activeDate != "" && len(tags) > 0:
		notes, err = s.idx.NoteList(ctx, index.NoteListFilter{
			Tags:   tags,
			Date:   activeDate,
			Query:  activeSearch,
			Folder: folder,
			Root:   rootOnly,
			Limit:  homeNotesPageSize + 1,
			Offset: offset,
		})
	case activeDate != "":
		notes, err = s.idx.NoteList(ctx, index.NoteListFilter{
			Date:   activeDate,
			Query:  activeSearch,
			Folder: folder,
			Root:   rootOnly,
			Limit:  homeNotesPageSize + 1,
			Offset: offset,
		})
	case onlyDue && len(tags) > 0:
		notes, err = s.idx.NotesWithDueTasks(ctx, tags, time.Now().Format("2006-01-02"), homeNotesPageSize+1, offset, folder, rootOnly)
	case onlyDue:
		notes, err = s.idx.NotesWithDueTasks(ctx, nil, time.Now().Format("2006-01-02"), homeNotesPageSize+1, offset, folder, rootOnly)
	case onlyTodo && len(tags) > 0:
		notes, err = s.idx.NotesWithOpenTasks(ctx, tags, homeNotesPageSize+1, offset, folder, rootOnly)
	case onlyTodo:
		notes, err = s.idx.NotesWithOpenTasks(ctx, nil, homeNotesPageSize+1, offset, folder, rootOnly)
	case len(tags) > 0:
		notes, err = s.idx.NoteList(ctx, index.NoteListFilter{
			Tags:   tags,
			Query:  activeSearch,
			Folder: folder,
			Root:   rootOnly,
			Limit:  homeNotesPageSize + 1,
			Offset: offset,
		})
	default:
		notes, err = s.idx.NoteList(ctx, index.NoteListFilter{
			Query:  activeSearch,
			Folder: folder,
			Root:   rootOnly,
			Limit:  homeNotesPageSize + 1,
			Offset: offset,
		})
	}
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
		normalized := normalizeLineEndings(string(content))
		labelTime := note.MTime
		if historyTime, ok := index.LatestHistoryTime(normalized); ok {
			labelTime = historyTime
		}
		metaAttrs := index.FrontmatterAttributes(normalized)
		if metaAttrs.Updated.IsZero() {
			metaAttrs.Updated = labelTime.Local()
		}
		cards = append(cards, NoteCard{
			Path:     note.Path,
			Title:    note.Title,
			FileName: filepath.Base(note.Path),
			Meta:     metaAttrs,
		})
	}
	return cards, offset + len(notes), hasMore, nil
}

func (s *Server) handleNewNote(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		uploadToken := strings.TrimSpace(r.URL.Query().Get("upload_token"))
		if uploadToken == "" {
			uploadToken = uuid.NewString()
		} else if _, err := uuid.Parse(uploadToken); err != nil {
			uploadToken = uuid.NewString()
		}
		data := ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			NoteTitle:        "",
			RawContent:       "",
			FrontmatterBlock: "",
			NoteMeta:         index.FrontmatterAttrs{Priority: "10"},
			FolderOptions:    s.folderOptions(r.Context()),
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
		}
		s.attachViewData(r, &data)
		s.views.RenderPage(w, data)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		uploadToken := r.Form.Get("upload_token")
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       r.Form.Get("content"),
			FrontmatterBlock: r.Form.Get("frontmatter"),
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	}
	content := normalizeLineEndings(r.Form.Get("content"))
	frontmatter := normalizeLineEndings(r.Form.Get("frontmatter"))
	uploadToken := r.Form.Get("upload_token")
	visibility := strings.TrimSpace(r.Form.Get("visibility"))
	folderInput := r.Form.Get("folder")
	priorityInput := strings.TrimSpace(r.Form.Get("priority"))
	if content == "" {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       "",
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     "content required",
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	}
	mergedContent := content
	if frontmatter != "" {
		mergedContent = frontmatter + "\n" + content
	}
	mergedContent = normalizeLineEndings(mergedContent)
	title := index.DeriveTitleFromBody(content)
	now := time.Now()
	journalMode := false
	if title == "" {
		journalMode = true
		journalDate := now.Format("2 Jan 2006")
		journalTime := now.Format("15:04")
		journalEntry := "## " + journalTime + "\n\n" + strings.TrimSpace(content) + "\n"
		notePath := filepath.ToSlash(filepath.Join(now.Format("2006-01"), now.Format("02")+".md"))
		fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
		if err != nil {
			s.renderEditError(w, r, ViewData{
				Title:            "New note",
				ContentTemplate:  "edit",
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				SaveAction:       "/notes/new",
				UploadToken:      uploadToken,
				Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
				ErrorMessage:     err.Error(),
				ErrorReturnURL:   "/notes/new",
			}, http.StatusBadRequest)
			return
		}
		if existing, err := os.ReadFile(fullPath); err == nil {
			existingContent := strings.TrimRight(normalizeLineEndings(string(existing)), "\n")
			updatedContent := existingContent + "\n\n" + journalEntry
			derivedTitle := index.DeriveTitleFromBody(updatedContent)
			if derivedTitle == "" {
				derivedTitle = journalDate
			}
			updatedContent, err = index.EnsureFrontmatterWithTitleAndUser(updatedContent, now, s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(r.Context()))
			if err != nil {
				s.renderEditError(w, r, ViewData{
					Title:            "New note",
					ContentTemplate:  "edit",
					RawContent:       content,
					FrontmatterBlock: frontmatter,
					SaveAction:       "/notes/new",
					UploadToken:      uploadToken,
					Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
					ErrorMessage:     err.Error(),
					ErrorReturnURL:   "/notes/new",
				}, http.StatusInternalServerError)
				return
			}
			unlock := s.locker.Lock(notePath)
			if err := fs.WriteFileAtomic(fullPath, []byte(updatedContent), 0o644); err != nil {
				unlock()
				s.renderEditError(w, r, ViewData{
					Title:            "New note",
					ContentTemplate:  "edit",
					RawContent:       content,
					FrontmatterBlock: frontmatter,
					SaveAction:       "/notes/new",
					UploadToken:      uploadToken,
					Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
					ErrorMessage:     err.Error(),
					ErrorReturnURL:   "/notes/new",
				}, http.StatusInternalServerError)
				return
			}
			unlock()
			if err := s.promoteTempAttachments(uploadToken, updatedContent); err != nil {
				s.renderEditError(w, r, ViewData{
					Title:            "New note",
					ContentTemplate:  "edit",
					RawContent:       content,
					FrontmatterBlock: frontmatter,
					SaveAction:       "/notes/new",
					UploadToken:      uploadToken,
					Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
					ErrorMessage:     err.Error(),
					ErrorReturnURL:   "/notes/new",
				}, http.StatusInternalServerError)
				return
			}
			if info, err := os.Stat(fullPath); err == nil {
				_ = s.idx.IndexNote(r.Context(), notePath, []byte(updatedContent), info.ModTime(), info.Size())
			}
			targetURL := "/notes/" + notePath
			if isHTMX(r) {
				w.Header().Set("HX-Redirect", targetURL)
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Redirect(w, r, targetURL, http.StatusSeeOther)
			return
		} else if err != nil && !os.IsNotExist(err) {
			s.renderEditError(w, r, ViewData{
				Title:            "New note",
				ContentTemplate:  "edit",
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				SaveAction:       "/notes/new",
				UploadToken:      uploadToken,
				Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
				ErrorMessage:     err.Error(),
				ErrorReturnURL:   "/notes/new",
			}, http.StatusInternalServerError)
			return
		}

		content = "# " + journalDate + "\n\n" + journalEntry
		mergedContent = content
		if frontmatter != "" {
			mergedContent = frontmatter + "\n" + content
		}
		mergedContent = normalizeLineEndings(mergedContent)
		title = journalDate
		folderInput = now.Format("2006-01")
	} else {
		mergedContent = normalizeLineEndings(mergedContent)
	}

	mergedContent, err := index.EnsureFrontmatterWithTitleAndUser(mergedContent, now, s.cfg.UpdatedHistoryMax, title, historyUser(r.Context()))
	if err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	folder, err := normalizeFolderPath(folderInput)
	if err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     "invalid folder",
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	}
	priority := "10"
	if priorityInput != "" {
		val, err := strconv.Atoi(priorityInput)
		if err != nil || val <= 0 {
			s.renderEditError(w, r, ViewData{
				Title:            "New note",
				ContentTemplate:  "edit",
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				SaveAction:       "/notes/new",
				UploadToken:      uploadToken,
				Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
				ErrorMessage:     "invalid priority",
				ErrorReturnURL:   "/notes/new",
			}, http.StatusBadRequest)
			return
		}
		priority = strconv.Itoa(val)
	}
	if updated, err := index.SetVisibility(mergedContent, visibility); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}
	if updated, err := index.SetPriority(mergedContent, priority); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}
	if updated, err := index.SetFolder(mergedContent, folder); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}

	var notePath string
	if journalMode {
		notePath = filepath.ToSlash(filepath.Join(folder, now.Format("02")+".md"))
	} else {
		slug := slugify(title)
		notePath = fs.EnsureMDExt(slug)
		if folder != "" {
			notePath = filepath.ToSlash(filepath.Join(folder, notePath))
		}
	}
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(fullPath); err == nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     "note already exists",
			ErrorReturnURL:   "/notes/new",
		}, http.StatusConflict)
		return
	}
	if err != nil && !os.IsNotExist(err) {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	if err := fs.WriteFileAtomic(fullPath, []byte(mergedContent), 0o644); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	if err := s.promoteTempAttachments(uploadToken, mergedContent); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	info, err := os.Stat(fullPath)
	if err == nil {
		_ = s.idx.IndexNote(r.Context(), notePath, []byte(mergedContent), info.ModTime(), info.Size())
	}

	targetURL := "/notes/" + notePath
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", targetURL)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}

func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	pathPart := strings.TrimPrefix(r.URL.Path, "/notes/")
	pathPart = strings.TrimSuffix(pathPart, "/")
	if pathPart == "" {
		http.NotFound(w, r)
		return
	}
	if pathPart == "new/attachments/delete" {
		s.handleDeleteTempAttachment(w, r)
		return
	}
	if pathPart == "new/upload" {
		s.handleUploadTempAttachment(w, r)
		return
	}
	if strings.HasSuffix(pathPart, "/edit") {
		base := strings.TrimSuffix(pathPart, "/edit")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleEditNote(w, r, resolved)
		return
	}
	if strings.HasSuffix(pathPart, "/save") {
		base := strings.TrimSuffix(pathPart, "/save")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleSaveNote(w, r, resolved)
		return
	}
	if strings.HasSuffix(pathPart, "/upload") {
		base := strings.TrimSuffix(pathPart, "/upload")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleUploadAttachment(w, r, resolved)
		return
	}
	if strings.HasSuffix(pathPart, "/attachments/delete") {
		base := strings.TrimSuffix(pathPart, "/attachments/delete")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleDeleteAttachment(w, r, resolved)
		return
	}
	if strings.HasSuffix(pathPart, "/delete") {
		base := strings.TrimSuffix(pathPart, "/delete")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleDeleteNote(w, r, resolved)
		return
	}
	if strings.HasSuffix(pathPart, "/collapsed") {
		base := strings.TrimSuffix(pathPart, "/collapsed")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleCollapsedSections(w, r, resolved)
		return
	}
	if strings.HasSuffix(pathPart, "/preview") {
		base := strings.TrimSuffix(pathPart, "/preview")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handlePreview(w, r, resolved)
		return
	}
	if strings.HasSuffix(pathPart, "/card") {
		base := strings.TrimSuffix(pathPart, "/card")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleNoteCardFragment(w, r, resolved)
		return
	}
	if strings.HasSuffix(pathPart, "/detail") {
		base := strings.TrimSuffix(pathPart, "/detail")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleNoteDetailFragment(w, r, resolved)
		return
	}

	resolved, err := s.resolveNotePath(r.Context(), pathPart)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.handleViewNote(w, r, resolved)
}

func (s *Server) handleViewNote(w http.ResponseWriter, r *http.Request, notePath string) {
	data, status, err := s.buildNoteViewData(r, notePath, false)
	if err != nil {
		if status == http.StatusNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleNoteDetailFragment(w http.ResponseWriter, r *http.Request, notePath string) {
	data, status, err := s.buildNoteViewData(r, notePath, true)
	if err != nil {
		if status == http.StatusNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "note_detail", data)
}

func (s *Server) handleNoteCardFragment(w http.ResponseWriter, r *http.Request, notePath string) {
	data, status, err := s.buildNoteCardData(r, notePath)
	if err != nil {
		if status == http.StatusNotFound {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "note_detail", data)
}

func (s *Server) buildNoteCard(r *http.Request, notePath string) (NoteCard, error) {
	data, status, err := s.buildNoteCardData(r, notePath)
	if err != nil {
		return NoteCard{}, err
	}
	if status != http.StatusOK {
		return NoteCard{}, fmt.Errorf("unexpected status %d", status)
	}
	return NoteCard{
		Path:         notePath,
		Title:        data.NoteTitle,
		FileName:     filepath.Base(notePath),
		RenderedHTML: data.RenderedHTML,
		Meta:         data.NoteMeta,
	}, nil
}

func (s *Server) buildNoteViewData(r *http.Request, notePath string, renderBody bool) (ViewData, int, error) {
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		return ViewData{}, http.StatusBadRequest, err
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ViewData{}, http.StatusNotFound, err
		}
		return ViewData{}, http.StatusInternalServerError, err
	}
	if !index.HasFrontmatter(string(content)) {
		derivedTitle := index.DeriveTitleFromBody(string(content))
		if derivedTitle == "" {
			derivedTitle = time.Now().Format("2006-01-02 15-04")
		}
		updated, err := index.EnsureFrontmatterWithTitleAndUser(string(content), time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(r.Context()))
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
		unlock := s.locker.Lock(notePath)
		if err := fs.WriteFileAtomic(fullPath, []byte(updated), 0o644); err != nil {
			unlock()
			return ViewData{}, http.StatusInternalServerError, err
		}
		unlock()
		content = []byte(updated)
		if info, err := os.Stat(fullPath); err == nil {
			_ = s.idx.IndexNote(r.Context(), notePath, content, info.ModTime(), info.Size())
		}
	}
	if info, err := os.Stat(fullPath); err == nil {
		if err := s.idx.IndexNoteIfChanged(r.Context(), notePath, content, info.ModTime(), info.Size()); err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
	}

	normalizedContent := []byte(normalizeLineEndings(string(content)))
	meta := index.ParseContent(string(normalizedContent))
	noteMeta := index.FrontmatterAttributes(string(normalizedContent))
	if !IsAuthenticated(r.Context()) && !strings.EqualFold(noteMeta.Visibility, "public") {
		return ViewData{}, http.StatusNotFound, errors.New("not found")
	}
	htmlStr := ""
	if renderBody {
		renderCtx := r.Context()
		sections, err := s.idx.CollapsedSections(renderCtx, noteMeta.ID)
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
		if state, ok, err := collapsedSectionStateFromSections(noteMeta.ID, sections); err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		} else if ok {
			renderCtx = withCollapsibleSectionState(renderCtx, state)
		}
		rendered, err := s.renderNoteBody(renderCtx, normalizedContent)
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
		fileID, err := s.idx.FileIDByPath(r.Context(), notePath)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return ViewData{}, http.StatusInternalServerError, err
		}
		if err == nil && IsAuthenticated(r.Context()) {
			rendered = decorateTaskCheckboxes(rendered, fileID, meta.Tasks)
		}
		htmlStr = rendered
	}
	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := parseDateParam(r.URL.Query().Get("d"))
	activeTodo, activeDue, noteTags := splitSpecialTags(activeTags)
	isAuth := IsAuthenticated(r.Context())
	if !isAuth {
		activeTodo = false
		activeDue = false
		activeTags = noteTags
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot)
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	allowed := map[string]struct{}{}
	todoCount := 0
	dueCount := 0
	if isAuth {
		todoCount, dueCount, err = s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot)
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot)
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		if isAuth && (todoCount > 0 || activeTodo) {
			allowed["TODO"] = struct{}{}
		}
		if isAuth && (dueCount > 0 || activeDue) {
			allowed["DUE"] = struct{}{}
		}
	}
	tagLinks := buildTagLinks(activeTags, tags, allowed, "/", todoCount, dueCount, activeDate, activeSearch, isAuth, activeFolder, activeRoot)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot)
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	tagQuery := buildTagsQuery(activeTags)
	filterQuery := buildFilterQuery(activeTags, activeDate, activeSearch, activeFolder, activeRoot)
	calendar := buildCalendarMonth(time.Now(), updateDays, "/", tagQuery, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot))
	backlinks, err := s.idx.Backlinks(r.Context(), notePath, meta.Title, noteMeta.ID)
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	backlinkViews := make([]BacklinkView, 0, len(backlinks))
	for _, link := range backlinks {
		lineHTML, err := s.renderLineMarkdown(r.Context(), link.Line)
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
		backlinkViews = append(backlinkViews, BacklinkView{
			FromPath:  link.FromPath,
			FromTitle: link.FromTitle,
			LineNo:    link.LineNo,
			LineHTML:  lineHTML,
		})
	}

	folders, hasRoot, err := s.idx.ListFolders(r.Context())
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, "/", activeTags, activeDate, activeSearch)
	data := ViewData{
		Title:            meta.Title,
		ContentTemplate:  "view",
		NotePath:         notePath,
		NoteTitle:        meta.Title,
		NoteFileName:     filepath.Base(notePath),
		NoteMeta:         noteMeta,
		RenderedHTML:     template.HTML(htmlStr),
		Tags:             tags,
		TagLinks:         tagLinks,
		ActiveTags:       activeTags,
		TagQuery:         tagQuery,
		FolderTree:       folderTree,
		ActiveFolder:     activeFolder,
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      filterQuery,
		HomeURL:          buildTagsURL("/", activeTags, activeDate, activeSearch, buildFolderQuery(activeFolder, activeRoot)),
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
		UpdateDays:       updateDays,
		CalendarMonth:    calendar,
		Backlinks: backlinkViews,
	}
	return data, http.StatusOK, nil
}

func (s *Server) buildNoteCardData(r *http.Request, notePath string) (ViewData, int, error) {
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		return ViewData{}, http.StatusBadRequest, err
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ViewData{}, http.StatusNotFound, err
		}
		return ViewData{}, http.StatusInternalServerError, err
	}
	if !index.HasFrontmatter(string(content)) {
		derivedTitle := index.DeriveTitleFromBody(string(content))
		if derivedTitle == "" {
			derivedTitle = time.Now().Format("2006-01-02 15-04")
		}
		updated, err := index.EnsureFrontmatterWithTitleAndUser(string(content), time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(r.Context()))
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
		unlock := s.locker.Lock(notePath)
		if err := fs.WriteFileAtomic(fullPath, []byte(updated), 0o644); err != nil {
			unlock()
			return ViewData{}, http.StatusInternalServerError, err
		}
		unlock()
		content = []byte(updated)
		if info, err := os.Stat(fullPath); err == nil {
			_ = s.idx.IndexNote(r.Context(), notePath, content, info.ModTime(), info.Size())
		}
	}
	info, err := os.Stat(fullPath)
	if err == nil {
		if err := s.idx.IndexNoteIfChanged(r.Context(), notePath, content, info.ModTime(), info.Size()); err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
	}

	normalizedContent := []byte(normalizeLineEndings(string(content)))
	meta := index.ParseContent(string(normalizedContent))
	noteMeta := index.FrontmatterAttributes(string(normalizedContent))
	if !IsAuthenticated(r.Context()) && !strings.EqualFold(noteMeta.Visibility, "public") {
		return ViewData{}, http.StatusNotFound, errors.New("not found")
	}
	renderCtx := r.Context()
	if state, ok, err := s.collapsedSectionState(renderCtx, noteMeta.ID); err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	} else if ok {
		renderCtx = withCollapsibleSectionState(renderCtx, state)
	}
	htmlStr, err := s.renderNoteBody(renderCtx, normalizedContent)
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	fileID, err := s.idx.FileIDByPath(r.Context(), notePath)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ViewData{}, http.StatusInternalServerError, err
	}
	if err == nil && IsAuthenticated(r.Context()) {
		htmlStr = decorateTaskCheckboxes(htmlStr, fileID, meta.Tasks)
	}
	if info != nil {
		labelTime := info.ModTime()
		if historyTime, ok := index.LatestHistoryTime(string(normalizedContent)); ok {
			labelTime = historyTime
		}
		if noteMeta.Updated.IsZero() {
			noteMeta.Updated = labelTime.Local()
		}
	}

	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := parseDateParam(r.URL.Query().Get("d"))
	filterQuery := buildFilterQuery(activeTags, activeDate, activeSearch, activeFolder, activeRoot)
	noteURL := "/notes/" + notePath
	if filterQuery != "" {
		noteURL = noteURL + "?" + filterQuery
	}

	data := ViewData{
		NotePath:     notePath,
		NoteTitle:    meta.Title,
		NoteMeta:     noteMeta,
		RenderedHTML: template.HTML(htmlStr),
		NoteURL:      noteURL,
	}
	return data, http.StatusOK, nil
}

func (s *Server) resolveNotePath(ctx context.Context, noteRef string) (string, error) {
	noteRef = strings.TrimPrefix(noteRef, "/")
	if noteRef == "" {
		return noteRef, nil
	}
	exists, err := s.idx.NoteExists(ctx, noteRef)
	if err != nil {
		return "", err
	}
	if exists {
		return noteRef, nil
	}
	path, err := s.idx.PathByUID(ctx, noteRef)
	if errors.Is(err, sql.ErrNoRows) {
		return noteRef, nil
	}
	if err != nil {
		return "", err
	}
	return path, nil
}

func (s *Server) handleEditNote(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
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
	if !index.HasFrontmatter(string(content)) {
		derivedTitle := index.DeriveTitleFromBody(string(content))
		if derivedTitle == "" {
			derivedTitle = time.Now().Format("2006-01-02 15-04")
		}
		updated, err := index.EnsureFrontmatterWithTitleAndUser(string(content), time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(r.Context()))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		unlock := s.locker.Lock(notePath)
		if err := fs.WriteFileAtomic(fullPath, []byte(updated), 0o644); err != nil {
			unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		unlock()
		content = []byte(updated)
		if info, err := os.Stat(fullPath); err == nil {
			_ = s.idx.IndexNote(r.Context(), notePath, content, info.ModTime(), info.Size())
		}
	}
	if info, err := os.Stat(fullPath); err == nil {
		if err := s.idx.IndexNoteIfChanged(r.Context(), notePath, content, info.ModTime(), info.Size()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	meta := index.ParseContent(string(content))
	attachments := []string(nil)
	metaAttrs := index.FrontmatterAttributes(string(content))
	attachmentBase := ""
	if metaAttrs.ID != "" {
		attachments = listAttachmentNames(s.noteAttachmentsDir(metaAttrs.ID))
		attachmentBase = "/" + filepath.ToSlash(filepath.Join("attachments", metaAttrs.ID))
	}
	returnURL := sanitizeReturnURL(r, r.URL.Query().Get("return"))
	if returnURL == "" {
		returnURL = sanitizeReturnURL(r, r.Referer())
	}
	if returnURL == "" {
		returnURL = "/"
	}
	data := ViewData{
		Title:            "Edit: " + meta.Title,
		ContentTemplate:  "edit",
		NotePath:         notePath,
		NoteTitle:        meta.Title,
		RawContent:       index.StripFrontmatter(string(content)),
		FrontmatterBlock: index.FrontmatterBlock(string(content)),
		NoteMeta:         metaAttrs,
		FolderOptions:    s.folderOptions(r.Context()),
		Attachments:      attachments,
		AttachmentBase:   attachmentBase,
		ReturnURL:        returnURL,
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleDeleteNote(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	ctx := r.Context()
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	content, err := os.ReadFile(fullPath)
	if err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	attachmentPath := ""
	if err == nil {
		meta := index.FrontmatterAttributes(string(content))
		if meta.ID != "" {
			attachmentPath = s.noteAttachmentsDir(meta.ID)
		}
	}
	unlock := s.locker.Lock(notePath)
	defer unlock()

	if err := os.Remove(fullPath); err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if attachmentPath != "" {
		_ = os.RemoveAll(attachmentPath)
	}
	_ = s.idx.RemoveNoteByPath(ctx, notePath)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleUploadAttachment(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("attachment")
	if err != nil {
		http.Error(w, "attachment required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	meta := index.FrontmatterAttributes(string(content))
	if meta.ID == "" {
		http.Error(w, "note id missing", http.StatusBadRequest)
		return
	}
	filename := strings.TrimSpace(header.Filename)
	if filename == "" {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}
	filename = filepath.Base(filename)
	if filename == "." || filename == string(filepath.Separator) || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	attachmentsDir := s.noteAttachmentsDir(meta.ID)
	if err := os.MkdirAll(attachmentsDir, 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	targetPath := filepath.Join(attachmentsDir, filename)
	tmpFile, err := os.CreateTemp(attachmentsDir, ".upload-*")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	if _, err := io.Copy(tmpFile, file); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/notes/"+notePath+"/edit", http.StatusSeeOther)
}

func (s *Server) handleUploadTempAttachment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("upload_token"))
	if token == "" {
		http.Error(w, "upload token required", http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(token); err != nil {
		http.Error(w, "invalid upload token", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("attachment")
	if err != nil {
		http.Error(w, "attachment required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	filename := strings.TrimSpace(header.Filename)
	if filename == "" {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}
	filename = filepath.Base(filename)
	if filename == "." || filename == string(filepath.Separator) || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	attachmentsDir := s.tempAttachmentsDir(token)
	if err := os.MkdirAll(attachmentsDir, 0o755); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	targetPath := filepath.Join(attachmentsDir, filename)
	tmpFile, err := os.CreateTemp(attachmentsDir, ".upload-*")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	if _, err := io.Copy(tmpFile, file); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmpPath)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/notes/new?upload_token="+url.QueryEscape(token), http.StatusSeeOther)
}

func (s *Server) handleDeleteTempAttachment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := strings.TrimSpace(r.FormValue("upload_token"))
	if token == "" {
		http.Error(w, "upload token required", http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(token); err != nil {
		http.Error(w, "invalid upload token", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("file"))
	if name == "" {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	name = filepath.Base(name)
	if name == "." || name == string(filepath.Separator) || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(s.tempAttachmentsDir(token), name)
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/notes/new?upload_token="+url.QueryEscape(token), http.StatusSeeOther)
}

func (s *Server) handleDeleteAttachment(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("file"))
	if name == "" {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	name = filepath.Base(name)
	if name == "." || name == string(filepath.Separator) || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		http.Error(w, "invalid filename", http.StatusBadRequest)
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
	meta := index.FrontmatterAttributes(string(content))
	if meta.ID == "" {
		http.Error(w, "note id missing", http.StatusBadRequest)
		return
	}

	targetPath := filepath.Join(s.noteAttachmentsDir(meta.ID), name)
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/notes/"+notePath+"/edit", http.StatusSeeOther)
}

func (s *Server) handleAttachmentFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, "/attachments/")
	if rel == "" {
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(rel, ".tmp/") || rel == ".tmp" {
		http.NotFound(w, r)
		return
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		http.NotFound(w, r)
		return
	}
	attachmentsRoot := filepath.Clean(s.attachmentsRoot())
	fullPath := filepath.Clean(filepath.Join(attachmentsRoot, clean))
	if !strings.HasPrefix(fullPath, attachmentsRoot+string(filepath.Separator)) && fullPath != attachmentsRoot {
		http.NotFound(w, r)
		return
	}
	noteID, ok := firstPathSegment(clean)
	if !ok || !s.noteIDAccessible(r.Context(), noteID) {
		http.NotFound(w, r)
		return
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, fullPath)
}

func (s *Server) handleAssetFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, "/assets/")
	if rel == "" {
		http.NotFound(w, r)
		return
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		http.NotFound(w, r)
		return
	}
	assetsRoot := filepath.Clean(s.assetsRoot())
	if assetsRoot == "" {
		http.NotFound(w, r)
		return
	}
	fullPath := filepath.Clean(filepath.Join(assetsRoot, clean))
	if !strings.HasPrefix(fullPath, assetsRoot+string(filepath.Separator)) && fullPath != assetsRoot {
		http.NotFound(w, r)
		return
	}
	noteID, ok := firstPathSegment(clean)
	if !ok || !s.noteIDAccessible(r.Context(), noteID) {
		http.NotFound(w, r)
		return
	}
	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, fullPath)
}

func firstPathSegment(clean string) (string, bool) {
	parts := strings.Split(clean, string(filepath.Separator))
	if len(parts) < 2 {
		return "", false
	}
	noteID := strings.TrimSpace(parts[0])
	if noteID == "" {
		return "", false
	}
	return noteID, true
}

func (s *Server) noteIDAccessible(ctx context.Context, noteID string) bool {
	if noteID == "" {
		return false
	}
	if !IsAuthenticated(ctx) {
		ctx = index.WithPublicVisibility(ctx)
	}
	if _, err := s.idx.PathByUID(ctx, noteID); err != nil {
		return false
	}
	return true
}

func (s *Server) ensureVideoThumbnail(noteID, relPath string) (string, bool) {
	if noteID == "" || relPath == "" {
		return "", false
	}
	assetsRoot := s.assetsRoot()
	if assetsRoot == "" {
		return "", false
	}
	videoPath := filepath.Join(s.noteAttachmentsDir(noteID), filepath.FromSlash(relPath))
	videoInfo, err := os.Stat(videoPath)
	if err != nil || videoInfo.IsDir() {
		return "", false
	}
	baseName := strings.TrimSuffix(path.Base(relPath), path.Ext(relPath))
	if baseName == "" {
		return "", false
	}
	thumbDir := filepath.Join(assetsRoot, noteID)
	thumbName := baseName + ".jpg"
	thumbPath := filepath.Join(thumbDir, thumbName)
	thumbInfo, err := os.Stat(thumbPath)
	needsUpdate := err != nil
	if err == nil && thumbInfo.ModTime().Before(videoInfo.ModTime()) {
		needsUpdate = true
	}
	if needsUpdate {
		if err := os.MkdirAll(thumbDir, 0o755); err != nil {
			slog.Warn("video thumbnail mkdir failed", "err", err)
			return "", false
		}
		if err := generateVideoThumbnail(videoPath, thumbPath); err != nil {
			slog.Warn("video thumbnail generation failed", "err", err)
			return "", false
		}
	}
	return "/assets/" + noteID + "/" + thumbName, true
}

func generateVideoThumbnail(videoPath, thumbPath string) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(thumbPath), ".thumb-*.jpg")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	cmd := exec.Command("ffmpeg", "-y", "-ss", "00:00:01", "-i", videoPath, "-frames:v", "1", "-q:v", "2", tmpPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, thumbPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func (s *Server) promoteTempAttachments(token, content string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	if _, err := uuid.Parse(token); err != nil {
		return fmt.Errorf("invalid upload token")
	}
	meta := index.FrontmatterAttributes(content)
	if meta.ID == "" {
		return errors.New("note id missing")
	}
	tempDir := s.tempAttachmentsDir(token)
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(entries) == 0 {
		return os.RemoveAll(tempDir)
	}

	attachmentsDir := s.noteAttachmentsDir(meta.ID)
	if err := os.MkdirAll(attachmentsDir, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "" {
			continue
		}
		src := filepath.Join(tempDir, name)
		dst := filepath.Join(attachmentsDir, name)
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	return os.RemoveAll(tempDir)
}

func (s *Server) handleSaveNote(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		returnURL := sanitizeReturnURL(r, r.Form.Get("return_url"))
		s.renderEditError(w, r, ViewData{
			Title:           "Edit note",
			ContentTemplate: "edit",
			NotePath:        notePath,
			RawContent:      r.Form.Get("content"),
			ErrorMessage:    err.Error(),
			ErrorReturnURL:  "/notes/" + notePath + "/edit",
			ReturnURL:       returnURL,
		}, http.StatusBadRequest)
		return
	}
	returnURL := sanitizeReturnURL(r, r.Form.Get("return_url"))
	content := normalizeLineEndings(r.Form.Get("content"))
	frontmatter := normalizeLineEndings(r.Form.Get("frontmatter"))
	visibility := strings.TrimSpace(r.Form.Get("visibility"))
	folderInput := r.Form.Get("folder")
	priorityInput := strings.TrimSpace(r.Form.Get("priority"))
	if content == "" {
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			RawContent:       "",
			FrontmatterBlock: frontmatter,
			ErrorMessage:     "content required",
			ErrorReturnURL:   "/notes/" + notePath + "/edit",
			ReturnURL:        returnURL,
		}, http.StatusBadRequest)
		return
	}

	decision := r.Form.Get("rename_decision")
	derivedTitle := index.DeriveTitleFromBody(content)
	if derivedTitle == "" {
		derivedTitle = time.Now().Format("2006-01-02 15-04")
	}
	preserveUpdated := isJournalNotePath(notePath)
	folder, err := normalizeFolderPath(folderInput)
	if err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			NoteTitle:        derivedTitle,
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			ErrorMessage:     "invalid folder",
			ErrorReturnURL:   "/notes/" + notePath + "/edit",
			ReturnURL:        returnURL,
		}, http.StatusBadRequest)
		return
	}
	priority := ""
	if priorityInput != "" {
		val, err := strconv.Atoi(priorityInput)
		if err != nil || val <= 0 {
			s.renderEditError(w, r, ViewData{
				Title:            "Edit note",
				ContentTemplate:  "edit",
				NotePath:         notePath,
				NoteTitle:        derivedTitle,
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				ErrorMessage:     "invalid priority",
				ErrorReturnURL:   "/notes/" + notePath + "/edit",
				ReturnURL:        returnURL,
			}, http.StatusBadRequest)
			return
		}
		priority = strconv.Itoa(val)
	}

	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		s.renderEditError(w, r, ViewData{
			Title:           "Edit note",
			ContentTemplate: "edit",
			NotePath:        notePath,
			NoteTitle:       derivedTitle,
			RawContent:      content,
			ErrorMessage:    err.Error(),
			ErrorReturnURL:  "/notes/" + notePath + "/edit",
			ReturnURL:       returnURL,
		}, http.StatusBadRequest)
		return
	}
	existingContent, err := os.ReadFile(fullPath)
	if err != nil && !os.IsNotExist(err) {
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			NoteTitle:        derivedTitle,
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/" + notePath + "/edit",
			ReturnURL:        returnURL,
		}, http.StatusInternalServerError)
		return
	}
	existingContentNormalized := ""
	existingFrontmatter := ""
	oldTitle := ""
	if err == nil {
		existingContentNormalized = normalizeLineEndings(string(existingContent))
		existingFrontmatter = index.FrontmatterBlock(existingContentNormalized)
		oldTitle = index.DeriveTitleFromBody(existingContentNormalized)
	}
	hadFrontmatter := frontmatter != "" || existingFrontmatter != ""
	if frontmatter == "" {
		frontmatter = existingFrontmatter
	}
	mergedContent := content
	if frontmatter != "" {
		mergedContent = frontmatter + "\n" + content
	}
	mergedContent = normalizeLineEndings(mergedContent)
	if !hadFrontmatter {
		if preserveUpdated {
			mergedContent, err = index.EnsureFrontmatterWithTitleAndUserNoUpdated(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(r.Context()))
		} else {
			mergedContent, err = index.EnsureFrontmatterWithTitleAndUser(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(r.Context()))
		}
		if err != nil {
			s.renderEditError(w, r, ViewData{
				Title:            "Edit note",
				ContentTemplate:  "edit",
				NotePath:         notePath,
				NoteTitle:        derivedTitle,
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				ErrorMessage:     err.Error(),
				ErrorReturnURL:   "/notes/" + notePath + "/edit",
				ReturnURL:        returnURL,
			}, http.StatusInternalServerError)
			return
		}
	}
	if updated, err := index.SetVisibility(mergedContent, visibility); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			NoteTitle:        derivedTitle,
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/" + notePath + "/edit",
			ReturnURL:        returnURL,
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}
	if updated, err := index.SetPriority(mergedContent, priority); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			NoteTitle:        derivedTitle,
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/" + notePath + "/edit",
			ReturnURL:        returnURL,
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}
	if updated, err := index.SetFolder(mergedContent, folder); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			NoteTitle:        derivedTitle,
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/" + notePath + "/edit",
			ReturnURL:        returnURL,
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}
	titleChanged := oldTitle != "" && oldTitle != derivedTitle
	desiredPath := fs.EnsureMDExt(slugify(derivedTitle))
	if folder != "" {
		desiredPath = filepath.ToSlash(filepath.Join(folder, desiredPath))
	}
	if !preserveUpdated && (titleChanged || filepath.ToSlash(notePath) != desiredPath) && decision == "" {
		newPath := desiredPath
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			NoteTitle:        derivedTitle,
			RawContent:       content,
			FrontmatterBlock: index.FrontmatterBlock(mergedContent),
			NoteMeta:         index.FrontmatterAttributes(mergedContent),
			RenamePrompt:     true,
			RenameFromPath:   notePath,
			RenameToPath:     newPath,
			ReturnURL:        returnURL,
		}, http.StatusOK)
		return
	}

	if err == nil && hadFrontmatter && mergedContent == existingContentNormalized {
		targetURL := "/notes/" + notePath
		if isHTMX(r) {
			w.Header().Set("HX-Redirect", targetURL)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, targetURL, http.StatusSeeOther)
		return
	}

	if hadFrontmatter {
		if preserveUpdated {
			mergedContent, err = index.EnsureFrontmatterWithTitleAndUserNoUpdated(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(r.Context()))
		} else {
			mergedContent, err = index.EnsureFrontmatterWithTitleAndUser(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(r.Context()))
		}
		if err != nil {
			s.renderEditError(w, r, ViewData{
				Title:            "Edit note",
				ContentTemplate:  "edit",
				NotePath:         notePath,
				NoteTitle:        derivedTitle,
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				ErrorMessage:     err.Error(),
				ErrorReturnURL:   "/notes/" + notePath + "/edit",
				ReturnURL:        returnURL,
			}, http.StatusInternalServerError)
			return
		}
	}

	unlock := s.locker.Lock(notePath)
	defer unlock()

	targetPath := notePath
	targetFullPath := fullPath
	if !preserveUpdated && (titleChanged || filepath.ToSlash(notePath) != desiredPath) && decision == "confirm" {
		targetPath = desiredPath
		targetFullPath, err = fs.NoteFilePath(s.cfg.RepoPath, targetPath)
		if err != nil {
			s.renderEditError(w, r, ViewData{
				Title:            "Edit note",
				ContentTemplate:  "edit",
				NotePath:         notePath,
				NoteTitle:        derivedTitle,
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				ErrorMessage:     err.Error(),
				ErrorReturnURL:   "/notes/" + notePath + "/edit",
				ReturnURL:        returnURL,
			}, http.StatusBadRequest)
			return
		}
		if targetPath != notePath {
			if _, err := os.Stat(targetFullPath); err == nil {
				s.renderEditError(w, r, ViewData{
					Title:            "Edit note",
					ContentTemplate:  "edit",
					NotePath:         notePath,
					NoteTitle:        derivedTitle,
					RawContent:       content,
					FrontmatterBlock: frontmatter,
					ErrorMessage:     "note already exists",
					ErrorReturnURL:   "/notes/" + notePath + "/edit",
					ReturnURL:        returnURL,
				}, http.StatusConflict)
				return
			}
			if err != nil && !os.IsNotExist(err) {
				s.renderEditError(w, r, ViewData{
					Title:            "Edit note",
					ContentTemplate:  "edit",
					NotePath:         notePath,
					NoteTitle:        derivedTitle,
					RawContent:       content,
					FrontmatterBlock: frontmatter,
					ErrorMessage:     err.Error(),
					ErrorReturnURL:   "/notes/" + notePath + "/edit",
					ReturnURL:        returnURL,
				}, http.StatusInternalServerError)
				return
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(targetFullPath), 0o755); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         targetPath,
			NoteTitle:        derivedTitle,
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/" + targetPath + "/edit",
			ReturnURL:        returnURL,
		}, http.StatusInternalServerError)
		return
	}
	if err := fs.WriteFileAtomic(targetFullPath, []byte(mergedContent), 0o644); err != nil {
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         targetPath,
			NoteTitle:        derivedTitle,
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/" + targetPath + "/edit",
			ReturnURL:        returnURL,
		}, http.StatusInternalServerError)
		return
	}
	if targetPath != notePath {
		if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
			s.renderEditError(w, r, ViewData{
				Title:            "Edit note",
				ContentTemplate:  "edit",
				NotePath:         targetPath,
				NoteTitle:        derivedTitle,
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				ErrorMessage:     err.Error(),
				ErrorReturnURL:   "/notes/" + targetPath + "/edit",
				ReturnURL:        returnURL,
			}, http.StatusInternalServerError)
			return
		}
		_ = s.idx.RemoveNoteByPath(ctx, notePath)
	}
	info, err := os.Stat(targetFullPath)
	if err == nil {
		_ = s.idx.IndexNote(ctx, targetPath, []byte(mergedContent), info.ModTime(), info.Size())
	}

	targetURL := "/notes/" + targetPath
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", targetURL)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}

type collapsedSectionsPayload struct {
	Collapsed []collapsedSectionPayloadItem `json:"collapsed"`
}

type collapsedSectionPayloadItem struct {
	LineNo int    `json:"line_no"`
	Line   string `json:"line"`
}

func (s *Server) handleCollapsedSections(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
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
	meta := index.FrontmatterAttributes(string(content))
	if meta.ID == "" {
		http.Error(w, "note id missing", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		sections, err := s.idx.CollapsedSections(r.Context(), meta.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		payload := collapsedSectionsPayload{Collapsed: make([]collapsedSectionPayloadItem, 0, len(sections))}
		for _, section := range sections {
			payload.Collapsed = append(payload.Collapsed, collapsedSectionPayloadItem{
				LineNo: section.LineNo,
				Line:   section.Line,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
		return
	}
	var payload collapsedSectionsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	sections := make([]index.CollapsedSection, 0, len(payload.Collapsed))
	for _, item := range payload.Collapsed {
		if item.LineNo <= 0 {
			continue
		}
		sections = append(sections, index.CollapsedSection{
			LineNo: item.LineNo,
			Line:   item.Line,
		})
	}
	if err := s.idx.SetCollapsedSections(r.Context(), meta.ID, sections); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) renderEditError(w http.ResponseWriter, r *http.Request, data ViewData, status int) {
	w.WriteHeader(status)
	if !data.NoteMeta.Has && data.FrontmatterBlock != "" {
		data.NoteMeta = index.FrontmatterAttributes(data.FrontmatterBlock)
	}
	if data.ContentTemplate == "edit" && data.FolderOptions == nil {
		data.FolderOptions = s.folderOptions(r.Context())
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request, _ string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
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

	htmlStr, err := s.renderMarkdown(r.Context(), []byte(content))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := ViewData{RenderedHTML: template.HTML(htmlStr)}
	s.views.RenderTemplate(w, "note_content", data)
}

func (s *Server) renderMarkdown(ctx context.Context, data []byte) (string, error) {
	body := index.StripFrontmatter(string(data))
	body = s.expandWikiLinks(ctx, body)
	var b strings.Builder
	parseContext := parser.NewContext()
	parseContext.Set(mapsEmbedContextKey, ctx)
	parseContext.Set(youtubeEmbedContextKey, ctx)
	parseContext.Set(tiktokEmbedContextKey, ctx)
	parseContext.Set(instagramEmbedContextKey, ctx)
	parseContext.Set(attachmentVideoEmbedContextKey, attachmentVideoEmbedContextValue{ctx: ctx, server: s})
	if state, ok := collapsibleSectionStateFromContext(ctx); ok {
		parseContext.Set(collapsibleSectionContextKey, state)
	}
	if err := mdRenderer.Convert([]byte(body), &b, parser.WithContext(parseContext)); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (s *Server) renderNoteBody(ctx context.Context, data []byte) (string, error) {
	body := index.StripFrontmatter(string(data))
	body = stripFirstHeading(body)
	body = s.expandWikiLinks(ctx, body)
	var b strings.Builder
	parseContext := parser.NewContext()
	parseContext.Set(mapsEmbedContextKey, ctx)
	parseContext.Set(youtubeEmbedContextKey, ctx)
	parseContext.Set(tiktokEmbedContextKey, ctx)
	parseContext.Set(instagramEmbedContextKey, ctx)
	parseContext.Set(attachmentVideoEmbedContextKey, attachmentVideoEmbedContextValue{ctx: ctx, server: s})
	if state, ok := collapsibleSectionStateFromContext(ctx); ok {
		parseContext.Set(collapsibleSectionContextKey, state)
	}
	if err := mdRenderer.Convert([]byte(body), &b, parser.WithContext(parseContext)); err != nil {
		return "", err
	}
	return b.String(), nil
}

func (s *Server) renderLineMarkdown(ctx context.Context, line string) (template.HTML, error) {
	if strings.TrimSpace(line) == "" {
		return template.HTML(""), nil
	}
	htmlStr, err := s.renderMarkdown(ctx, []byte(line))
	if err != nil {
		return "", err
	}
	htmlStr = strings.TrimSpace(htmlStr)
	if strings.HasPrefix(htmlStr, "<p>") && strings.HasSuffix(htmlStr, "</p>") {
		htmlStr = strings.TrimSuffix(strings.TrimPrefix(htmlStr, "<p>"), "</p>")
		htmlStr = strings.TrimSpace(htmlStr)
	}
	return template.HTML(htmlStr), nil
}

func (s *Server) expandWikiLinks(ctx context.Context, input string) string {
	if !strings.Contains(input, "[[") {
		return input
	}
	return wikiLinkRe.ReplaceAllStringFunc(input, func(match string) string {
		trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(match, "[["), "]]"))
		if trimmed == "" {
			return match
		}
		target, label, err := s.resolveWikiLink(ctx, trimmed)
		if err != nil || target == "" {
			target = fs.EnsureMDExt(slugify(trimmed))
		}
		if label == "" {
			label = trimmed
		}
		return fmt.Sprintf("[%s](/notes/%s)", label, target)
	})
}

func stripFirstHeading(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") {
			lines = append(lines[:i], lines[i+1:]...)
			break
		}
		if trimmed != "" {
			break
		}
	}
	return strings.Join(lines, "\n")
}

func (s *Server) resolveWikiLink(ctx context.Context, ref string) (string, string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", nil
	}
	if path, title, err := s.idx.PathTitleByUID(ctx, ref); err == nil {
		return path, title, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}
	if path, err := s.idx.PathByTitleNewest(ctx, ref); err == nil {
		return path, "", nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}

	candidates := []string{ref}
	trimmed := strings.TrimPrefix(ref, "/notes/")
	trimmed = strings.TrimPrefix(trimmed, "notes/")
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed != ref && trimmed != "" {
		candidates = append(candidates, trimmed)
	}
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		for _, variant := range []string{candidate, fs.EnsureMDExt(candidate)} {
			if variant == "" {
				continue
			}
			if _, ok := seen[variant]; ok {
				continue
			}
			seen[variant] = struct{}{}
			exists, err := s.idx.NoteExists(ctx, variant)
			if err != nil {
				return "", "", err
			}
			if exists {
				return variant, "", nil
			}
		}
	}
	return "", "", nil
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

func isHTMX(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("HX-Request"), "true")
}

func sanitizeReturnURL(r *http.Request, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.IsAbs() {
		if !strings.EqualFold(parsed.Host, r.Host) {
			return ""
		}
		return parsed.RequestURI()
	}
	if strings.HasPrefix(parsed.Path, "/") {
		if parsed.RawQuery != "" {
			return parsed.Path + "?" + parsed.RawQuery
		}
		return parsed.Path
	}
	return ""
}
