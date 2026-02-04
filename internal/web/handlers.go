package web

import (
	"bufio"
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
	"mime"
	"net"
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
	"unicode"

	"github.com/alecthomas/chroma/v2"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	extensionast "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	"gwiki/internal/auth"
	"gwiki/internal/index"
	"gwiki/internal/storage/fs"
	"gwiki/internal/syncer"

	"github.com/google/uuid"
)

var (
	linkifyURLRegexp = regexp.MustCompile(`^(?:http|https|ftp)://(?:[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-z]+|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/#?][-a-zA-Z0-9@:%_+.~#$!?&/=\(\);,'">\^{}\[\]]*)?`)
	journalFolderRE  = regexp.MustCompile(`^\d{4}-\d{2}$`)
	journalNoteRE    = regexp.MustCompile(`^\d{4}-\d{2}/\d{2}\.md$`)
	journalDateH1    = regexp.MustCompile(`^#\s*(\d{4}-\d{2}-\d{2})\s*$`)
	wikiLinkRe       = regexp.MustCompile(`\[\[([^\]]+)\]\]`)
	taskCheckboxRe   = regexp.MustCompile(`(?i)<input\b[^>]*type="checkbox"[^>]*>`)
	taskToggleLineRe = regexp.MustCompile(`^(\s*- \[)( |x|X)(\] .+)$`)
	taskDoneTokenRe  = regexp.MustCompile(`\s+done:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`)
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
	goldmark.WithExtensions(&chatgptEmbedExtension{}),
	goldmark.WithExtensions(&whatsappLinkExtension{}),
	goldmark.WithExtensions(&attachmentVideoEmbedExtension{}),
	goldmark.WithExtensions(&linkTitleExtension{}),
	goldmark.WithExtensions(extension.TaskList),
	goldmark.WithRendererOptions(renderer.WithNodeRenderers(
		util.Prioritized(newCodeBlockHTMLRenderer(), 700),
	)),
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

type codeBlockHTMLRenderer struct{}

func newCodeBlockHTMLRenderer() renderer.NodeRenderer {
	return &codeBlockHTMLRenderer{}
}

func (r *codeBlockHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindFencedCodeBlock, r.renderFencedCodeBlock)
	reg.Register(ast.KindCodeBlock, r.renderCodeBlock)
}

func (r *codeBlockHTMLRenderer) renderFencedCodeBlock(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*ast.FencedCodeBlock)
	code := linesValue(n.Lines(), source)
	lang := strings.TrimSpace(string(n.Language(source)))
	renderCodeBlockHTML(w, code, lang)
	return ast.WalkSkipChildren, nil
}

func (r *codeBlockHTMLRenderer) renderCodeBlock(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*ast.CodeBlock)
	code := linesValue(n.Lines(), source)
	renderCodeBlockHTML(w, code, "")
	return ast.WalkSkipChildren, nil
}

func renderCodeBlockHTML(w util.BufWriter, code string, lang string) {
	lines := strings.Split(code, "\n")
	if len(lines) == 0 {
		lines = []string{""}
	}

	langLabel := "Plain"
	if lang != "" {
		langLabel = strings.ToUpper(lang)
	}

	_, _ = w.WriteString(`<div class="md-code-block my-4 rounded-2xl border border-slate-800/70 bg-[#0f1216]/90">`)
	_, _ = w.WriteString(`<div class="flex items-center justify-between border-b border-slate-800/70 px-4 py-2 text-[11px] uppercase tracking-[0.2em] text-slate-500">`)
	_, _ = w.WriteString(`<span class="font-semibold">`)
	_, _ = w.WriteString(html.EscapeString(langLabel))
	_, _ = w.WriteString(`</span>`)
	_, _ = w.WriteString(`<button type="button" class="js-code-copy rounded-lg border border-slate-800/80 bg-[#15181c] px-2.5 py-1 text-[10px] font-semibold text-slate-300 transition hover:text-slate-100">Copy</button>`)
	_, _ = w.WriteString(`</div>`)
	_, _ = w.WriteString(`<div class="md-code-row">`)
	_, _ = w.WriteString(`<div class="select-none border-r border-slate-800/70 bg-[#0c0f12] px-3 py-3 text-right font-mono text-[13px] leading-relaxed text-slate-600">`)
	for i := range lines {
		_, _ = w.WriteString(`<div>`)
		_, _ = w.WriteString(strconv.Itoa(i + 1))
		_, _ = w.WriteString(`</div>`)
	}
	_, _ = w.WriteString(`</div>`)
	_, _ = w.WriteString(`<pre class="m-0 w-full min-w-0 overflow-x-auto px-4 py-3 font-mono text-[13px] text-slate-100"><code`)
	if lang != "" {
		_, _ = w.WriteString(` class="language-`)
		_, _ = w.WriteString(html.EscapeString(lang))
		_, _ = w.WriteString(`"`)
	}
	_, _ = w.WriteString(`>`)
	if highlighted, ok := highlightCodeHTML(code, lang); ok {
		_, _ = w.WriteString(highlighted)
	} else {
		_, _ = w.WriteString(html.EscapeString(code))
	}
	_, _ = w.WriteString(`</code></pre>`)
	_, _ = w.WriteString(`</div></div>`)
}

func linesValue(lines *text.Segments, source []byte) string {
	if lines == nil || lines.Len() == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < lines.Len(); i++ {
		segment := lines.At(i)
		b.Write(segment.Value(source))
	}
	return b.String()
}

func highlightCodeHTML(code string, lang string) (string, bool) {
	var lexer chroma.Lexer
	if lang != "" {
		lexer = lexers.Get(lang)
	}
	if lexer == nil {
		lexer = lexers.Analyse(code)
	}
	if lexer == nil {
		return "", false
	}
	lexer = chroma.Coalesce(lexer)
	formatter := chromahtml.New(chromahtml.WithClasses(false), chromahtml.PreventSurroundingPre(true))
	style := styles.Get("github-dark")
	if style == nil {
		style = styles.Fallback
	}
	iter, err := lexer.Tokenise(nil, code)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	if err := formatter.Format(&b, style, iter); err != nil {
		return "", false
	}
	return b.String(), true
}

func (s *Server) attachViewData(r *http.Request, data *ViewData) {
	data.AuthEnabled = s.auth != nil
	data.BuildVersion = BuildVersion
	if user, ok := CurrentUser(r.Context()); ok {
		data.CurrentUser = user
		data.IsAuthenticated = user.Authenticated
		data.IsAdmin = hasRole(user.Roles, "admin")
	}
	if data.QuickEntries == nil {
		if entries, err := s.quickLauncherEntries(r, "", nil); err == nil {
			data.QuickEntries = entries
		} else {
			slog.Warn("quick launcher entries", "err", err)
		}
	}
	cfg, err := s.loadUserConfig(r.Context())
	if err != nil {
		slog.Warn("load user config", "err", err)
	}
	data.CompactNoteList = cfg.CompactNoteListValue()
	data.EditCommandTrigger = cfg.EditCommandTriggerValue()
	data.EditCommandTodo = cfg.EditCommandTodoValue()
	data.EditCommandToday = cfg.EditCommandTodayValue()
	data.EditCommandTime = cfg.EditCommandTimeValue()
	data.EditCommandDateBase = cfg.EditCommandDateBaseValue()
	// access is now driven by per-owner access files
}

func hasRole(roles []string, role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return false
	}
	for _, candidate := range roles {
		if strings.EqualFold(strings.TrimSpace(candidate), role) {
			return true
		}
	}
	return false
}

func isAdmin(ctx context.Context) bool {
	user, ok := CurrentUser(ctx)
	if !ok {
		return false
	}
	return hasRole(user.Roles, "admin")
}

func syncOwnerFromPath(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false
	}
	path = strings.TrimSuffix(path, "/")
	if !strings.HasPrefix(path, "/sync/") {
		return "", false
	}
	owner := strings.TrimSpace(strings.TrimPrefix(path, "/sync/"))
	if owner == "" || strings.Contains(owner, "/") {
		return "", false
	}
	return owner, true
}

func validEditCommandToken(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if len([]rune(value)) != 1 {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func currentUserName(ctx context.Context) string {
	if user, ok := CurrentUser(ctx); ok {
		return strings.TrimSpace(user.Name)
	}
	return ""
}

func (s *Server) ownerOptionsForUser(ctx context.Context) ([]OwnerOption, string, error) {
	userName := currentUserName(ctx)
	if userName == "" {
		return nil, "", nil
	}
	options := []OwnerOption{{Name: userName, Label: "Personal"}}
	owners, err := s.idx.WritableOwnersForUser(ctx, userName)
	if err != nil {
		return nil, "", err
	}
	for _, owner := range owners {
		if owner == userName {
			continue
		}
		options = append(options, OwnerOption{Name: owner, Label: owner})
	}
	return options, userName, nil
}

func (s *Server) ownerRepoPath(owner string) string {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return ""
	}
	return filepath.Join(s.cfg.RepoPath, owner)
}

func (s *Server) ownerFromNotePath(notePath string) (string, string, error) {
	return fs.SplitOwnerNotePath(notePath)
}

func (s *Server) ownerFromNoteID(ctx context.Context, noteID string) (string, string, error) {
	if noteID == "" {
		return "", "", fmt.Errorf("note id required")
	}
	notePath, err := s.idx.PathByUID(ctx, noteID)
	if err != nil {
		return "", "", err
	}
	return fs.SplitOwnerNotePath(notePath)
}

func (s *Server) noteFolderLabel(ctx context.Context, notePath, folder string) string {
	label := folder
	if label == "" {
		label = "/"
	}
	owner, _, err := s.ownerFromNotePath(notePath)
	if err != nil || strings.TrimSpace(owner) == "" {
		return label
	}
	ownerLabel := owner
	if currentUserName(ctx) != "" && owner == currentUserName(ctx) {
		ownerLabel = "Personal"
	}
	return ownerLabel + "/" + strings.TrimPrefix(label, "/")
}

func (s *Server) requireWriteAccess(w http.ResponseWriter, r *http.Request, ownerName string) bool {
	if !s.requireAuth(w, r) {
		return false
	}
	userName := currentUserName(r.Context())
	if userName == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	canWrite, err := s.idx.CanWriteOwner(r.Context(), ownerName, userName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if !canWrite {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) requireWriteAccessForPath(w http.ResponseWriter, r *http.Request, notePath string) bool {
	owner, _, err := s.ownerFromNotePath(notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	_, relPath, err := fs.SplitOwnerNotePath(notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return s.requireWriteAccessForRelPath(w, r, owner, relPath)
}

func (s *Server) requireWriteAccessForRelPath(w http.ResponseWriter, r *http.Request, ownerName, relPath string) bool {
	if !s.requireAuth(w, r) {
		return false
	}
	userName := currentUserName(r.Context())
	if userName == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	canWrite, err := s.idx.CanWritePath(r.Context(), ownerName, relPath, userName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}
	if !canWrite {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string {
	return e.message
}

func (s *Server) apiWriteAccessForRelPath(ctx context.Context, ownerName, relPath string) *apiError {
	userName := currentUserName(ctx)
	if userName == "" {
		return &apiError{status: http.StatusUnauthorized, message: "unauthorized"}
	}
	canWrite, err := s.idx.CanWritePath(ctx, ownerName, relPath, userName)
	if err != nil {
		return &apiError{status: http.StatusInternalServerError, message: err.Error()}
	}
	if !canWrite {
		return &apiError{status: http.StatusForbidden, message: "forbidden"}
	}
	return nil
}

func (s *Server) apiWriteAccessForOwner(ctx context.Context, ownerName string) *apiError {
	userName := currentUserName(ctx)
	if userName == "" {
		return &apiError{status: http.StatusUnauthorized, message: "unauthorized"}
	}
	canWrite, err := s.idx.CanWriteOwner(ctx, ownerName, userName)
	if err != nil {
		return &apiError{status: http.StatusInternalServerError, message: err.Error()}
	}
	if !canWrite {
		return &apiError{status: http.StatusForbidden, message: "forbidden"}
	}
	return nil
}

func buildJournalIndex(dates []time.Time) map[int]map[time.Month]map[int]struct{} {
	index := map[int]map[time.Month]map[int]struct{}{}
	for _, dt := range dates {
		year, month, day := dt.Date()
		if _, ok := index[year]; !ok {
			index[year] = map[time.Month]map[int]struct{}{}
		}
		if _, ok := index[year][month]; !ok {
			index[year][month] = map[int]struct{}{}
		}
		index[year][month][day] = struct{}{}
	}
	return index
}

func (s *Server) buildJournalSidebar(ctx context.Context, now time.Time, ownerName string) (JournalSidebar, error) {
	dates, err := s.idx.JournalDates(ctx, ownerName)
	if err != nil {
		return JournalSidebar{}, err
	}
	if len(dates) == 0 {
		return JournalSidebar{}, nil
	}
	index := buildJournalIndex(dates)
	currentYear, currentMonth, _ := now.Date()
	yearKeys := make([]int, 0, len(index))
	for year := range index {
		yearKeys = append(yearKeys, year)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(yearKeys)))

	years := make([]JournalYearNode, 0, len(yearKeys))
	for _, year := range yearKeys {
		yearNode := JournalYearNode{
			Year:  year,
			Label: fmt.Sprintf("%d", year),
		}
		if year == currentYear {
			yearNode.Expanded = true
			monthsMap := index[year]
			monthKeys := make([]int, 0, len(monthsMap))
			for month := range monthsMap {
				monthKeys = append(monthKeys, int(month))
			}
			sort.Sort(sort.Reverse(sort.IntSlice(monthKeys)))
			for _, monthValue := range monthKeys {
				month := time.Month(monthValue)
				monthNode := JournalMonthNode{
					Year:  year,
					Month: int(month),
					Label: time.Date(year, month, 1, 0, 0, 0, 0, time.UTC).Format("January"),
				}
				if month == currentMonth {
					monthNode.Expanded = true
					daysMap := monthsMap[month]
					dayKeys := make([]int, 0, len(daysMap))
					for day := range daysMap {
						dayKeys = append(dayKeys, day)
					}
					sort.Sort(sort.Reverse(sort.IntSlice(dayKeys)))
					for _, day := range dayKeys {
						dateStr := fmt.Sprintf("%04d-%02d-%02d", year, month, day)
						monthNode.Days = append(monthNode.Days, JournalDay{
							Label: fmt.Sprintf("%02d", day),
							Date:  dateStr,
							URL:   "/daily/" + dateStr,
						})
					}
				}
				yearNode.Months = append(yearNode.Months, monthNode)
			}
		}
		years = append(years, yearNode)
	}

	return JournalSidebar{Years: years}, nil
}

func buildJournalFilterQuery(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	query := r.URL.Query()
	activeTags := parseTagsParam(query.Get("t"))
	activeFolder, activeRoot := parseFolderParam(query.Get("f"))
	_, _, activeJournal, noteTags := splitSpecialTags(activeTags)
	if !IsAuthenticated(r.Context()) {
		activeJournal = false
		activeTags = noteTags
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	query.Set("t", buildTagsQuery(urlTags))
	if folderQuery := buildFolderQuery(activeFolder, activeRoot); folderQuery != "" {
		query.Set("f", folderQuery)
	} else {
		query.Del("f")
	}
	query.Del("d")
	raw := query.Encode()
	if raw == "" {
		return ""
	}
	return raw
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
	for _, section := range sections {
		if section.LineNo <= 0 {
			continue
		}
		collapsed[section.LineNo] = struct{}{}
	}
	if len(collapsed) == 0 {
		return collapsibleSectionRenderState{}, false, nil
	}
	return collapsibleSectionRenderState{
		NoteID:    noteID,
		Collapsed: collapsed,
	}, true, nil
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.auth == nil {
		return true
	}
	if IsAuthenticated(r.Context()) {
		return true
	}
	s.renderLoginPrompt(w, r, sanitizeReturnURL(r, r.URL.RequestURI()), "", http.StatusUnauthorized)
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
	if _, rel, err := fs.SplitOwnerNotePath(notePath); err == nil {
		notePath = rel
	}
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

func (s *Server) attachmentsRoot(owner string) string {
	return filepath.Join(s.cfg.RepoPath, owner, "notes", "attachments")
}

func (s *Server) ensureOwnerNotesDir(owner string) error {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return fmt.Errorf("owner required")
	}
	notesRoot := filepath.Join(s.cfg.RepoPath, owner, "notes")
	return os.MkdirAll(notesRoot, 0o755)
}

func (s *Server) tempAttachmentsDir(owner, token string) string {
	return filepath.Join(s.attachmentsRoot(owner), ".tmp", token)
}

func (s *Server) noteAttachmentsDir(owner, noteID string) string {
	return filepath.Join(s.attachmentsRoot(owner), noteID)
}

func (s *Server) assetsRoot() string {
	if s.cfg.DataPath == "" {
		if s.cfg.RepoPath == "" {
			return ""
		}
		repoAssets := filepath.Join(s.cfg.RepoPath, "assets")
		if info, err := os.Stat(repoAssets); err == nil && info.IsDir() {
			return repoAssets
		}
		return ""
	}
	dataAssets := filepath.Join(s.cfg.DataPath, "assets")
	if info, err := os.Stat(dataAssets); err == nil && info.IsDir() {
		return dataAssets
	}
	if s.cfg.RepoPath == "" {
		return ""
	}
	repoAssets := filepath.Join(s.cfg.RepoPath, "assets")
	if info, err := os.Stat(repoAssets); err == nil && info.IsDir() {
		return repoAssets
	}
	return dataAssets
}

func (s *Server) staticRoot() string {
	paths := make([]string, 0, 3)
	if s.cfg.RepoPath != "" {
		paths = append(paths, filepath.Join(s.cfg.RepoPath, "static"))
	}
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, "static"))
	}
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "static"))
	}
	for _, candidate := range paths {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	if len(paths) > 0 {
		return paths[0]
	}
	return ""
}

func (s *Server) acquireNoteWriteLock() (*fs.FileLock, error) {
	lockRoot := s.cfg.DataPath
	if lockRoot == "" && s.cfg.RepoPath != "" {
		lockRoot = filepath.Join(s.cfg.RepoPath, ".wiki")
	}
	if lockRoot == "" {
		return nil, fmt.Errorf("missing data path for lock")
	}
	lockPath := filepath.Join(lockRoot, "locks", "note-write.lock")
	timeout := s.cfg.NoteLockTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return fs.AcquireFileLockWithTimeout(lockPath, timeout)
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
		tag = strings.TrimSuffix(tag, "!")
		if tag == "" {
			continue
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

const journalTagName = "JOURNAL"

func splitSpecialTags(tags []string) (bool, bool, bool, []string) {
	out := make([]string, 0, len(tags))
	activeTodo := false
	activeDue := false
	activeJournal := false
	for _, tag := range tags {
		switch {
		case strings.EqualFold(tag, "todo"):
			activeTodo = true
		case strings.EqualFold(tag, "due"):
			activeDue = true
		case strings.EqualFold(tag, journalTagName):
			activeJournal = true
		default:
			out = append(out, tag)
		}
	}
	return activeTodo, activeDue, activeJournal, out
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
		`<input type="checkbox"%s data-task-id="%s" id="%s" hx-post="/tasks/toggle" hx-trigger="change" hx-target="closest .note-body" hx-swap="outerHTML" hx-vals='{"task_id":"%s"}'>`,
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

func buildTagLinks(active []string, tags []index.TagSummary, allowed map[string]struct{}, baseURL string) []TagLink {
	activeSet := map[string]struct{}{}
	for _, tag := range active {
		activeSet[tag] = struct{}{}
	}
	links := make([]TagLink, 0, len(tags)+2)
	for _, tag := range tags {
		_, isActive := activeSet[tag.Name]
		disabled := false
		if len(active) > 0 && !isActive && allowed != nil {
			if _, ok := allowed[tag.Name]; !ok {
				disabled = true
			}
		}
		url := ""
		if !disabled {
			url = toggleTagURL(baseURL, tag.Name)
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

func appendJournalTagLink(links []TagLink, activeJournal bool, journalCount int, baseURL string, noteTags []string) []TagLink {
	targetTags := append([]string{}, noteTags...)
	if !activeJournal {
		targetTags = append(targetTags, journalTagName)
	}
	link := TagLink{
		Name:   journalTagName,
		Count:  journalCount,
		URL:    setTagsURL(baseURL, targetTags),
		Active: activeJournal,
	}
	if activeJournal {
		link.URL = setTagsURL(baseURL, noteTags)
	}
	return append([]TagLink{link}, links...)
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

func buildFolderQuery(folder string, rootOnly bool) string {
	if rootOnly {
		return "root"
	}
	return strings.TrimSpace(folder)
}

func buildTodoLink(raw string) string {
	if raw == "" {
		return "/todo"
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "/todo"
	}
	if u.RawQuery == "" {
		return "/todo"
	}
	return "/todo?" + u.RawQuery
}

func noteCardETag(meta index.FrontmatterAttrs, hash string, etagTime int64, userKey string) string {
	if hash == "" {
		return ""
	}
	if etagTime <= 0 {
		updated := meta.Updated
		if updated.IsZero() {
			updated = time.Unix(0, 0)
		}
		etagTime = updated.Unix()
	}
	return fmt.Sprintf("\"%s-%d-%s-%s\"", meta.ID, etagTime, hash, userKey)
}

func pageETag(scope string, rawURL string, etagTime int64, userKey string) string {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = "page"
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		rawURL = "/"
	}
	if etagTime < 0 {
		etagTime = 0
	}
	version := strings.TrimSpace(BuildVersion)
	if version == "" {
		version = "dev"
	}
	return fmt.Sprintf("\"%s-%d-%s-%s-%s\"", scope, etagTime, version, rawURL, userKey)
}

func setPrivateCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate, no-transform")
	w.Header().Del("Pragma")
	w.Header().Del("Expires")
}

func currentURLString(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery == "" {
		return path
	}
	return path + "?" + r.URL.RawQuery
}

func currentPageURLString(r *http.Request) string {
	if r == nil {
		return "/"
	}
	parsed := quickLauncherURL(r)
	if parsed == nil {
		return currentURLString(r)
	}
	path := strings.TrimSpace(parsed.Path)
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery == "" {
		return path
	}
	return path + "?" + parsed.RawQuery
}

func baseURLForLinks(r *http.Request, basePath string) string {
	raw := currentURLString(r)
	if basePath == "" {
		return raw
	}
	return urlWithPath(raw, basePath)
}

func urlWithPath(raw string, path string) string {
	if path == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return path
	}
	u.RawQuery = normalizeQueryKeys(u.Query()).Encode()
	u.Path = path
	u.RawPath = ""
	return u.String()
}

func mutateURL(raw string, mutate func(values url.Values)) string {
	if raw == "" {
		raw = "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		u = &url.URL{Path: raw}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	query := normalizeQueryKeys(u.Query())
	if mutate != nil {
		mutate(query)
	}
	u.RawQuery = query.Encode()
	if u.RawQuery == "" {
		return u.Path
	}
	return u.Path + "?" + u.RawQuery
}

func normalizeQueryKeys(values url.Values) url.Values {
	if len(values) == 0 {
		return values
	}
	normalized := url.Values{}
	for key, vals := range values {
		if strings.Contains(key, "=") && len(vals) == 1 && vals[0] == "" {
			parts := strings.SplitN(key, "=", 2)
			normalized.Set(parts[0], parts[1])
			continue
		}
		normalized[key] = vals
	}
	return normalized
}

func setTagsURL(raw string, tags []string) string {
	return mutateURL(raw, func(query url.Values) {
		if len(tags) == 0 {
			query.Del("t")
			return
		}
		query.Set("t", strings.Join(tags, ","))
	})
}

func toggleTagURL(raw string, tag string) string {
	if strings.TrimSpace(tag) == "" {
		return raw
	}
	return mutateURL(raw, func(query url.Values) {
		active := parseTagsParam(query.Get("t"))
		next := make([]string, 0, len(active)+1)
		found := false
		for _, item := range active {
			if item == tag {
				found = true
				continue
			}
			next = append(next, item)
		}
		if !found {
			next = append(next, tag)
		}
		if len(next) == 0 {
			query.Del("t")
			return
		}
		query.Set("t", strings.Join(next, ","))
	})
}

func setFolderURL(raw string, folder string, rootOnly bool) string {
	return mutateURL(raw, func(query url.Values) {
		if rootOnly {
			query.Set("f", "root")
			return
		}
		folder = strings.TrimSpace(folder)
		if folder == "" {
			query.Del("f")
			return
		}
		query.Set("f", folder)
	})
}

func queryWithout(raw string, keys ...string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return ""
	}
	query := normalizeQueryKeys(u.Query())
	for _, key := range keys {
		query.Del(key)
	}
	return query.Encode()
}

func extractQuery(uri string, key string) (string, string) {
	if uri == "" {
		return "/", ""
	}
	u, err := url.Parse(uri)
	if err != nil || u == nil {
		return uri, ""
	}
	query := u.Query()
	value := query.Get(key)
	query.Del(key)
	u.RawQuery = query.Encode()
	if u.RawQuery == "" {
		return u.Path, value
	}
	return u.Path + "?" + u.RawQuery, value
}

func setQuery(uri string, key string, value string) string {
	return mutateURL(uri, func(values url.Values) {
		if strings.TrimSpace(value) == "" {
			values.Del(key)
			return
		}
		values.Set(key, value)
	})
}

func applyCalendarLinks(data *ViewData, baseURL string) {
	if data == nil {
		return
	}
	if strings.TrimSpace(baseURL) == "" {
		return
	}
	data.CalendarPrevURL = setQuery(baseURL, "month", data.CalendarMonth.PrevMonth)
	data.CalendarNextURL = setQuery(baseURL, "month", data.CalendarMonth.NextMonth)
	if data.CalendarMonth.IsCurrent {
		data.CalendarTodayURL = ""
	} else {
		data.CalendarTodayURL = setQuery(baseURL, "month", data.CalendarMonth.CurrentMonth)
	}
}

func (s *Server) folderOptions(ctx context.Context) []string {
	folders, _, err := s.idx.ListFolders(ctx, "")
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

func buildFolderTree(folders []string, hasRoot bool, activeFolder string, activeRoot bool, baseURL string) []FolderNode {
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
	allURL := setFolderURL(baseURL, "", false)
	rootURL := setFolderURL(baseURL, "", true)
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
			node.URL = setFolderURL(baseURL, node.Path, false)
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

func (s *Server) populateSidebarData(r *http.Request, basePath string, data *ViewData) error {
	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := ""
	baseURL := baseURLForLinks(r, basePath)
	activeTodo, activeDue, activeJournal, noteTags := splitSpecialTags(activeTags)
	isAuth := IsAuthenticated(r.Context())
	if !isAuth {
		activeTodo = false
		activeDue = false
		activeJournal = false
		activeTags = noteTags
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot, activeJournal, "")
	if err != nil {
		return err
	}
	allowed := map[string]struct{}{}
	todoCount := 0
	dueCount := 0
	if isAuth {
		todoCount, dueCount, err = s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			return err
		}
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			return err
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		_ = dueCount
	}
	tagLinks := buildTagLinks(urlTags, tags, allowed, baseURL)
	journalCount, err := s.idx.CountJournalNotes(r.Context(), activeFolder, activeRoot, "")
	if err != nil {
		return err
	}
	tagLinks = appendJournalTagLink(tagLinks, activeJournal, journalCount, baseURL, noteTags)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot, "")
	if err != nil {
		return err
	}
	tagQuery := buildTagsQuery(urlTags)
	filterQuery := queryWithout(baseURL, "d")
	calendar := buildCalendarMonth(calendarReferenceDate(r), updateDays, baseURL, activeDate)
	ownerFolder := ""
	if ownerName, ok := ownerHomeName(basePath); ok {
		ownerFolder = ownerName
	}
	folders, hasRoot, err := s.idx.ListFolders(r.Context(), ownerFolder)
	if err != nil {
		return err
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, baseURL)
	journalSidebar, err := s.buildJournalSidebar(r.Context(), time.Now(), "")
	if err != nil {
		return err
	}
	users, err := s.idx.ListUsers(r.Context())
	if err != nil {
		return err
	}
	currentUser := currentUserName(r.Context())
	users = filterSidebarUsers(users, currentUser)
	userCounts, err := s.idx.CountSharedNotesByOwner(r.Context(), currentUser)
	if err != nil {
		return err
	}
	data.Tags = tags
	data.TagLinks = tagLinks
	data.TodoCount = todoCount
	data.DueCount = dueCount
	data.ActiveTags = urlTags
	data.TagQuery = tagQuery
	data.FolderTree = folderTree
	data.ActiveFolder = activeFolder
	data.FolderQuery = buildFolderQuery(activeFolder, activeRoot)
	data.FilterQuery = filterQuery
	data.TodoURL = buildTodoLink(currentURLString(r))
	data.RawQuery = r.URL.RawQuery
	data.HomeURL = baseURL
	data.ActiveDate = activeDate
	data.DateQuery = buildDateQuery(activeDate)
	data.SearchQuery = activeSearch
	data.SearchQueryParam = buildSearchQuery(activeSearch)
	data.UpdateDays = updateDays
	data.CalendarMonth = calendar
	applyCalendarLinks(data, baseURL)
	data.JournalSidebar = journalSidebar
	data.Users = buildUserLinks(users, userCounts)
	return nil
}

func filterSidebarUsers(users []string, current string) []string {
	current = strings.TrimSpace(current)
	if current == "" || len(users) == 0 {
		return filterInternalUsers(users)
	}
	out := make([]string, 0, len(users))
	for _, user := range users {
		if strings.EqualFold(user, current) {
			continue
		}
		out = append(out, user)
	}
	return filterInternalUsers(out)
}

func filterInternalUsers(users []string) []string {
	if len(users) == 0 {
		return users
	}
	out := make([]string, 0, len(users))
	for _, user := range users {
		if strings.EqualFold(user, "system") {
			continue
		}
		out = append(out, user)
	}
	return out
}

func buildUserLinks(users []string, counts map[string]int) []UserLink {
	if len(users) == 0 {
		return nil
	}
	out := make([]UserLink, 0, len(users))
	for _, user := range users {
		out = append(out, UserLink{
			Name:  user,
			Count: counts[user],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func (s *Server) loadSpecialTagCounts(r *http.Request, noteTags []string, activeTodo bool, activeDue bool, activeDate string, folder string, rootOnly bool, journalOnly bool, ownerName string) (int, int, error) {
	_ = activeTodo
	_ = activeDue
	todoCount, err := s.idx.CountTasks(r.Context(), index.TaskCountFilter{
		Tags:        noteTags,
		Date:        activeDate,
		Folder:      folder,
		Root:        rootOnly,
		JournalOnly: journalOnly,
		OwnerName:   ownerName,
	})
	if err != nil {
		return 0, 0, err
	}
	dueCount, err := s.idx.CountTasks(r.Context(), index.TaskCountFilter{
		Tags:        noteTags,
		Date:        activeDate,
		Folder:      folder,
		Root:        rootOnly,
		JournalOnly: journalOnly,
		DueOnly:     true,
		OwnerName:   ownerName,
	})
	if err != nil {
		return 0, 0, err
	}
	return todoCount, dueCount, nil
}

func (s *Server) loadFilteredTags(r *http.Request, noteTags []string, activeTodo bool, activeDue bool, activeDate string, folder string, rootOnly bool, journalOnly bool, ownerName string) ([]index.TagSummary, error) {
	_ = activeTodo
	_ = activeDue
	if activeDate != "" {
		return s.idx.ListTagsFilteredByDate(r.Context(), noteTags, activeDate, 100, folder, rootOnly, journalOnly, ownerName)
	}
	return s.idx.ListTagsFiltered(r.Context(), noteTags, 100, folder, rootOnly, journalOnly, ownerName)
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
	chatgptEmbedKind       = ast.NewNodeKind("ChatGPTEmbed")
	chatgptEmbedHTTPClient = &http.Client{Timeout: 3 * time.Second}
	chatgptEmbedCacheKind  = "chatgpt"
	chatgptEmbedContextKey = parser.NewContextKey()
)

const (
	chatgptEmbedSuccessTTL  = 7 * 24 * time.Hour
	chatgptEmbedFailureTTL  = 30 * time.Minute
	chatgptEmbedPendingTTL  = 20 * time.Second
	chatgptEmbedSyncTimeout = 1200 * time.Millisecond
)

var chatgptEmbedInFlight = newTTLCache(512)

var (
	attachmentVideoEmbedKind       = ast.NewNodeKind("AttachmentVideoEmbed")
	attachmentVideoEmbedContextKey = parser.NewContextKey()
)

var (
	linkTitleCacheKind  = "link_title"
	linkTitleContextKey = parser.NewContextKey()
	linkTitleHTTPClient = &http.Client{Timeout: 3 * time.Second}
)

const (
	linkTitleSuccessTTL = 7 * 24 * time.Hour
	linkTitleFailureTTL = 24 * time.Hour
	linkTitlePendingTTL = 20 * time.Second
)

var linkTitleInFlight = newTTLCache(512)

var (
	whatsappLinkKind = ast.NewNodeKind("WhatsAppLink")
)

var (
	dueTokenRe  = regexp.MustCompile(`(?i)(?:@due\((\d{4}-\d{2}-\d{2})\)|due:(\d{4}-\d{2}-\d{2}))`)
	doneTokenRe = regexp.MustCompile(`(?i)done:(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})`)
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

type chatgptEmbedStatus int

const (
	chatgptEmbedStatusPending chatgptEmbedStatus = iota
	chatgptEmbedStatusFound
	chatgptEmbedStatusFailed
)

type collapsibleSection struct {
	ast.BaseBlock
	Title  string
	LineNo int
	Open   bool
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
		lineNo := headingLineInfo(heading, source)
		open := true
		if lineNo > 0 && state.Collapsed != nil {
			if _, ok := state.Collapsed[lineNo]; ok {
				open = false
			}
		}
		section := &collapsibleSection{
			Title:  title,
			LineNo: lineNo,
			Open:   open,
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

func headingLineInfo(node *ast.Heading, source []byte) int {
	lines := node.Lines()
	if lines == nil || lines.Len() == 0 {
		return 0
	}
	segment := lines.At(0)
	if segment.Start < 0 || segment.Start > len(source) {
		return 0
	}
	lineStart := bytes.LastIndex(source[:segment.Start], []byte("\n")) + 1
	lineNo := bytes.Count(source[:lineStart], []byte("\n")) + 1
	return lineNo
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

type chatgptEmbed struct {
	ast.BaseBlock
	Title           string
	Preview         string
	OriginalURL     string
	FallbackMessage string
}

func (n *chatgptEmbed) Kind() ast.NodeKind {
	return chatgptEmbedKind
}

func (n *chatgptEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Preview":  n.Preview,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type chatgptEmbedExtension struct{}

func (e *chatgptEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&chatgptEmbedTransformer{}, 128),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newChatGPTEmbedHTMLRenderer(), 535),
	))
}

type whatsappLink struct {
	ast.BaseInline
	Number      string
	OriginalURL string
}

func (n *whatsappLink) Kind() ast.NodeKind {
	return whatsappLinkKind
}

func (n *whatsappLink) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Number":   n.Number,
		"Original": n.OriginalURL,
	}, nil)
}

type whatsappLinkExtension struct{}

func (e *whatsappLinkExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&whatsappLinkTransformer{}, 129),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newWhatsAppLinkHTMLRenderer(), 536),
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

type linkTitleExtension struct{}

func (e *linkTitleExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&linkTitleTransformer{}, 135),
	))
}

type linkTitleTransformer struct{}

func (t *linkTitleTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := linkTitleContext(pc)
	source := reader.Source()
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch link := n.(type) {
		case *ast.Link:
			urlText := strings.TrimSpace(string(link.Destination))
			if !isExternalHTTPURL(urlText) {
				return ast.WalkContinue, nil
			}
			label, ok := linkLabelText(link, source)
			if !ok || !textMatchesURL(label, urlText) {
				return ast.WalkContinue, nil
			}
			title, ok := lookupLinkTitle(ctx, urlText)
			if !ok || title == "" {
				return ast.WalkContinue, nil
			}
			replaceLinkLabel(link, title)
			if shouldOpenNewTab(link.Destination) {
				link.SetAttributeString("target", []byte("_blank"))
				link.SetAttributeString("rel", []byte("noopener noreferrer"))
			}
		case *ast.AutoLink:
			if link.AutoLinkType != ast.AutoLinkURL {
				return ast.WalkContinue, nil
			}
			urlText := strings.TrimSpace(string(link.URL(source)))
			if !isExternalHTTPURL(urlText) {
				return ast.WalkContinue, nil
			}
			title, ok := lookupLinkTitle(ctx, urlText)
			if !ok || title == "" {
				return ast.WalkContinue, nil
			}
			parent := link.Parent()
			if parent == nil {
				return ast.WalkContinue, nil
			}
			newLink := ast.NewLink()
			newLink.Destination = []byte(urlText)
			newLink.AppendChild(newLink, ast.NewString([]byte(title)))
			if shouldOpenNewTab(newLink.Destination) {
				newLink.SetAttributeString("target", []byte("_blank"))
				newLink.SetAttributeString("rel", []byte("noopener noreferrer"))
			}
			parent.ReplaceChild(parent, link, newLink)
		}
		return ast.WalkContinue, nil
	})
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
	var blocks []ast.Node
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			blocks = append(blocks, para)
		}
		if block, ok := n.(*ast.TextBlock); ok {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})

	for _, block := range blocks {
		if !isEmbedParagraphParent(block.Parent()) {
			// Skip paragraphs already replaced during link processing.
			continue
		}
		if urlText, ok := blockOnlyURL(block, source); ok {
			if !isYouTubeURL(urlText) {
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
			parent := block.Parent()
			replaceBlockWithEmbed(parent, block, embed)
			continue
		}
		urlText, hasTextBefore, _, linkNode, ok := blockSingleLinkWithText(block, source)
		if !ok || !isYouTubeURL(urlText) {
			continue
		}
		block.RemoveChild(block, linkNode)
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
		parent := block.Parent()
		if parent == nil {
			continue
		}
		if hasTextBefore {
			parent.InsertAfter(parent, block, embed)
			continue
		}
		parent.ReplaceChild(parent, block, embed)
		parent.InsertAfter(parent, embed, block)
	}
}

type tiktokEmbedTransformer struct{}

func (t *tiktokEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := tiktokEmbedContext(pc)
	source := reader.Source()
	var blocks []ast.Node
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			blocks = append(blocks, para)
		}
		if block, ok := n.(*ast.TextBlock); ok {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})

	for _, block := range blocks {
		if !isEmbedParagraphParent(block.Parent()) {
			continue
		}
		if urlText, ok := blockOnlyURL(block, source); ok {
			if !isTikTokURL(urlText) {
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
			parent := block.Parent()
			replaceBlockWithEmbed(parent, block, embed)
			continue
		}
		urlText, hasTextBefore, _, linkNode, ok := blockSingleLinkWithText(block, source)
		if !ok || !isTikTokURL(urlText) {
			continue
		}
		block.RemoveChild(block, linkNode)
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
		parent := block.Parent()
		if parent == nil {
			continue
		}
		if hasTextBefore {
			parent.InsertAfter(parent, block, embed)
			continue
		}
		parent.ReplaceChild(parent, block, embed)
		parent.InsertAfter(parent, embed, block)
	}
}

type instagramEmbedTransformer struct{}

func (t *instagramEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := instagramEmbedContext(pc)
	source := reader.Source()
	var blocks []ast.Node
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			blocks = append(blocks, para)
		}
		if block, ok := n.(*ast.TextBlock); ok {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})

	for _, block := range blocks {
		if !isEmbedParagraphParent(block.Parent()) {
			continue
		}
		if urlText, ok := blockOnlyURL(block, source); ok {
			if !isInstagramURL(urlText) {
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
			parent := block.Parent()
			replaceBlockWithEmbed(parent, block, embed)
			continue
		}
		urlText, hasTextBefore, _, linkNode, ok := blockSingleLinkWithText(block, source)
		if !ok || !isInstagramURL(urlText) {
			continue
		}
		block.RemoveChild(block, linkNode)
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
		parent := block.Parent()
		if parent == nil {
			continue
		}
		if hasTextBefore {
			parent.InsertAfter(parent, block, embed)
			continue
		}
		parent.ReplaceChild(parent, block, embed)
		parent.InsertAfter(parent, embed, block)
	}
}

type chatgptEmbedTransformer struct{}

func (t *chatgptEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := chatgptEmbedContext(pc)
	source := reader.Source()
	var blocks []ast.Node
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			blocks = append(blocks, para)
		}
		if block, ok := n.(*ast.TextBlock); ok {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})

	for _, block := range blocks {
		if !isEmbedParagraphParent(block.Parent()) {
			continue
		}
		if urlText, ok := blockOnlyURL(block, source); ok {
			if !isChatGPTShareURL(urlText) {
				continue
			}
			status, title, preview, errMsg := lookupChatGPTEmbed(ctx, urlText)
			embed := &chatgptEmbed{
				Title:       title,
				Preview:     preview,
				OriginalURL: urlText,
			}
			switch status {
			case chatgptEmbedStatusFailed:
				embed.Title = ""
				embed.Preview = ""
				embed.FallbackMessage = errMsg
			case chatgptEmbedStatusPending:
				embed.Title = ""
				embed.Preview = ""
				embed.FallbackMessage = "ChatGPT preview loading. Reload to display the card."
			}
			parent := block.Parent()
			replaceBlockWithEmbed(parent, block, embed)
			continue
		}
		urlText, hasTextBefore, _, linkNode, ok := blockSingleLinkWithText(block, source)
		if !ok || !isChatGPTShareURL(urlText) {
			continue
		}
		block.RemoveChild(block, linkNode)
		status, title, preview, errMsg := lookupChatGPTEmbed(ctx, urlText)
		embed := &chatgptEmbed{
			Title:       title,
			Preview:     preview,
			OriginalURL: urlText,
		}
		switch status {
		case chatgptEmbedStatusFailed:
			embed.Title = ""
			embed.Preview = ""
			embed.FallbackMessage = errMsg
		case chatgptEmbedStatusPending:
			embed.Title = ""
			embed.Preview = ""
			embed.FallbackMessage = "ChatGPT preview loading. Reload to display the card."
		}
		parent := block.Parent()
		if parent == nil {
			continue
		}
		if hasTextBefore {
			parent.InsertAfter(parent, block, embed)
			continue
		}
		parent.ReplaceChild(parent, block, embed)
		parent.InsertAfter(parent, embed, block)
	}
}

type whatsappLinkTransformer struct{}

func (t *whatsappLinkTransformer) Transform(node *ast.Document, reader text.Reader, _ parser.Context) {
	source := reader.Source()
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var urlText string
		switch link := n.(type) {
		case *ast.Link:
			urlText = strings.TrimSpace(string(link.Destination))
		case *ast.AutoLink:
			if link.AutoLinkType != ast.AutoLinkURL {
				return ast.WalkContinue, nil
			}
			urlText = strings.TrimSpace(string(link.URL(source)))
		default:
			return ast.WalkContinue, nil
		}
		number, ok := whatsAppNumber(urlText)
		if !ok {
			return ast.WalkContinue, nil
		}
		parent := n.Parent()
		if parent == nil {
			return ast.WalkContinue, nil
		}
		parent.ReplaceChild(parent, n, &whatsappLink{
			Number:      number,
			OriginalURL: urlText,
		})
		return ast.WalkContinue, nil
	})
}

type attachmentVideoEmbedTransformer struct{}

func (t *attachmentVideoEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx, srv := attachmentVideoEmbedContext(pc)
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
		if !isEmbedParagraphParent(para.Parent()) {
			continue
		}
		urlText, label, _, ok := paragraphOnlyMedia(para, source)
		if !ok {
			embeds := make([]ast.Node, 0, 2)
			remove := make([]ast.Node, 0, 2)
			for child := para.FirstChild(); child != nil; child = child.NextSibling() {
				inlineURL, inlineLabel, ok := inlineMediaURL(child, source)
				if !ok {
					continue
				}
				noteID, relPath, ok := attachmentVideoFromURL(inlineURL)
				if !ok {
					continue
				}
				thumbURL, ok := srv.ensureVideoThumbnail(ctx, noteID, relPath)
				title := strings.TrimSpace(inlineLabel)
				if title == "" {
					title = path.Base(relPath)
				}
				embed := &attachmentVideoEmbed{
					Title:        title,
					ThumbnailURL: thumbURL,
					OriginalURL:  inlineURL,
				}
				if !ok {
					embed.ThumbnailURL = ""
					embed.FallbackMessage = "Video preview unavailable."
				}
				embeds = append(embeds, embed)
				remove = append(remove, child)
			}
			if len(embeds) == 0 {
				continue
			}
			for _, node := range remove {
				para.RemoveChild(para, node)
			}
			parent := para.Parent()
			if parent == nil {
				continue
			}
			if !paragraphHasVisibleContent(para, source) {
				first := embeds[0]
				replaceBlockWithEmbed(parent, para, first)
				cursor := first
				for i := 1; i < len(embeds); i++ {
					parent.InsertAfter(parent, cursor, embeds[i])
					cursor = embeds[i]
				}
				continue
			}
			cursor := ast.Node(para)
			for _, embed := range embeds {
				parent.InsertAfter(parent, cursor, embed)
				cursor = embed
			}
			continue
		}
		noteID, relPath, ok := attachmentVideoFromURL(urlText)
		if !ok {
			continue
		}
		thumbURL, ok := srv.ensureVideoThumbnail(ctx, noteID, relPath)
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
		replaceBlockWithEmbed(parent, para, embed)
	}
}

func replaceBlockWithEmbed(parent ast.Node, block ast.Node, embed ast.Node) {
	if parent == nil {
		return
	}
	if checkbox := taskCheckboxClone(block); checkbox != nil {
		placeholder := ast.NewParagraph()
		placeholder.AppendChild(placeholder, checkbox)
		parent.ReplaceChild(parent, block, placeholder)
		parent.InsertAfter(parent, placeholder, embed)
		return
	}
	parent.ReplaceChild(parent, block, embed)
}

func taskCheckboxClone(block ast.Node) *extensionast.TaskCheckBox {
	for child := block.FirstChild(); child != nil; child = child.NextSibling() {
		if checkbox, ok := child.(*extensionast.TaskCheckBox); ok {
			return extensionast.NewTaskCheckBox(checkbox.IsChecked)
		}
	}
	return nil
}

func blockHasTaskCheckbox(block ast.Node) bool {
	for child := block.FirstChild(); child != nil; child = child.NextSibling() {
		if _, ok := child.(*extensionast.TaskCheckBox); ok {
			return true
		}
	}
	return false
}

func isTaskMarkerText(text string) bool {
	switch strings.TrimSpace(text) {
	case "[ ]", "[x]", "[X]":
		return true
	default:
		return false
	}
}

func filterFutureJournalTasks(tasks []index.TaskItem, now time.Time) []index.TaskItem {
	if len(tasks) == 0 {
		return tasks
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	filtered := make([]index.TaskItem, 0, len(tasks))
	for _, task := range tasks {
		taskPath := task.Path
		if _, rel, err := fs.SplitOwnerNotePath(task.Path); err == nil {
			taskPath = rel
		}
		if !journalNoteRE.MatchString(taskPath) {
			filtered = append(filtered, task)
			continue
		}
		trimmed := strings.TrimSuffix(taskPath, ".md")
		parts := strings.Split(trimmed, "/")
		if len(parts) != 2 {
			filtered = append(filtered, task)
			continue
		}
		dateStr := parts[0] + "-" + parts[1]
		date, err := time.ParseInLocation("2006-01-02", dateStr, now.Location())
		if err != nil {
			filtered = append(filtered, task)
			continue
		}
		if date.After(today) {
			continue
		}
		filtered = append(filtered, task)
	}
	return filtered
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
			if label, ok := linkLabelText(node, source); ok && strings.TrimSpace(label) != "" {
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

func linkLabelText(link *ast.Link, source []byte) (string, bool) {
	var b strings.Builder
	for child := link.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Text:
			b.Write(node.Segment.Value(source))
		case *ast.String:
			b.Write(node.Value)
		default:
			return "", false
		}
	}
	text := strings.TrimSpace(b.String())
	if text == "" {
		return "", false
	}
	return text, true
}

func replaceLinkLabel(link *ast.Link, title string) {
	for child := link.FirstChild(); child != nil; {
		next := child.NextSibling()
		link.RemoveChild(link, child)
		child = next
	}
	link.AppendChild(link, ast.NewString([]byte(title)))
}

func isExternalHTTPURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func isIPHost(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return false
	}
	return net.ParseIP(host) != nil
}

func isIgnoredLinkTitle(title string) bool {
	lower := strings.ToLower(strings.TrimSpace(title))
	if lower == "" {
		return true
	}
	return strings.HasPrefix(lower, "login") ||
		strings.HasPrefix(lower, "sign in") ||
		strings.HasPrefix(lower, "sign-in")
}

var metaTagRegexp = regexp.MustCompile(`(?is)<meta\s+[^>]*>`)
var metaAttrRegexp = regexp.MustCompile(`(?i)([a-zA-Z:-]+)\s*=\s*["']([^"']+)["']`)
var titleTagRegexp = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractMetaContent(htmlStr string, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return ""
	}
	for _, tag := range metaTagRegexp.FindAllString(htmlStr, -1) {
		var name string
		var content string
		for _, match := range metaAttrRegexp.FindAllStringSubmatch(tag, -1) {
			if len(match) != 3 {
				continue
			}
			attrName := strings.ToLower(strings.TrimSpace(match[1]))
			attrValue := strings.TrimSpace(match[2])
			switch attrName {
			case "property", "name":
				name = strings.ToLower(attrValue)
			case "content":
				content = attrValue
			}
		}
		if name == key && content != "" {
			return html.UnescapeString(content)
		}
	}
	return ""
}

func extractTitleTag(htmlStr string) string {
	match := titleTagRegexp.FindStringSubmatch(htmlStr)
	if len(match) < 2 {
		return ""
	}
	return html.UnescapeString(strings.TrimSpace(match[1]))
}

func isEmbedParagraphParent(parent ast.Node) bool {
	switch parent.(type) {
	case *ast.Document, *ast.ListItem:
		return true
	default:
		return false
	}
}

func blockOnlyURL(block ast.Node, source []byte) (string, bool) {
	hasTask := blockHasTaskCheckbox(block)
	var b strings.Builder
	hasLink := false
	hasURLText := false
	for child := block.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *extensionast.TaskCheckBox:
			continue
		case *ast.Link:
			if label, ok := linkLabelText(node, source); ok && strings.TrimSpace(label) != "" {
				return "", false
			}
			if hasLink || hasURLText {
				return "", false
			}
			hasLink = true
			b.Reset()
			b.WriteString(strings.TrimSpace(string(node.Destination)))
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", false
			}
			if hasLink || hasURLText {
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
			if hasTask && isTaskMarkerText(text) {
				continue
			}
			if hasLink {
				if textMatchesURL(text, b.String()) {
					continue
				}
				return "", false
			}
			if !linkifyURLRegexp.MatchString(text) {
				return "", false
			}
			if hasURLText {
				return "", false
			}
			hasURLText = true
			b.Reset()
			b.WriteString(text)
		case *ast.String:
			text := strings.TrimSpace(string(node.Value))
			if text == "" {
				continue
			}
			if hasTask && isTaskMarkerText(text) {
				continue
			}
			if hasLink {
				if textMatchesURL(text, b.String()) {
					continue
				}
				return "", false
			}
			if !linkifyURLRegexp.MatchString(text) {
				return "", false
			}
			if hasURLText {
				return "", false
			}
			hasURLText = true
			b.Reset()
			b.WriteString(text)
		default:
			return "", false
		}
	}
	value := strings.TrimSpace(string(b.String()))
	if value == "" || (!hasLink && !hasURLText) {
		return "", false
	}
	return strings.Trim(value, "<>"), true
}

func blockSingleLinkWithText(block ast.Node, source []byte) (string, bool, bool, ast.Node, bool) {
	hasTask := blockHasTaskCheckbox(block)
	var (
		foundLink     bool
		urlText       string
		linkNode      ast.Node
		hasTextBefore bool
		hasTextAfter  bool
	)
	for child := block.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *extensionast.TaskCheckBox:
			continue
		case *ast.Link:
			if foundLink {
				return "", false, false, nil, false
			}
			if label, ok := linkLabelText(node, source); ok && strings.TrimSpace(label) != "" {
				return "", false, false, nil, false
			}
			foundLink = true
			urlText = strings.TrimSpace(string(node.Destination))
			linkNode = node
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", false, false, nil, false
			}
			if foundLink {
				return "", false, false, nil, false
			}
			foundLink = true
			urlText = strings.TrimSpace(string(node.URL(source)))
			linkNode = node
		case *ast.Text:
			text := strings.TrimSpace(string(node.Segment.Value(source)))
			if text == "" {
				continue
			}
			if hasTask && isTaskMarkerText(text) {
				continue
			}
			if !foundLink {
				hasTextBefore = true
				continue
			}
			hasTextAfter = true
		case *ast.String:
			text := strings.TrimSpace(string(node.Value))
			if text == "" {
				continue
			}
			if hasTask && isTaskMarkerText(text) {
				continue
			}
			if !foundLink {
				hasTextBefore = true
				continue
			}
			hasTextAfter = true
		default:
			return "", false, false, nil, false
		}
	}
	if !foundLink || strings.TrimSpace(urlText) == "" || (!hasTextBefore && !hasTextAfter) {
		return "", false, false, nil, false
	}
	return strings.Trim(urlText, "<>"), hasTextBefore, hasTextAfter, linkNode, true
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

func paragraphOnlyMedia(para *ast.Paragraph, source []byte) (string, string, ast.Node, bool) {
	var (
		foundNode ast.Node
		urlText   string
	)
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Link:
			if foundNode != nil {
				return "", "", nil, false
			}
			foundNode = node
			urlText = strings.TrimSpace(string(node.Destination))
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", "", nil, false
			}
			if foundNode != nil {
				return "", "", nil, false
			}
			foundNode = node
			urlText = strings.TrimSpace(string(node.URL(source)))
		case *ast.Image:
			if foundNode != nil {
				return "", "", nil, false
			}
			foundNode = node
			urlText = strings.TrimSpace(string(node.Destination))
		case *ast.Text:
			if strings.TrimSpace(string(node.Segment.Value(source))) == "" {
				continue
			}
			return "", "", nil, false
		default:
			return "", "", nil, false
		}
	}
	if foundNode == nil || urlText == "" {
		return "", "", nil, false
	}
	label := ""
	switch node := foundNode.(type) {
	case *ast.Link:
		label = extractTextFromNode(node, source)
	case *ast.Image:
		label = extractTextFromNode(node, source)
		if label == "" {
			label = strings.TrimSpace(string(node.Title))
		}
	}
	if label == "" {
		label = urlText
	}
	return strings.Trim(urlText, "<>"), label, foundNode, true
}

func inlineMediaURL(node ast.Node, source []byte) (string, string, bool) {
	var (
		urlText string
		label   string
	)
	switch typed := node.(type) {
	case *ast.Link:
		urlText = strings.TrimSpace(string(typed.Destination))
		label = extractTextFromNode(typed, source)
	case *ast.AutoLink:
		if typed.AutoLinkType != ast.AutoLinkURL {
			return "", "", false
		}
		urlText = strings.TrimSpace(string(typed.URL(source)))
		label = urlText
	case *ast.Image:
		urlText = strings.TrimSpace(string(typed.Destination))
		label = extractTextFromNode(typed, source)
		if label == "" {
			label = strings.TrimSpace(string(typed.Title))
		}
	default:
		return "", "", false
	}
	if urlText == "" {
		return "", "", false
	}
	if label == "" {
		label = urlText
	}
	return strings.Trim(urlText, "<>"), label, true
}

func paragraphHasVisibleContent(para *ast.Paragraph, source []byte) bool {
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Text:
			if strings.TrimSpace(string(node.Segment.Value(source))) != "" {
				return true
			}
		default:
			return true
		}
	}
	return false
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

type chatgptEmbedHTMLRenderer struct{}

func newChatGPTEmbedHTMLRenderer() renderer.NodeRenderer {
	return &chatgptEmbedHTMLRenderer{}
}

func (r *chatgptEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(chatgptEmbedKind, r.renderChatGPTEmbed)
}

func (r *chatgptEmbedHTMLRenderer) renderChatGPTEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*chatgptEmbed)
	if n.OriginalURL != "" && n.Title != "" {
		title := html.EscapeString(n.Title)
		preview := html.EscapeString(n.Preview)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="chatgpt-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="chatgpt-card__meta">`)
		_, _ = w.WriteString(`<div class="chatgpt-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		if preview != "" {
			_, _ = w.WriteString(`<div class="chatgpt-card__preview">`)
			_, _ = w.WriteString(preview)
			_, _ = w.WriteString(`</div>`)
		}
		_, _ = w.WriteString(`<div class="chatgpt-card__host">chatgpt.com</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="chatgpt-card chatgpt-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open on ChatGPT</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type whatsappLinkHTMLRenderer struct{}

func newWhatsAppLinkHTMLRenderer() renderer.NodeRenderer {
	return &whatsappLinkHTMLRenderer{}
}

func (r *whatsappLinkHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(whatsappLinkKind, r.renderWhatsAppLink)
}

func (r *whatsappLinkHTMLRenderer) renderWhatsAppLink(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*whatsappLink)
	if n.OriginalURL == "" || n.Number == "" {
		return ast.WalkContinue, nil
	}
	url := html.EscapeString(n.OriginalURL)
	number := html.EscapeString(n.Number)
	_, _ = w.WriteString(`<a class="whatsapp-link" href="`)
	_, _ = w.WriteString(url)
	_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
	_, _ = w.WriteString(`<span class="whatsapp-link__icon" aria-hidden="true">`)
	_, _ = w.WriteString(`<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6">`)
	_, _ = w.WriteString(`<path d="M20.3 12.1c0 4.5-3.7 8.2-8.2 8.2-1.4 0-2.7-.4-3.9-1l-4.5 1.2 1.2-4.4c-.7-1.2-1.1-2.6-1.1-4 0-4.5 3.7-8.2 8.2-8.2 4.5 0 8.3 3.7 8.3 8.2z"/>`)
	_, _ = w.WriteString(`<path d="M9.3 7.7c-.2-.4-.4-.4-.6-.4h-.6c-.2 0-.5.1-.7.4-.3.3-.9.9-.9 2.2 0 1.3 1 2.5 1.1 2.7.1.2 2 3.1 4.9 4.2 2.4.9 2.9.7 3.4.7.5-.1 1.6-.7 1.8-1.3.2-.6.2-1.1.1-1.3-.1-.2-.3-.3-.7-.5-.4-.2-2.2-1.1-2.6-1.2-.3-.1-.6-.2-.8.2-.2.3-.9 1.2-1.1 1.4-.2.2-.4.3-.8.1-.4-.2-1.7-.6-3.2-1.9-1.2-1-2-2.2-2.2-2.6-.2-.4 0-.6.1-.8.2-.2.4-.4.6-.6.2-.2.3-.4.4-.6.1-.2 0-.4 0-.6-.1-.2-.7-1.9-1-2.5z"/>`)
	_, _ = w.WriteString(`</svg></span>`)
	_, _ = w.WriteString(`<span class="whatsapp-link__number">`)
	_, _ = w.WriteString(number)
	_, _ = w.WriteString(`</span></a>`)
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

func chatgptEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.TODO()
	}
	if value := pc.Get(chatgptEmbedContextKey); value != nil {
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

func linkTitleContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.TODO()
	}
	if value := pc.Get(linkTitleContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.TODO()
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

func isChatGPTShareURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	if host != "chatgpt.com" {
		return false
	}
	return strings.HasPrefix(parsed.Path, "/s/")
}

func whatsAppNumber(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	switch host {
	case "wa.me":
		number := strings.TrimSpace(strings.Trim(parsed.Path, "/"))
		if number == "" {
			return "", false
		}
		return formatWhatsAppNumber(number), true
	case "api.whatsapp.com", "chat.whatsapp.com":
		phone := strings.TrimSpace(parsed.Query().Get("phone"))
		if phone == "" {
			return "", false
		}
		return formatWhatsAppNumber(phone), true
	}
	if strings.EqualFold(parsed.Scheme, "whatsapp") {
		phone := strings.TrimSpace(parsed.Query().Get("phone"))
		if phone == "" {
			phone = strings.TrimSpace(parsed.Query().Get("number"))
		}
		if phone == "" {
			return "", false
		}
		return formatWhatsAppNumber(phone), true
	}
	return "", false
}

func formatWhatsAppNumber(raw string) string {
	var digits strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	value := digits.String()
	if value == "" {
		return raw
	}
	trimmed := strings.TrimSpace(raw)
	hasPlus := strings.HasPrefix(trimmed, "+") || strings.HasPrefix(trimmed, "00")
	if strings.HasPrefix(value, "0") {
		value = "62" + strings.TrimPrefix(value, "0")
	}
	country := "62"
	local := value
	if hasPlus {
		switch {
		case strings.HasPrefix(value, "1"):
			country = "1"
			local = strings.TrimPrefix(value, "1")
		case strings.HasPrefix(value, "7"):
			country = "7"
			local = strings.TrimPrefix(value, "7")
		case strings.HasPrefix(value, "62"):
			country = "62"
			local = strings.TrimPrefix(value, "62")
		default:
			for i := 1; i <= 3 && i <= len(value); i++ {
				country = value[:i]
				local = value[i:]
			}
		}
	} else if strings.HasPrefix(value, "62") {
		country = "62"
		local = strings.TrimPrefix(value, "62")
	} else if strings.HasPrefix(value, "1") || strings.HasPrefix(value, "7") {
		country = value[:1]
		local = value[1:]
	}
	if local == "" {
		return "+" + country
	}
	return formatIntlNumber(country, local)
}

func formatIntlNumber(country string, local string) string {
	group := local
	if len(local) > 3 {
		group = local[:3] + "-" + local[3:]
	}
	return "+" + country + " " + group
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
	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimPrefix(clean, "../")
	if !strings.HasPrefix(clean, "/attachments/") && !strings.HasPrefix(clean, "attachments/") {
		return "", "", false
	}
	rel := strings.TrimPrefix(clean, "/attachments/")
	rel = strings.TrimPrefix(rel, "attachments/")
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
	if !isVideoExtension(relPath) {
		return "", "", false
	}
	return noteID, relPath, true
}

func isVideoExtension(relPath string) bool {
	ext := strings.ToLower(path.Ext(relPath))
	if ext == "" {
		return false
	}
	if ext == ".mp4" || ext == ".webm" || ext == ".mov" || ext == ".m4v" || ext == ".mkv" || ext == ".avi" {
		return true
	}
	mimeType := mime.TypeByExtension(ext)
	return strings.HasPrefix(mimeType, "video/")
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

func lookupChatGPTEmbed(ctx context.Context, rawURL string) (chatgptEmbedStatus, string, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, chatgptEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return chatgptEmbedStatusFound, entry.ErrorMsg, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "ChatGPT preview unavailable."
				}
				return chatgptEmbedStatusFailed, "", "", message
			}
		}
	}

	if chatgptEmbedIsInFlight(rawURL) {
		return chatgptEmbedStatusPending, "", "", ""
	}
	chatgptEmbedMarkInFlight(rawURL)

	if title, preview, ok := resolveChatGPTEmbedNow(rawURL, chatgptEmbedSyncTimeout); ok {
		chatgptEmbedStoreFound(ctx, rawURL, title, preview)
		chatgptEmbedClearInFlight(rawURL)
		return chatgptEmbedStatusFound, title, preview, ""
	}

	go resolveChatGPTEmbedAsync(context.WithoutCancel(ctx), rawURL)
	return chatgptEmbedStatusPending, "", "", ""
}

func lookupLinkTitle(ctx context.Context, rawURL string) (string, bool) {
	if isIPHost(rawURL) {
		return "", false
	}
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, linkTitleCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				title := strings.TrimSpace(entry.EmbedURL)
				if title != "" {
					return title, true
				}
			}
			return "", false
		}
		if err != nil {
			slog.Debug("link title cache lookup failed", "url", rawURL, "err", err)
		}
	}

	if embedCacheStore == nil || linkTitleIsInFlight(rawURL) {
		return "", false
	}
	linkTitleMarkInFlight(rawURL)
	slog.Debug("link title fetch queued", "url", rawURL)
	go resolveLinkTitleAsync(context.WithoutCancel(ctx), rawURL)
	return "", false
}

func linkTitleIsInFlight(rawURL string) bool {
	return linkTitleInFlight.IsActive(rawURL, time.Now())
}

func linkTitleMarkInFlight(rawURL string) {
	linkTitleInFlight.Upsert(rawURL, time.Now().Add(linkTitlePendingTTL))
}

func linkTitleClearInFlight(rawURL string) {
	linkTitleInFlight.Delete(rawURL)
}

func resolveLinkTitleAsync(ctx context.Context, rawURL string) {
	title, ok := resolveLinkTitleWithClient(rawURL, linkTitleHTTPClient)
	if !ok {
		linkTitleStoreFailure(ctx, rawURL, "Link title unavailable.")
		linkTitleClearInFlight(rawURL)
		return
	}

	linkTitleStoreFound(ctx, rawURL, title)
	linkTitleClearInFlight(rawURL)
}

func resolveLinkTitleWithClient(rawURL string, client *http.Client) (string, bool) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false
	}
	htmlStr := string(body)
	title := extractMetaContent(htmlStr, "og:title")
	if title == "" {
		title = extractTitleTag(htmlStr)
	}
	title = strings.TrimSpace(title)
	if title == "" || isIgnoredLinkTitle(title) {
		return "", false
	}
	return title, true
}

func linkTitleStoreFound(ctx context.Context, rawURL string, title string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      linkTitleCacheKind,
		EmbedURL:  title,
		Status:    index.EmbedCacheStatusFound,
		UpdatedAt: now,
		ExpiresAt: now.Add(linkTitleSuccessTTL),
	}
	if err := embedCacheStore.UpsertEmbedCache(ctx, entry); err != nil {
		slog.Debug("link title cache store failed", "url", rawURL, "err", err)
		return
	}
	if touched, err := embedCacheStore.TouchNotesByLink(context.WithoutCancel(ctx), rawURL); err != nil {
		slog.Debug("link title cache touch failed", "url", rawURL, "err", err)
	} else if touched > 0 {
		slog.Debug("link title cache touch", "url", rawURL, "notes", touched)
	}
	slog.Debug("link title cached", "url", rawURL)
}

func linkTitleStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      linkTitleCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(linkTitleFailureTTL),
	}
	if err := embedCacheStore.UpsertEmbedCache(ctx, entry); err != nil {
		slog.Debug("link title cache store failed", "url", rawURL, "err", err)
		return
	}
	if touched, err := embedCacheStore.TouchNotesByLink(context.WithoutCancel(ctx), rawURL); err != nil {
		slog.Debug("link title cache touch failed", "url", rawURL, "err", err)
	} else if touched > 0 {
		slog.Debug("link title cache touch", "url", rawURL, "notes", touched)
	}
	slog.Debug("link title cache failed", "url", rawURL, "err", message)
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

func resolveChatGPTEmbedNow(rawURL string, timeout time.Duration) (string, string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveChatGPTEmbedWithClient(rawURL, client)
}

func resolveChatGPTEmbedAsync(ctx context.Context, rawURL string) {
	title, preview, ok := resolveChatGPTEmbedWithClient(rawURL, chatgptEmbedHTTPClient)
	if !ok {
		chatgptEmbedStoreFailure(ctx, rawURL, "ChatGPT preview unavailable.")
		chatgptEmbedClearInFlight(rawURL)
		return
	}

	chatgptEmbedStoreFound(ctx, rawURL, title, preview)
	chatgptEmbedClearInFlight(rawURL)
}

func resolveChatGPTEmbedWithClient(rawURL string, client *http.Client) (string, string, bool) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", false
	}
	htmlStr := string(body)
	title := extractMetaContent(htmlStr, "og:title")
	if title == "" {
		title = extractTitleTag(htmlStr)
	}
	preview := extractMetaContent(htmlStr, "og:description")
	if preview == "" {
		preview = extractMetaContent(htmlStr, "description")
	}
	title = strings.TrimSpace(title)
	preview = strings.TrimSpace(preview)
	if title == "" {
		return "", "", false
	}
	return title, preview, true
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

func chatgptEmbedIsInFlight(rawURL string) bool {
	return chatgptEmbedInFlight.IsActive(rawURL, time.Now())
}

func chatgptEmbedMarkInFlight(rawURL string) {
	chatgptEmbedInFlight.Upsert(rawURL, time.Now().Add(chatgptEmbedPendingTTL))
}

func chatgptEmbedClearInFlight(rawURL string) {
	chatgptEmbedInFlight.Delete(rawURL)
}

func chatgptEmbedStoreFound(ctx context.Context, rawURL string, title string, preview string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      chatgptEmbedCacheKind,
		EmbedURL:  preview,
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  title,
		UpdatedAt: now,
		ExpiresAt: now.Add(chatgptEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func chatgptEmbedStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      chatgptEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(chatgptEmbedFailureTTL),
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

const (
	homeNotesPageSize    = 6
	homeSectionsMaxNotes = 5000
)

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		ownerName, ok := ownerHomeName(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, err := s.idx.LookupOwnerIDs(r.Context(), ownerName); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.renderHomePage(w, r, ownerName, "/"+ownerName)
		return
	}
	s.renderHomePage(w, r, "", "/")
}

func ownerHomeName(rawPath string) (string, bool) {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" || rawPath == "/" {
		return "", false
	}
	trimmed := strings.Trim(rawPath, "/")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return "", false
	}
	lowered := strings.ToLower(trimmed)
	if _, reserved := reservedOwnerPaths[lowered]; reserved {
		return "", false
	}
	return trimmed, true
}

var reservedOwnerPaths = map[string]struct{}{
	"login":       {},
	"logout":      {},
	"notes":       {},
	"daily":       {},
	"journal":     {},
	"search":      {},
	"tags":        {},
	"todo":        {},
	"settings":    {},
	"sync":        {},
	"quick":       {},
	"static":      {},
	"assets":      {},
	"attachments": {},
	"events":      {},
	"tasks":       {},
	"rebuild":     {},
	"calendar":    {},
	"broken":      {},
}

func (s *Server) renderHomePage(w http.ResponseWriter, r *http.Request, ownerName string, basePath string) {
	if maxTime, err := s.idx.MaxEtagTime(r.Context()); err == nil {
		etag := pageETag("home", currentURLString(r), maxTime, currentUserName(r.Context()))
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.Header().Set("ETag", etag)
			setPrivateCacheHeaders(w)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		setPrivateCacheHeaders(w)
	}

	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := ""
	baseURL := baseURLForLinks(r, basePath)
	activeTodo, activeDue, activeJournal, noteTags := splitSpecialTags(activeTags)
	isAuth := IsAuthenticated(r.Context())
	if !isAuth {
		activeTodo = false
		activeDue = false
		activeJournal = false
		activeTags = noteTags
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot, activeJournal, ownerName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allowed := map[string]struct{}{}
	todoCount := 0
	dueCount := 0
	if isAuth {
		todoCount, dueCount, err = s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, ownerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, ownerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		_ = dueCount
	}
	tagLinks := buildTagLinks(urlTags, tags, allowed, baseURL)
	journalCount, err := s.idx.CountJournalNotes(r.Context(), activeFolder, activeRoot, ownerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagLinks = appendJournalTagLink(tagLinks, activeJournal, journalCount, baseURL, noteTags)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot, ownerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagQuery := buildTagsQuery(urlTags)
	filterQuery := queryWithout(baseURL, "d")
	calendar := buildCalendarMonth(calendarReferenceDate(r), updateDays, baseURL, activeDate)
	priorityNotes, err := s.loadHomeSectionNotes(r.Context(), "priority", noteTags, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	todayNotes, err := s.loadHomeSectionNotes(r.Context(), "today", noteTags, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	plannedNotes := []NoteCard(nil)
	weekNotes := []NoteCard(nil)
	monthNotes := []NoteCard(nil)
	yearNotes := []NoteCard(nil)
	lastYearNotes := []NoteCard(nil)
	otherNotes := []NoteCard(nil)
	folders, hasRoot, err := s.idx.ListFolders(r.Context(), ownerName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, baseURL)
	journalSidebar, err := s.buildJournalSidebar(r.Context(), time.Now(), ownerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	title := "Home"
	if strings.TrimSpace(ownerName) != "" {
		title = ownerName
	}
	data := ViewData{
		Title:             title,
		ContentTemplate:   "home",
		HomeNotes:         nil,
		HomePriorityNotes: priorityNotes,
		HomeTodayNotes:    todayNotes,
		HomePlannedNotes:  plannedNotes,
		HomeWeekNotes:     weekNotes,
		HomeMonthNotes:    monthNotes,
		HomeYearNotes:     yearNotes,
		HomeLastYearNotes: lastYearNotes,
		HomeOtherNotes:    otherNotes,
		HomeHasMore:       false,
		NextHomeOffset:    0,
		HomeOffset:        0,
		HomeOwner:         ownerName,
		Tags:              tags,
		TagLinks:          tagLinks,
		TodoCount:         todoCount,
		DueCount:          dueCount,
		ActiveTags:        urlTags,
		TagQuery:          tagQuery,
		FolderTree:        folderTree,
		ActiveFolder:      activeFolder,
		FolderQuery:       buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:       filterQuery,
		HomeURL:           baseURL,
		ActiveDate:        activeDate,
		DateQuery:         buildDateQuery(activeDate),
		SearchQuery:       activeSearch,
		SearchQueryParam:  buildSearchQuery(activeSearch),
		UpdateDays:        updateDays,
		CalendarMonth:     calendar,
		JournalSidebar:    journalSidebar,
	}
	applyCalendarLinks(&data, baseURL)
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleDaily(w http.ResponseWriter, r *http.Request) {
	date := strings.TrimPrefix(r.URL.Path, "/daily/")
	date = strings.TrimSuffix(date, "/")
	parsedDate, err := time.Parse("2006-01-02", date)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	displayDate := parsedDate.Format("02 Jan 2006")
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

	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := ""
	calendarDate := date
	dailyBase := "/daily/" + date
	baseURL := baseURLForLinks(r, dailyBase)
	activeTodo, activeDue, activeJournal, noteTags := splitSpecialTags(activeTags)
	isAuth := IsAuthenticated(r.Context())
	if !isAuth {
		activeTodo = false
		activeDue = false
		activeJournal = false
		activeTags = noteTags
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot, activeJournal, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allowed := map[string]struct{}{}
	todoCount := 0
	dueCount := 0
	if isAuth {
		todoCount, dueCount, err = s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		_ = dueCount
	}
	notes, err := s.idx.NoteList(r.Context(), index.NoteListFilter{
		Tags:        noteTags,
		Date:        date,
		Query:       activeSearch,
		Folder:      activeFolder,
		Root:        activeRoot,
		JournalOnly: activeJournal,
		ExcludeUID:  excludeUID,
		Limit:       200,
		Offset:      0,
	})
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
	tagLinks := buildTagLinks(urlTags, tags, allowed, baseURL)
	journalCount, err := s.idx.CountJournalNotes(r.Context(), activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagLinks = appendJournalTagLink(tagLinks, activeJournal, journalCount, baseURL, noteTags)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagQuery := buildTagsQuery(urlTags)
	filterQuery := queryWithout(baseURL, "d")
	calendar := buildCalendarMonth(parsedDate, updateDays, baseURL, calendarDate)
	folders, hasRoot, err := s.idx.ListFolders(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, baseURL)
	journalSidebar, err := s.buildJournalSidebar(r.Context(), parsedDate, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{
		Title:            "Daily",
		ContentTemplate:  "daily",
		DailyDate:        displayDate,
		DailyJournal:     journalCard,
		DailyNotes:       noteCards,
		Tags:             tags,
		TagLinks:         tagLinks,
		TodoCount:        todoCount,
		DueCount:         dueCount,
		ActiveTags:       urlTags,
		TagQuery:         tagQuery,
		FolderTree:       folderTree,
		ActiveFolder:     activeFolder,
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      filterQuery,
		HomeURL:          baseURL,
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
		UpdateDays:       updateDays,
		CalendarMonth:    calendar,
		JournalSidebar:   journalSidebar,
	}
	applyCalendarLinks(&data, baseURL)
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
		returnTo := sanitizeReturnURL(r, r.URL.Query().Get("return_to"))
		data := ViewData{
			Title:           "Login",
			ContentTemplate: "login",
			ReturnURL:       returnTo,
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
	returnTo := sanitizeReturnURL(r, r.FormValue("return_to"))
	if user == "" || pass == "" {
		data := ViewData{
			Title:           "Login",
			ContentTemplate: "login",
			ErrorMessage:    "username and password required",
			ReturnURL:       returnTo,
		}
		s.attachViewData(r, &data)
		s.views.RenderPage(w, data)
		return
	}
	if err := s.refreshAuthSources(r.Context()); err != nil {
		slog.Warn("refresh auth sources", "err", err)
		data := ViewData{
			Title:           "Login",
			ContentTemplate: "login",
			ErrorMessage:    "failed to refresh auth sources",
			ReturnURL:       returnTo,
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
			ReturnURL:       returnTo,
		}
		s.attachViewData(r, &data)
		s.views.RenderPage(w, data)
		return
	}
	if s.auth.IsExpired(user, time.Now()) {
		returnTo = "/password/change"
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
	if returnTo == "" {
		returnTo = "/"
	}
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", returnTo)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		http.NotFound(w, r)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	userName := currentUserName(r.Context())
	if userName == "" {
		http.Error(w, "user required", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet {
		returnTo := sanitizeReturnURL(r, r.URL.Query().Get("return_to"))
		data := ViewData{
			Title:           "Change Password",
			ContentTemplate: "change_password",
			ReturnURL:       returnTo,
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
	currentPass := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirmPass := r.FormValue("confirm_password")
	returnTo := sanitizeReturnURL(r, r.FormValue("return_to"))
	fail := func(message string) {
		s.addToast(r, Toast{
			ID:              uuid.NewString(),
			Message:         message,
			Kind:            "error",
			DurationSeconds: 6,
			CreatedAt:       time.Now(),
		})
		if isHTMX(r) {
			w.Header().Set("HX-Retarget", "#toast-stack")
			w.Header().Set("HX-Reswap", "outerHTML")
			toasts := s.toasts.List(toastKey(r))
			data := ViewData{
				ContentTemplate: "toast",
				ToastItems:      toasts,
			}
			s.attachViewData(r, &data)
			s.views.RenderTemplate(w, "toast", data)
			return
		}
		http.Redirect(w, r, "/password/change", http.StatusSeeOther)
	}
	if currentPass == "" || newPass == "" {
		fail("Current and new password required.")
		return
	}
	if newPass != confirmPass {
		fail("Password confirmation does not match.")
		return
	}
	if currentPass == newPass {
		fail("New password must differ from current password.")
		return
	}
	if !s.auth.Authenticate(userName, currentPass) {
		fail("Current password is incorrect.")
		return
	}
	if strings.TrimSpace(s.cfg.AuthFile) == "" {
		fail("Auth file not configured.")
		return
	}
	hash, err := auth.HashPassword(newPass)
	if err != nil {
		fail("Failed to hash password.")
		return
	}
	months := s.cfg.PasswordExpiryMonths
	if months <= 0 {
		months = 6
	}
	expiry := time.Now().In(time.Local).AddDate(0, months, 0).Format("2006-01-02")
	if err := updateAuthUserPassword(s.cfg.AuthFile, userName, hash, expiry); err != nil {
		fail("Failed to update password.")
		return
	}
	if s.auth != nil {
		if err := s.auth.Reload(); err != nil {
			slog.Warn("reload auth", "err", err)
		}
	}
	data := ViewData{
		Title:           "Password Updated",
		ContentTemplate: "change_password_ok",
		ReturnURL:       returnTo,
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) refreshAuthSources(ctx context.Context) error {
	if s.auth == nil {
		return nil
	}
	users := make([]string, 0)
	if s.cfg.AuthFile != "" {
		fileUsers, err := auth.LoadFile(s.cfg.AuthFile)
		if err != nil {
			return err
		}
		for user := range fileUsers {
			users = append(users, user)
		}
		slog.Debug("auth reload users from file", "count", len(users))
	}
	if s.cfg.AuthUser != "" {
		users = append(users, s.cfg.AuthUser)
	}
	accessFile, err := auth.LoadAccessFromRepo(s.cfg.RepoPath)
	if err != nil {
		return err
	}
	slog.Debug("auth reload access from repo", "count", len(accessFile))
	accessRules := make(map[string][]index.AccessPathRule, len(accessFile))
	for owner, rules := range accessFile {
		list := make([]index.AccessPathRule, 0, len(rules))
		for _, rule := range rules {
			members := make([]index.AccessMember, 0, len(rule.Members))
			for _, member := range rule.Members {
				members = append(members, index.AccessMember{User: member.User, Access: member.Access})
			}
			list = append(list, index.AccessPathRule{Path: rule.Path, Members: members})
		}
		accessRules[owner] = list
	}
	dbUsers, err := s.idx.ListUsers(ctx)
	if err != nil {
		return err
	}
	slog.Debug("auth reload users from db", "count", len(dbUsers))
	if err := s.auth.ReloadWithExtra(dbUsers); err != nil {
		return err
	}
	ownerStats, accessStats, err := s.idx.SyncAuthSources(ctx, users, accessRules)
	if err != nil {
		return err
	}
	slog.Debug(
		"auth reload sync owners",
		"users_in_file", ownerStats.UsersInFile,
		"users_added", ownerStats.UsersAdded,
		"users_updated", ownerStats.UsersUpdated,
	)
	slog.Debug(
		"auth reload sync access",
		"owners_in_file", accessStats.OwnersInFile,
		"paths_in_file", accessStats.PathsInFile,
		"grants_added", accessStats.GrantsAdded,
		"grants_updated", accessStats.GrantsUpdated,
		"grants_removed", accessStats.GrantsRemoved,
	)
	return nil
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
	_, shortTokens := splitSearchTokens(query)
	ftsQuery := ftsPrefixQuery(query)
	var results []index.SearchResult
	if ftsQuery != "" {
		var err error
		results, err = s.idx.SearchWithShortTokens(r.Context(), ftsQuery, shortTokens, 50)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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

	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := ""
	activeDate := ""
	baseURL := baseURLForLinks(r, "/")
	activeTodo, activeDue, activeJournal, noteTags := splitSpecialTags(activeTags)
	isAuth := IsAuthenticated(r.Context())
	if !isAuth {
		activeTodo = false
		activeDue = false
		activeJournal = false
		activeTags = noteTags
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot, activeJournal, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allowed := map[string]struct{}{}
	todoCount := 0
	dueCount := 0
	if isAuth {
		todoCount, dueCount, err = s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
	}
	tagLinks := buildTagLinks(urlTags, tags, allowed, baseURL)
	journalCount, err := s.idx.CountJournalNotes(r.Context(), activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagLinks = appendJournalTagLink(tagLinks, activeJournal, journalCount, baseURL, noteTags)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagQuery := buildTagsQuery(urlTags)
	filterQuery := queryWithout(baseURL, "d")
	calendar := buildCalendarMonth(calendarReferenceDate(r), updateDays, baseURL, activeDate)
	folders, hasRoot, err := s.idx.ListFolders(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, baseURL)
	journalSidebar, err := s.buildJournalSidebar(r.Context(), time.Now(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data.Title = "Search"
	data.ContentTemplate = "search"
	data.Tags = tags
	data.TagLinks = tagLinks
	data.TodoCount = todoCount
	data.DueCount = dueCount
	data.ActiveTags = urlTags
	data.TagQuery = tagQuery
	data.FolderTree = folderTree
	data.ActiveFolder = activeFolder
	data.FolderQuery = buildFolderQuery(activeFolder, activeRoot)
	data.FilterQuery = filterQuery
	data.HomeURL = baseURL
	data.ActiveDate = activeDate
	data.DateQuery = buildDateQuery(activeDate)
	data.SearchQueryParam = buildSearchQuery(activeSearch)
	data.UpdateDays = updateDays
	data.CalendarMonth = calendar
	data.JournalSidebar = journalSidebar
	applyCalendarLinks(&data, baseURL)
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
	tags, err := s.idx.ListTags(r.Context(), 200, "", false, false, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	queryLower := strings.ToLower(query)
	queryNormalized := normalizeFuzzyTerm(queryLower)
	const maxSuggestions = 10
	suggestions := make([]string, 0, maxSuggestions)
	seen := map[string]struct{}{}
	for _, tag := range tags {
		if _, ok := seen[tag.Name]; ok {
			continue
		}
		nameLower := strings.ToLower(tag.Name)
		if !fuzzyMatchTag(queryNormalized, nameLower) {
			continue
		}
		seen[tag.Name] = struct{}{}
		suggestions = append(suggestions, tag.Name)
		if len(suggestions) >= maxSuggestions {
			break
		}
	}
	if len(suggestions) < maxSuggestions {
		journalLower := strings.ToLower(journalTagName)
		if _, ok := seen[journalTagName]; !ok && fuzzyMatchTag(queryNormalized, journalLower) {
			suggestions = append(suggestions, journalTagName)
		}
	}
	s.views.RenderTemplate(w, "tag_suggest", ViewData{TagSuggestions: suggestions})
}

func (s *Server) handleQuickNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		s.views.RenderTemplate(w, "quick_notes", ViewData{})
		return
	}
	ftsQuery := ftsPrefixQuery(query)
	if ftsQuery == "" {
		ftsQuery = query
	}
	results, err := s.idx.Search(r.Context(), ftsQuery, 10)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	matches := make([]index.NoteSummary, 0, len(results))
	for _, result := range results {
		matches = append(matches, index.NoteSummary{
			Path:  result.Path,
			Title: result.Title,
		})
	}
	s.views.RenderTemplate(w, "quick_notes", ViewData{RecentNotes: matches})
}

func (s *Server) handleQuickLauncher(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	uriRaw := strings.TrimSpace(r.URL.Query().Get("uri"))
	var currentURL *url.URL
	if uriRaw != "" {
		if parsed, err := url.Parse(uriRaw); err == nil {
			currentURL = parsed
		}
	}
	entries, err := s.quickLauncherEntries(r, query, currentURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{QuickEntries: entries}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "quick_launcher_entries", data)
}

func (s *Server) handleQuickEditActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	entries, err := s.quickEditActionsEntries(r, query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{QuickEntries: entries}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "note_edit_actions_entries", data)
}

func normalizeFuzzyTerm(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func splitSearchTokens(raw string) ([]string, []string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Fields(raw)
	longTokens := make([]string, 0, len(parts))
	shortTokens := make([]string, 0, len(parts))
	for _, part := range parts {
		var b strings.Builder
		for _, r := range part {
			switch {
			case r >= 'a' && r <= 'z':
				b.WriteRune(r)
			case r >= 'A' && r <= 'Z':
				b.WriteRune(r + ('a' - 'A'))
			case r >= '0' && r <= '9':
				b.WriteRune(r)
			}
		}
		token := b.String()
		if token == "" {
			continue
		}
		if len(token) < 3 {
			shortTokens = append(shortTokens, token)
			continue
		}
		longTokens = append(longTokens, token)
	}
	return longTokens, shortTokens
}

func ftsPrefixQuery(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	longTokens, _ := splitSearchTokens(raw)
	tokens := make([]string, 0, len(longTokens))
	for _, token := range longTokens {
		tokens = append(tokens, token+"*")
	}
	if len(tokens) == 0 {
		return ""
	}
	return strings.Join(tokens, " AND ")
}

func (s *Server) quickLauncherEntries(r *http.Request, query string, currentURL *url.URL) ([]QuickLauncherEntry, error) {
	query = strings.TrimSpace(query)
	longTokens, shortTokens := splitSearchTokens(query)
	normalized := normalizeFuzzyTerm(strings.ToLower(query))
	isAuth := IsAuthenticated(r.Context())
	authEnabled := s.auth != nil
	if currentURL == nil {
		currentURL = quickLauncherURL(r)
	}
	basePath, _, _, _, _, _ := quickLauncherContext(currentURL)
	notePath, hasNote := quickLauncherNotePath(basePath)

	actions := []QuickLauncherEntry{}
	contextActions := []QuickLauncherEntry{}
	addAction := func(target *[]QuickLauncherEntry, entry QuickLauncherEntry) {
		if entry.Hidden {
			*target = append(*target, entry)
			return
		}
		if query == "" {
			*target = append(*target, entry)
			return
		}
		if fuzzyMatchAction(normalized, entry.Label, entry.Hint) {
			*target = append(*target, entry)
		}
	}

	if authEnabled && !isAuth {
		addAction(&actions, QuickLauncherEntry{
			ID:     "quick-launcher-create-note",
			Kind:   "action",
			Label:  "Create note",
			Hint:   "New",
			Icon:   "+",
			Action: "wiki-create",
			Href:   "#",
			Hidden: true,
		})
		addAction(&actions, QuickLauncherEntry{
			Kind:  "action",
			Label: "Login",
			Hint:  "Session",
			Icon:  "I",
			Href:  "/login",
		})
	} else {
		addAction(&actions, QuickLauncherEntry{
			ID:     "quick-launcher-create-note",
			Kind:   "action",
			Label:  "Create note",
			Hint:   "New",
			Icon:   "+",
			Action: "wiki-create",
			Href:   "#",
			Hidden: true,
		})
		addAction(&actions, QuickLauncherEntry{Kind: "action", Label: "New note", Hint: "Create", Icon: "+", Href: "/notes/new"})
		addAction(&actions, QuickLauncherEntry{Kind: "action", Label: "Home", Hint: "Index", Icon: "H", Href: "/"})
		addAction(&actions, QuickLauncherEntry{Kind: "action", Label: "Todo", Hint: "Tasks", Icon: "T", Href: "/todo"})
		addAction(&contextActions, QuickLauncherEntry{Kind: "action", Label: "Search", Hint: "Find", Icon: "F", Href: "/search"})
		addAction(&contextActions, QuickLauncherEntry{Kind: "action", Label: "Sync", Hint: "Git", Icon: "G", Href: "/sync"})
		addAction(&contextActions, QuickLauncherEntry{Kind: "action", Label: "Settings", Hint: "Config", Icon: "S", Href: "/settings"})
		addAction(&contextActions, QuickLauncherEntry{Kind: "action", Label: "Broken links", Hint: "Fix", Icon: "B", Href: "/broken"})
		addAction(&contextActions, QuickLauncherEntry{Kind: "action", Label: "Scroll to top", Hint: "Jump", Icon: "T", Href: "#top", Action: "scroll-top"})
		if isAuth && hasNote {
			addAction(&actions, QuickLauncherEntry{Kind: "action", Label: "Edit", Hint: "Modify", Icon: "E", Href: "/notes/" + notePath + "/edit"})
			addAction(&actions, QuickLauncherEntry{ID: "quick-action-delete", Kind: "form", Label: "Delete", Hint: "Remove", Icon: "D", Href: "/notes/" + notePath + "/delete"})
		}
		if authEnabled {
			addAction(&actions, QuickLauncherEntry{Kind: "action", Label: "Logout", Hint: "Session", Icon: "L", Href: "/logout"})
		}
	}

	if query == "" {
		return actions, nil
	}

	entries := make([]QuickLauncherEntry, 0, len(actions)+len(contextActions)+20)
	entries = append(entries, actions...)
	entries = append(entries, contextActions...)

	tags, err := s.idx.ListTags(r.Context(), 200, "", false, false, "")
	if err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if !fuzzyMatchTag(normalized, strings.ToLower(tag.Name)) {
			continue
		}
		tagHref := toggleTagURL(currentURL.String(), tag.Name)
		entries = append(entries, QuickLauncherEntry{
			Kind:  "tag",
			Label: "#" + tag.Name,
			Hint:  "Tag",
			Icon:  "#",
			Href:  tagHref,
			Tag:   tag.Name,
		})
	}
	journalLower := strings.ToLower(journalTagName)
	if fuzzyMatchTag(normalized, journalLower) {
		tagHref := toggleTagURL(currentURL.String(), journalTagName)
		entries = append(entries, QuickLauncherEntry{
			Kind:  "tag",
			Label: "#" + journalTagName,
			Hint:  "Tag",
			Icon:  "#",
			Href:  tagHref,
			Tag:   journalTagName,
		})
	}

	folders, _, err := s.idx.ListFolders(r.Context(), "")
	if err != nil {
		return nil, err
	}
	for _, folder := range folders {
		if strings.TrimSpace(folder) == "" {
			continue
		}
		if !fuzzyMatchTag(normalized, strings.ToLower(folder)) {
			continue
		}
		folderHref := setFolderURL(currentURL.String(), folder, false)
		entries = append(entries, QuickLauncherEntry{
			Kind:  "folder",
			Label: folder,
			Hint:  "Folder",
			Icon:  "F",
			Href:  folderHref,
		})
	}

	if len(longTokens) > 0 {
		ftsQuery := ftsPrefixQuery(query)
		if ftsQuery == "" {
			ftsQuery = query
		}
		notes, err := s.idx.SearchWithShortTokens(r.Context(), ftsQuery, shortTokens, 12)
		if err != nil {
			return nil, err
		}
		for _, note := range notes {
			label := note.Title
			if label == "" {
				label = note.Path
			}
			entries = append(entries, QuickLauncherEntry{
				Kind:      "note",
				Label:     label,
				Hint:      note.Path,
				Icon:      "N",
				Href:      "/notes/" + note.Path,
				NotePath:  note.Path,
				NoteTitle: note.Title,
			})
		}
	}
	return entries, nil
}

func (s *Server) quickEditActionsEntries(r *http.Request, query string) ([]QuickLauncherEntry, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, nil
	}
	tagQuery := strings.TrimPrefix(query, "#")
	normalized := normalizeFuzzyTerm(strings.ToLower(tagQuery))
	ftsQuerySource := query
	if strings.HasPrefix(query, "#") {
		ftsQuerySource = ""
	}
	longTokens, shortTokens := splitSearchTokens(ftsQuerySource)
	entries := make([]QuickLauncherEntry, 0, 32)

	actionEntries := []QuickLauncherEntry{
		{Kind: "action", Label: "Tomorrow", Hint: "+1 day", Icon: "1", Action: "tomorrow"},
		{Kind: "action", Label: "Next week", Hint: "+7 days", Icon: "7", Action: "next-week"},
		{Kind: "action", Label: "Next month", Hint: "+1 month", Icon: "M", Action: "next-month"},
	}
	for _, entry := range actionEntries {
		if fuzzyMatchAction(normalized, entry.Label, entry.Hint) {
			entries = append(entries, entry)
		}
	}

	tags, err := s.idx.ListTags(r.Context(), 200, "", false, false, "")
	if err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if !fuzzyMatchTag(normalized, strings.ToLower(tag.Name)) {
			continue
		}
		entries = append(entries, QuickLauncherEntry{
			Kind:  "tag",
			Label: "#" + tag.Name,
			Hint:  "Tag",
			Icon:  "#",
			Tag:   tag.Name,
		})
	}
	journalLower := strings.ToLower(journalTagName)
	if fuzzyMatchTag(normalized, journalLower) {
		entries = append(entries, QuickLauncherEntry{
			Kind:  "tag",
			Label: "#" + journalTagName,
			Hint:  "Tag",
			Icon:  "#",
			Tag:   journalTagName,
		})
	}

	if len(longTokens) == 0 {
		return entries, nil
	}

	ftsQuery := ftsPrefixQuery(ftsQuerySource)
	if ftsQuery == "" {
		ftsQuery = ftsQuerySource
	}
	notes, err := s.idx.SearchWithShortTokens(r.Context(), ftsQuery, shortTokens, 12)
	if err != nil {
		return nil, err
	}
	for _, note := range notes {
		label := note.Title
		if label == "" {
			label = note.Path
		}
		entries = append(entries, QuickLauncherEntry{
			Kind:      "note",
			Label:     label,
			Hint:      note.Path,
			Icon:      "N",
			NotePath:  note.Path,
			NoteTitle: note.Title,
		})
	}
	return entries, nil
}

func fuzzyMatchAction(term string, label string, hint string) bool {
	if term == "" {
		return true
	}
	candidate := strings.ToLower(strings.TrimSpace(label + " " + hint))
	candidateNormalized := normalizeFuzzyTerm(candidate)
	if fuzzySubsequence(term, candidateNormalized) {
		return true
	}
	return strings.Contains(candidate, term)
}

func quickLauncherURL(r *http.Request) *url.URL {
	if r == nil {
		return &url.URL{Path: "/"}
	}
	if isHTMX(r) {
		raw := strings.TrimSpace(r.Header.Get("HX-Current-URL"))
		if raw == "" {
			raw = strings.TrimSpace(r.Referer())
		}
		if raw != "" {
			if parsed, err := url.Parse(raw); err == nil {
				return parsed
			}
		}
	}
	return r.URL
}

func quickLauncherContext(parsed *url.URL) (string, []string, string, string, string, bool) {
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	query := parsed.Query()
	activeTags := parseTagsParam(query.Get("t"))
	activeFolder, activeRoot := parseFolderParam(query.Get("f"))
	activeSearch := strings.TrimSpace(query.Get("s"))
	activeDate := strings.TrimSpace(query.Get("d"))
	return path, activeTags, activeDate, activeSearch, activeFolder, activeRoot
}

func quickLauncherNotePath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/notes/") {
		return "", false
	}
	rest := strings.TrimPrefix(path, "/notes/")
	if rest == "" {
		return "", false
	}
	blocked := []string{"/edit", "/preview", "/save", "/wikilink", "/detail", "/card", "/collapsed", "/backlinks"}
	for _, suffix := range blocked {
		if strings.HasSuffix(rest, suffix) {
			return "", false
		}
	}
	return rest, true
}

func toggleTag(tags []string, target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return tags
	}
	next := make([]string, 0, len(tags)+1)
	found := false
	for _, tag := range tags {
		if tag == target {
			found = true
			continue
		}
		next = append(next, tag)
	}
	if !found {
		next = append(next, target)
	}
	return next
}

func applyRenderReplacements(input string) string {
	return replaceTaskTokens(input)
}

func replaceDueTokens(input string) string {
	return dueTokenRe.ReplaceAllStringFunc(input, func(match string) string {
		parts := dueTokenRe.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		raw := parts[1]
		if raw == "" {
			raw = parts[2]
		}
		if raw == "" {
			return match
		}
		parsed, err := time.Parse("2006-01-02", raw)
		if err != nil {
			return match
		}
		label := parsed.Format("2 Jan 2006")
		return fmt.Sprintf(`<span class="due-badge">Due %s</span>`, label)
	})
}

func replaceDoneTokens(input string) string {
	return doneTokenRe.ReplaceAllStringFunc(input, func(match string) string {
		parts := doneTokenRe.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		rawDate := parts[1]
		rawTime := parts[2]
		parsed, err := time.Parse("2006-01-02", rawDate)
		if err != nil {
			return match
		}
		label := parsed.Format("2 Jan 2006")
		return fmt.Sprintf(`<span class="due-badge">Done %s %s</span>`, label, rawTime)
	})
}

func replaceTaskTokens(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		if doneTokenRe.MatchString(line) {
			isTask := strings.Contains(line, "type=\"checkbox\"")
			isChecked := strings.Contains(line, "checked")
			if isTask && !isChecked {
				lines[i] = doneTokenRe.ReplaceAllString(line, "")
				continue
			}
			line = dueTokenRe.ReplaceAllString(line, "")
			line = replaceDoneTokens(line)
			lines[i] = line
			continue
		}
		line = replaceDueTokens(line)
		line = replaceDoneTokens(line)
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func fuzzyMatchTag(term string, candidate string) bool {
	if term == "" {
		return true
	}
	candidateNormalized := normalizeFuzzyTerm(candidate)
	if fuzzySubsequence(term, candidateNormalized) {
		return true
	}
	parts := strings.FieldsFunc(candidate, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	if len(parts) == 0 {
		return false
	}
	var initials strings.Builder
	for _, part := range parts {
		initials.WriteByte(part[0])
	}
	return fuzzySubsequence(term, initials.String())
}

func fuzzyMatchNote(term string, title string, notePath string) bool {
	if term == "" {
		return true
	}
	candidate := strings.ToLower(title + " " + notePath)
	candidateNormalized := normalizeFuzzyTerm(candidate)
	if fuzzySubsequence(term, candidateNormalized) {
		return true
	}
	return strings.Contains(candidate, term)
}

func fuzzySubsequence(term string, candidate string) bool {
	ti := 0
	for i := 0; i < len(candidate) && ti < len(term); i++ {
		if term[ti] == candidate[i] {
			ti++
		}
	}
	return ti == len(term)
}

func (s *Server) handleJournalYear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	yearStr := strings.TrimPrefix(r.URL.Path, "/journal/year/")
	yearStr = strings.TrimSuffix(yearStr, "/")
	year, err := strconv.Atoi(yearStr)
	if err != nil || year <= 0 {
		http.NotFound(w, r)
		return
	}
	dates, err := s.idx.JournalDates(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	index := buildJournalIndex(dates)
	monthsMap := index[year]
	monthKeys := make([]int, 0, len(monthsMap))
	for month := range monthsMap {
		monthKeys = append(monthKeys, int(month))
	}
	sort.Sort(sort.Reverse(sort.IntSlice(monthKeys)))
	months := make([]JournalMonthNode, 0, len(monthKeys))
	for _, monthValue := range monthKeys {
		month := time.Month(monthValue)
		months = append(months, JournalMonthNode{
			Year:  year,
			Month: int(month),
			Label: time.Date(year, month, 1, 0, 0, 0, 0, time.UTC).Format("January"),
		})
	}
	data := ViewData{
		JournalYear: JournalYearNode{
			Year:   year,
			Label:  fmt.Sprintf("%d", year),
			Months: months,
		},
		FilterQuery: buildJournalFilterQuery(r),
	}
	s.views.RenderTemplate(w, "journal_year", data)
}

func (s *Server) handleJournalMonth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	monthStr := strings.TrimPrefix(r.URL.Path, "/journal/month/")
	monthStr = strings.TrimSuffix(monthStr, "/")
	parsed, err := time.Parse("2006-01", monthStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	year, month, _ := parsed.Date()
	dates, err := s.idx.JournalDates(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	index := buildJournalIndex(dates)
	daysMap := index[year][month]
	dayKeys := make([]int, 0, len(daysMap))
	for day := range daysMap {
		dayKeys = append(dayKeys, day)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(dayKeys)))
	days := make([]JournalDay, 0, len(dayKeys))
	for _, day := range dayKeys {
		dateStr := fmt.Sprintf("%04d-%02d-%02d", year, month, day)
		days = append(days, JournalDay{
			Label: fmt.Sprintf("%02d", day),
			Date:  dateStr,
			URL:   "/daily/" + dateStr,
		})
	}
	data := ViewData{
		JournalMonth: JournalMonthNode{
			Year:  year,
			Month: int(month),
			Days:  days,
		},
		FilterQuery: buildJournalFilterQuery(r),
	}
	s.views.RenderTemplate(w, "journal_month", data)
}

func (s *Server) handleHomeNotesPage(w http.ResponseWriter, r *http.Request) {
	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	ownerName := strings.TrimSpace(r.URL.Query().Get("o"))
	if ownerName != "" {
		normalized, ok := ownerHomeName("/" + ownerName)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, err := s.idx.LookupOwnerIDs(r.Context(), normalized); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ownerName = normalized
	}
	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := ""
	basePath := "/"
	if ownerName != "" {
		basePath = "/" + ownerName
	}
	baseURL := baseURLForLinks(r, basePath)
	_, _, activeJournal, noteTags := splitSpecialTags(activeTags)
	if !IsAuthenticated(r.Context()) {
		activeJournal = false
		activeTags = noteTags
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	homeNotes, nextOffset, hasMore, err := s.loadHomeNotes(r.Context(), offset, noteTags, activeDate, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	priorityNotes, todayNotes, plannedNotes, weekNotes, monthNotes, yearNotes, lastYearNotes, otherNotes := splitHomeSections(homeNotes)
	data := ViewData{
		HomeNotes:         homeNotes,
		HomePriorityNotes: priorityNotes,
		HomeTodayNotes:    todayNotes,
		HomePlannedNotes:  plannedNotes,
		HomeWeekNotes:     weekNotes,
		HomeMonthNotes:    monthNotes,
		HomeYearNotes:     yearNotes,
		HomeLastYearNotes: lastYearNotes,
		HomeOtherNotes:    otherNotes,
		HomeHasMore:       hasMore,
		NextHomeOffset:    nextOffset,
		HomeOffset:        offset,
		HomeOwner:         ownerName,
		ActiveTags:        urlTags,
		TagQuery:          buildTagsQuery(urlTags),
		FolderQuery:       buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:       queryWithout(baseURL, "d"),
		HomeURL:           baseURL,
		ActiveDate:        activeDate,
		DateQuery:         buildDateQuery(activeDate),
		SearchQuery:       activeSearch,
		SearchQueryParam:  buildSearchQuery(activeSearch),
	}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "home_notes", data)
}

func (s *Server) handleHomeNotesSection(w http.ResponseWriter, r *http.Request) {
	section := strings.TrimSpace(r.URL.Query().Get("name"))
	if section == "" {
		http.Error(w, "missing section", http.StatusBadRequest)
		return
	}
	ownerName := strings.TrimSpace(r.URL.Query().Get("o"))
	if ownerName != "" {
		normalized, ok := ownerHomeName("/" + ownerName)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if _, err := s.idx.LookupOwnerIDs(r.Context(), normalized); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ownerName = normalized
	}
	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := ""
	basePath := "/"
	if ownerName != "" {
		basePath = "/" + ownerName
	}
	baseURL := baseURLForLinks(r, basePath)
	_, _, activeJournal, noteTags := splitSpecialTags(activeTags)
	if !IsAuthenticated(r.Context()) {
		activeJournal = false
		activeTags = noteTags
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}

	data := ViewData{
		HomeOwner:        ownerName,
		ActiveTags:       urlTags,
		TagQuery:         buildTagsQuery(urlTags),
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      queryWithout(baseURL, "d"),
		HomeURL:          baseURL,
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
		RawQuery:         queryWithout(currentURLString(r), "name"),
	}

	switch section {
	case "planned":
		plannedNotes, err := s.loadHomeSectionNotes(r.Context(), "planned", noteTags, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data.HomePlannedNotes = plannedNotes
		s.attachViewData(r, &data)
		s.views.RenderTemplate(w, "home_section_planned", data)
	case "rest":
		weekNotes, err := s.loadHomeSectionNotes(r.Context(), "week", noteTags, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		monthNotes, err := s.loadHomeSectionNotes(r.Context(), "month", noteTags, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		yearNotes, err := s.loadHomeSectionNotes(r.Context(), "year", noteTags, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		lastYearNotes, err := s.loadHomeSectionNotes(r.Context(), "lastYear", noteTags, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		otherNotes, err := s.loadHomeSectionNotes(r.Context(), "others", noteTags, activeSearch, activeFolder, activeRoot, activeJournal, ownerName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data.HomeWeekNotes = weekNotes
		data.HomeMonthNotes = monthNotes
		data.HomeYearNotes = yearNotes
		data.HomeLastYearNotes = lastYearNotes
		data.HomeOtherNotes = otherNotes
		s.attachViewData(r, &data)
		s.views.RenderTemplate(w, "home_section_rest", data)
	default:
		http.Error(w, "unknown section", http.StatusBadRequest)
	}
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
	activeDate := ""
	baseURL := baseURLForLinks(r, "/tasks")
	activeTodo, activeDue, activeJournal, noteTags := splitSpecialTags(activeTags)
	dueDate := ""
	if activeDue {
		dueDate = time.Now().Format("2006-01-02")
	}
	var tasks []index.TaskItem
	var err error
	tasks, err = s.idx.OpenTasks(r.Context(), noteTags, 300, activeDue, dueDate, activeFolder, activeRoot, activeJournal)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(tasks) > 1 {
		noteEarliest := make(map[string]time.Time, len(tasks))
		for _, task := range tasks {
			dueTime, err := time.Parse("2006-01-02", task.DueDate)
			if err != nil {
				dueTime = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
			}
			if current, ok := noteEarliest[task.Path]; !ok || dueTime.Before(current) {
				noteEarliest[task.Path] = dueTime
			}
		}
		sort.Slice(tasks, func(i, j int) bool {
			ai := noteEarliest[tasks[i].Path]
			aj := noteEarliest[tasks[j].Path]
			if !ai.Equal(aj) {
				return ai.Before(aj)
			}
			di, err := time.Parse("2006-01-02", tasks[i].DueDate)
			if err != nil {
				di = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
			}
			dj, err := time.Parse("2006-01-02", tasks[j].DueDate)
			if err != nil {
				dj = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
			}
			if !di.Equal(dj) {
				return di.Before(dj)
			}
			if tasks[i].UpdatedAt.Equal(tasks[j].UpdatedAt) {
				return tasks[i].LineNo < tasks[j].LineNo
			}
			return tasks[i].UpdatedAt.After(tasks[j].UpdatedAt)
		})
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot, activeJournal, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allowed := map[string]struct{}{}
	todoCount, dueCount, err := s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		_ = dueCount
	}
	tagLinks := buildTagLinks(urlTags, tags, allowed, baseURL)
	journalCount, err := s.idx.CountJournalNotes(r.Context(), activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagLinks = appendJournalTagLink(tagLinks, activeJournal, journalCount, baseURL, noteTags)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagQuery := buildTagsQuery(urlTags)
	filterQuery := queryWithout(baseURL, "d")
	calendar := buildCalendarMonth(calendarReferenceDate(r), updateDays, baseURL, activeDate)
	folders, hasRoot, err := s.idx.ListFolders(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, baseURL)
	journalSidebar, err := s.buildJournalSidebar(r.Context(), time.Now(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{
		Title:            "Tasks",
		ContentTemplate:  "tasks",
		OpenTasks:        tasks,
		Tags:             tags,
		TagLinks:         tagLinks,
		TodoCount:        todoCount,
		DueCount:         dueCount,
		ActiveTags:       urlTags,
		TagQuery:         tagQuery,
		FolderTree:       folderTree,
		ActiveFolder:     activeFolder,
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      filterQuery,
		HomeURL:          baseURL,
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
		UpdateDays:       updateDays,
		CalendarMonth:    calendar,
		JournalSidebar:   journalSidebar,
	}
	applyCalendarLinks(&data, baseURL)
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleTodo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if maxTime, err := s.idx.MaxEtagTime(r.Context()); err == nil {
		etag := pageETag("todo", currentURLString(r), maxTime, currentUserName(r.Context()))
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.Header().Set("ETag", etag)
			setPrivateCacheHeaders(w)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		setPrivateCacheHeaders(w)
	}
	activeTags := parseTagsParam(r.URL.Query().Get("t"))
	activeFolder, activeRoot := parseFolderParam(r.URL.Query().Get("f"))
	activeSearch := strings.TrimSpace(r.URL.Query().Get("s"))
	activeDate := ""
	baseURL := baseURLForLinks(r, "/")
	activeTodo, activeDue, activeJournal, noteTags := splitSpecialTags(activeTags)
	dueDate := ""
	if activeDue {
		dueDate = time.Now().Format("2006-01-02")
	}
	tasks, err := s.idx.OpenTasks(r.Context(), noteTags, 300, activeDue, dueDate, activeFolder, activeRoot, activeJournal)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot, activeJournal, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	allowed := map[string]struct{}{}
	todoCount, dueCount, err := s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		_ = dueCount
	}
	tagLinks := buildTagLinks(urlTags, tags, allowed, baseURL)
	journalCount, err := s.idx.CountJournalNotes(r.Context(), activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagLinks = appendJournalTagLink(tagLinks, activeJournal, journalCount, baseURL, noteTags)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tagQuery := buildTagsQuery(urlTags)
	filterQuery := queryWithout(baseURL, "d")
	calendar := buildCalendarMonth(calendarReferenceDate(r), updateDays, baseURL, activeDate)
	folders, hasRoot, err := s.idx.ListFolders(r.Context(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, baseURL)
	journalSidebar, err := s.buildJournalSidebar(r.Context(), time.Now(), "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tasksByNote := make(map[string][]index.TaskItem)
	noteTitles := make(map[string]string)
	noteUpdated := make(map[string]time.Time)
	noteEarliestDue := make(map[string]time.Time)
	for _, task := range tasks {
		dueTime, err := time.Parse("2006-01-02", task.DueDate)
		if err != nil {
			dueTime = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
		}
		tasksByNote[task.Path] = append(tasksByNote[task.Path], task)
		if _, ok := noteTitles[task.Path]; !ok {
			noteTitles[task.Path] = task.Title
			noteUpdated[task.Path] = task.UpdatedAt
			noteEarliestDue[task.Path] = dueTime
		} else if task.UpdatedAt.After(noteUpdated[task.Path]) {
			noteUpdated[task.Path] = task.UpdatedAt
			if dueTime.Before(noteEarliestDue[task.Path]) {
				noteEarliestDue[task.Path] = dueTime
			}
		} else if dueTime.Before(noteEarliestDue[task.Path]) {
			noteEarliestDue[task.Path] = dueTime
		}
	}
	todoNotes := make([]NoteCard, 0, len(tasksByNote))
	for path, noteTasks := range tasksByNote {
		sort.Slice(noteTasks, func(i, j int) bool {
			return noteTasks[i].LineNo < noteTasks[j].LineNo
		})
		fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, path)
		if err != nil {
			continue
		}
		contentBytes, err := os.ReadFile(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				_ = s.idx.RemoveNoteByPath(r.Context(), path)
			}
			continue
		}
		body := index.StripFrontmatter(normalizeLineEndings(string(contentBytes)))
		lines := strings.Split(body, "\n")
		snippet, checkboxTasks := buildTodoDebugSnippet(lines, noteTasks)
		htmlStr, err := s.renderNoteBody(r.Context(), []byte(snippet))
		if err != nil {
			slog.Warn("render todo note snippet", "path", path, "err", err)
			continue
		}
		fileID := 0
		if len(noteTasks) > 0 {
			fileID = noteTasks[0].FileID
		}
		if fileID > 0 && len(checkboxTasks) > 0 {
			htmlStr = decorateTaskCheckboxes(htmlStr, fileID, checkboxTasks)
		}
		noteMeta := index.FrontmatterAttributes(string(contentBytes))
		folderLabel := s.noteFolderLabel(r.Context(), path, noteMeta.Folder)
		todoNotes = append(todoNotes, NoteCard{
			Path:         path,
			Title:        noteTitles[path],
			FileName:     filepath.Base(path),
			RenderedHTML: template.HTML(htmlStr),
			Meta:         noteMeta,
			FolderLabel:  folderLabel,
		})
	}
	sort.Slice(todoNotes, func(i, j int) bool {
		leftDue := noteEarliestDue[todoNotes[i].Path]
		rightDue := noteEarliestDue[todoNotes[j].Path]
		if !leftDue.Equal(rightDue) {
			return leftDue.Before(rightDue)
		}
		leftUpdated := noteUpdated[todoNotes[i].Path]
		rightUpdated := noteUpdated[todoNotes[j].Path]
		if leftUpdated.Equal(rightUpdated) {
			return todoNotes[i].Title < todoNotes[j].Title
		}
		return leftUpdated.Before(rightUpdated)
	})
	data := ViewData{
		Title:            "Todo",
		ContentTemplate:  "todo",
		TodoNotes:        todoNotes,
		Tags:             tags,
		TagLinks:         tagLinks,
		TodoCount:        todoCount,
		DueCount:         dueCount,
		ActiveTags:       urlTags,
		TagQuery:         tagQuery,
		FolderTree:       folderTree,
		ActiveFolder:     activeFolder,
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      filterQuery,
		HomeURL:          baseURL,
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
		UpdateDays:       updateDays,
		CalendarMonth:    calendar,
		JournalSidebar:   journalSidebar,
	}
	applyCalendarLinks(&data, baseURL)
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func buildTodoDebugSnippet(lines []string, tasks []index.TaskItem) (string, []index.Task) {
	if len(lines) == 0 || len(tasks) == 0 {
		return "", nil
	}
	currentLine := 1
	taskIndex := 0
	var out strings.Builder
	firstBlock := true
	checkboxTasks := make([]index.Task, 0)
	for {
		for taskIndex < len(tasks) && tasks[taskIndex].LineNo < currentLine {
			taskIndex++
		}
		if taskIndex >= len(tasks) {
			break
		}
		if !firstBlock {
			out.WriteString("\n")
		}
		firstBlock = false
		currentLine = tasks[taskIndex].LineNo
		if currentLine < 1 || currentLine > len(lines) {
			taskIndex++
			currentLine++
			continue
		}
		line := lines[currentLine-1]
		if match := taskToggleLineRe.FindStringSubmatch(line); len(match) > 0 && strings.ToLower(match[2]) != "x" {
			line = taskDoneTokenRe.ReplaceAllString(line, "")
		}
		indent := countLeadingSpaces(line)
		if match := taskToggleLineRe.FindStringSubmatch(line); len(match) > 0 {
			checkboxTasks = append(checkboxTasks, index.Task{
				LineNo: currentLine,
				Hash:   index.TaskLineHash(line),
				Done:   strings.TrimSpace(match[2]) != "",
			})
		}
		out.WriteString(stripIndent(line, indent))
		out.WriteString("\n")
		currentLine++
		for currentLine <= len(lines) {
			line = lines[currentLine-1]
			if strings.TrimSpace(line) == "" {
				out.WriteString("\n")
				currentLine++
				continue
			}
			if match := taskToggleLineRe.FindStringSubmatch(line); len(match) > 0 && strings.ToLower(match[2]) != "x" {
				line = taskDoneTokenRe.ReplaceAllString(line, "")
			}
			cil := countLeadingSpaces(line)
			if cil <= indent {
				break
			}
			if match := taskToggleLineRe.FindStringSubmatch(line); len(match) > 0 {
				checkboxTasks = append(checkboxTasks, index.Task{
					LineNo: currentLine,
					Hash:   index.TaskLineHash(line),
					Done:   strings.TrimSpace(match[2]) != "",
				})
			}
			out.WriteString(stripIndent(line, indent))
			out.WriteString("\n")
			currentLine++
		}
		taskIndex++
	}
	return out.String(), checkboxTasks
}

func todoFiltersFromURL(raw string) (noteTags []string, activeDue bool, dueDate string, activeFolder string, activeRoot bool, activeJournal bool) {
	if raw == "" {
		return nil, false, "", "", false, false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, false, "", "", false, false
	}
	activeTags := parseTagsParam(parsed.Query().Get("t"))
	activeFolder, activeRoot = parseFolderParam(parsed.Query().Get("f"))
	activeTodo, activeDue, activeJournal, noteTags := splitSpecialTags(activeTags)
	_ = activeTodo
	if activeDue {
		dueDate = time.Now().Format("2006-01-02")
	}
	return noteTags, activeDue, dueDate, activeFolder, activeRoot, activeJournal
}

func countLeadingSpaces(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func stripIndent(line string, indent int) string {
	if indent <= 0 {
		return line
	}
	if len(line) <= indent {
		return ""
	}
	return line[indent:]
}

func (s *Server) handleBroken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	links, err := s.idx.BrokenLinks(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	groups := make([]BrokenLinkGroup, 0)
	var current *BrokenLinkGroup
	for _, link := range links {
		if current == nil || current.Ref != link.ToRef {
			groups = append(groups, BrokenLinkGroup{Ref: link.ToRef})
			current = &groups[len(groups)-1]
		}
		title := link.FromTitle
		if title == "" {
			title = filepath.Base(link.FromPath)
		}
		lineHTML, err := s.renderLineMarkdown(r.Context(), link.Line)
		if err != nil {
			lineHTML = template.HTML(template.HTMLEscapeString(link.Line))
		}
		current.Items = append(current.Items, BrokenLinkItem{
			FromPath:  link.FromPath,
			FromTitle: title,
			LineNo:    link.LineNo,
			LineHTML:  lineHTML,
		})
	}
	data := ViewData{
		Title:           "Broken Links",
		ContentTemplate: "broken",
		BrokenLinks:     groups,
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleRebuild(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	start := time.Now()
	scanned, updated, cleaned, err := s.idx.RebuildFromFSWithStats(r.Context(), s.cfg.RepoPath)
	duration := time.Since(start).Round(time.Millisecond).String()
	data := ViewData{
		Title:           "Rebuild Index",
		ContentTemplate: "rebuild",
		RebuildScanned:  scanned,
		RebuildUpdated:  updated,
		RebuildCleaned:  cleaned,
		RebuildDuration: duration,
	}
	if err != nil {
		data.RebuildError = err.Error()
		w.WriteHeader(http.StatusInternalServerError)
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	ownerName := currentUserName(r.Context())
	if ownerName == "" {
		http.Error(w, "owner required", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/sync/"+ownerName, http.StatusSeeOther)
}

func (s *Server) handleSyncUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if strings.HasSuffix(r.URL.Path, "/run") {
		s.handleSyncRun(w, r)
		return
	}
	ownerName, ok := syncOwnerFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "owner required", http.StatusBadRequest)
		return
	}
	if !isAdmin(r.Context()) && !strings.EqualFold(ownerName, currentUserName(r.Context())) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if _, err := s.idx.LookupOwnerIDs(r.Context(), ownerName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := ViewData{
		Title:           "Git Sync: " + ownerName,
		ContentTemplate: "sync",
		SyncPending:     true,
		SyncOwner:       ownerName,
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleSyncRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	ownerName := currentUserName(r.Context())
	if ownerName == "" {
		http.Error(w, "owner required", http.StatusBadRequest)
		return
	}
	if r.URL.Path != "/sync/run" {
		requested, ok := syncOwnerFromPath(strings.TrimSuffix(r.URL.Path, "/run"))
		if !ok {
			http.Error(w, "owner required", http.StatusBadRequest)
			return
		}
		if !isAdmin(r.Context()) && !strings.EqualFold(requested, ownerName) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		ownerName = requested
	}
	if ownerName == "" {
		http.Error(w, "owner required", http.StatusBadRequest)
		return
	}
	ownerRepo := s.ownerRepoPath(ownerName)
	if ownerRepo == "" {
		ownerRepo = s.cfg.RepoPath
	}
	unlock, err := syncer.Acquire(10 * time.Second)
	if err != nil {
		data := ViewData{
			SyncError:    "Sync already in progress. Please try again.",
			SyncDuration: "0s",
		}
		s.attachViewData(r, &data)
		s.views.RenderTemplate(w, "sync_result", data)
		return
	}
	defer unlock()
	dataPath := strings.TrimSpace(s.cfg.DataPath)
	if dataPath == "" && s.cfg.RepoPath != "" {
		dataPath = filepath.Join(s.cfg.RepoPath, ".wiki")
	}
	if dataPath != "" {
		if absPath, err := filepath.Abs(dataPath); err == nil {
			dataPath = absPath
		}
		_ = os.MkdirAll(dataPath, 0o755)
	}
	userName := ownerName
	credPath := ""
	gitConfig := ""
	if dataPath != "" && userName != "" {
		credPath = filepath.Join(dataPath, userName+".cred")
		gitConfig = filepath.Join(dataPath, userName+".gitconfig")
	}
	opts := syncer.Options{
		HomeDir:            dataPath,
		GitCredentialsFile: credPath,
		GitConfigGlobal:    gitConfig,
		UserName:           userName,
		CommitMessage:      "manual sync",
	}
	start := time.Now()
	output, err := syncer.RunWithOptions(r.Context(), ownerRepo, opts)
	if err == nil {
		logOutput, logErr := syncer.LogGraphWithOptions(r.Context(), ownerRepo, 10, opts)
		output += logOutput
		if logErr != nil {
			err = logErr
		}
		scanned, updated, cleaned, recheckErr := s.idx.RecheckFromFS(r.Context(), s.cfg.RepoPath)
		output += fmt.Sprintf("\nindex: recheck scanned=%d updated=%d cleaned=%d", scanned, updated, cleaned)
		if recheckErr != nil {
			err = recheckErr
		}
		if authErr := s.refreshAuthSources(r.Context()); authErr != nil {
			slog.Warn("sync refresh auth sources", "err", authErr)
			output += fmt.Sprintf("\nauth: refresh failed: %v", authErr)
			if err == nil {
				err = authErr
			}
		} else {
			output += "\nauth: refreshed"
		}
	}
	duration := time.Since(start).Round(time.Millisecond).String()
	data := ViewData{
		SyncOutput:   output,
		SyncDuration: duration,
	}
	if err != nil {
		slog.Warn("sync failed", "repo", ownerRepo, "err", err)
		data.SyncError = err.Error()
	}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "sync_result", data)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	returnURL := sanitizeReturnURL(r, r.URL.Query().Get("return"))
	if returnURL == "" {
		returnURL = sanitizeReturnURL(r, r.Referer())
	}
	data := ViewData{
		Title:           "Settings",
		ContentTemplate: "settings",
		ReturnURL:       returnURL,
	}
	dataPath := strings.TrimSpace(s.cfg.DataPath)
	if dataPath == "" && s.cfg.RepoPath != "" {
		dataPath = filepath.Join(s.cfg.RepoPath, ".wiki")
	}
	if dataPath != "" {
		if absPath, err := filepath.Abs(dataPath); err == nil {
			dataPath = absPath
		}
	}
	userName := currentUserName(r.Context())
	ownerRepo := s.ownerRepoPath(userName)
	if ownerRepo == "" {
		ownerRepo = s.cfg.RepoPath
	}
	if dataPath != "" {
		if userName != "" {
			credPath := filepath.Join(dataPath, userName+".cred")
			creds := parseGitCredentialsFile(credPath)
			remotes, err := listGitRemotes(ownerRepo)
			if err == nil {
				data.GitRemoteCreds = mergeGitRemoteCreds(remotes, creds)
			}
		}
	}
	if err := s.populateSidebarData(r, "/", &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.attachViewData(r, &data)
	if data.IsAdmin {
		data.SettingsUsers = s.settingsUsersWithOrigin(r.Context())
	}
	s.views.RenderPage(w, data)
}

func (s *Server) settingsUsersWithOrigin(ctx context.Context) []UserSummary {
	if strings.TrimSpace(s.cfg.AuthFile) == "" {
		return nil
	}
	fileUsers, err := auth.LoadFile(s.cfg.AuthFile)
	if err != nil {
		slog.Warn("load auth file", "err", err)
		return nil
	}
	users := make([]UserSummary, 0, len(fileUsers))
	for name, entry := range fileUsers {
		users = append(users, UserSummary{
			Name:  name,
			Roles: entry.Roles,
		})
	}
	sort.Slice(users, func(i, j int) bool {
		return strings.ToLower(users[i].Name) < strings.ToLower(users[j].Name)
	})
	for i := range users {
		repoPath := s.ownerRepoPath(users[i].Name)
		users[i].GitOrigin = gitOriginURL(repoPath)
	}
	return users
}

func gitOriginURL(repoPath string) string {
	remotes, err := listGitRemotes(repoPath)
	if err != nil {
		return ""
	}
	for _, remote := range remotes {
		if remote.Alias == "origin" {
			return remote.URL
		}
	}
	return ""
}

func validGitRemoteAlias(alias string) bool {
	if alias == "" {
		return false
	}
	for _, r := range alias {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func addGitRemote(ctx context.Context, repoPath, alias, url string) error {
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "remote", "add", alias, url)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git remote add failed: %s", msg)
	}
	return nil
}

func removeGitRemote(ctx context.Context, repoPath, alias string) error {
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "remote", "remove", alias)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git remote remove failed: %s", msg)
	}
	return nil
}

func upsertGitCredential(dataPath, owner, rawURL, user, token string) error {
	dataPath = strings.TrimSpace(dataPath)
	if dataPath == "" {
		return fmt.Errorf("data path required")
	}
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid remote URL")
	}
	host := parsed.Host
	credPath := filepath.Join(dataPath, owner+".cred")
	entries := parseGitCredentialsFile(credPath)
	next := make([]gitCredentialEntry, 0, len(entries)+1)
	updated := false
	for _, entry := range entries {
		if entry.Host == host {
			next = append(next, gitCredentialEntry{Host: host, User: user, Pass: token})
			updated = true
			continue
		}
		next = append(next, entry)
	}
	if !updated {
		next = append(next, gitCredentialEntry{Host: host, User: user, Pass: token})
	}
	return writeGitCredentialsFile(credPath, next)
}

func removeGitCredential(dataPath, owner, host string) error {
	if host == "" {
		return nil
	}
	dataPath = strings.TrimSpace(dataPath)
	if dataPath == "" {
		return fmt.Errorf("data path required")
	}
	credPath := filepath.Join(dataPath, owner+".cred")
	entries := parseGitCredentialsFile(credPath)
	if len(entries) == 0 {
		return nil
	}
	next := entries[:0]
	for _, entry := range entries {
		if entry.Host == host {
			continue
		}
		next = append(next, entry)
	}
	return writeGitCredentialsFile(credPath, next)
}

func writeGitCredentialsFile(path string, entries []gitCredentialEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Host == "" || entry.User == "" || entry.Pass == "" {
			continue
		}
		u := &url.URL{
			Scheme: "https",
			User:   url.UserPassword(entry.User, entry.Pass),
			Host:   entry.Host,
		}
		lines = append(lines, u.String())
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return fs.WriteFileAtomic(path, []byte(content), 0o600)
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	mode := strings.TrimSpace(r.Form.Get("list_view"))
	if mode != "compact" && mode != "full" {
		http.Error(w, "invalid list view", http.StatusBadRequest)
		return
	}
	trigger := strings.TrimSpace(r.Form.Get("edit_command_trigger"))
	todoToken := strings.TrimSpace(r.Form.Get("edit_command_todo"))
	todayToken := strings.TrimSpace(r.Form.Get("edit_command_today"))
	timeToken := strings.TrimSpace(r.Form.Get("edit_command_time"))
	dateBaseToken := strings.TrimSpace(r.Form.Get("edit_command_date_base"))
	if trigger == "" {
		trigger = "!"
	}
	if todoToken == "" {
		todoToken = "!"
	}
	if todayToken == "" {
		todayToken = "d"
	}
	if timeToken == "" {
		timeToken = "t"
	}
	if dateBaseToken == "" {
		dateBaseToken = "d"
	}
	if !validEditCommandToken(trigger) || !validEditCommandToken(todoToken) || !validEditCommandToken(todayToken) || !validEditCommandToken(timeToken) || !validEditCommandToken(dateBaseToken) {
		http.Error(w, "invalid edit command tokens", http.StatusBadRequest)
		return
	}
	owner := currentUserName(r.Context())
	if owner == "" {
		http.Error(w, "owner required", http.StatusBadRequest)
		return
	}
	ownerRepo := s.ownerRepoPath(owner)
	if ownerRepo == "" {
		ownerRepo = s.cfg.RepoPath
	}
	dataPath := strings.TrimSpace(s.cfg.DataPath)
	if dataPath == "" && s.cfg.RepoPath != "" {
		dataPath = filepath.Join(s.cfg.RepoPath, ".wiki")
	}
	if dataPath != "" {
		if absPath, err := filepath.Abs(dataPath); err == nil {
			dataPath = absPath
		}
	}
	cfg, err := s.loadUserConfig(r.Context())
	if err != nil {
		slog.Warn("load user config", "err", err)
	}
	val := mode == "compact"
	cfg.CompactNoteList = &val
	cfg.EditCommandTrigger = trigger
	cfg.EditCommandTodo = todoToken
	cfg.EditCommandToday = todayToken
	cfg.EditCommandTime = timeToken
	cfg.EditCommandDateBase = dateBaseToken
	if err := s.saveUserConfig(r.Context(), owner, cfg); err != nil {
		http.Error(w, "failed to save settings", http.StatusInternalServerError)
		return
	}
	s.commitOwnerRepoAsync(owner, "update config")
	s.addToast(r, Toast{
		ID:              uuid.NewString(),
		Message:         "Settings saved.",
		Kind:            "success",
		DurationSeconds: 3,
		CreatedAt:       time.Now(),
	})
	returnURL := sanitizeReturnURL(r, r.Form.Get("return_url"))
	if returnURL == "" {
		returnURL = "/settings"
	}
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

func (s *Server) handleSettingsRemoteAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	returnURL := sanitizeReturnURL(r, r.FormValue("return"))
	if returnURL == "" {
		returnURL = "/settings"
	}
	fail := func(message string) {
		s.addToast(r, Toast{
			ID:              uuid.NewString(),
			Message:         message,
			Kind:            "error",
			DurationSeconds: 6,
			CreatedAt:       time.Now(),
		})
		http.Redirect(w, r, returnURL, http.StatusSeeOther)
	}
	alias := strings.TrimSpace(r.FormValue("alias"))
	rawURL := strings.TrimSpace(r.FormValue("url"))
	user := strings.TrimSpace(r.FormValue("user"))
	token := strings.TrimSpace(r.FormValue("token"))
	if rawURL == "" {
		fail("Remote URL is required.")
		return
	}
	owner := currentUserName(r.Context())
	if owner == "" {
		fail("Owner required.")
		return
	}
	repoPath := s.ownerRepoPath(owner)
	if repoPath == "" {
		fail("Repo path required.")
		return
	}
	remotes, err := listGitRemotes(repoPath)
	if err != nil {
		fail("Failed to list git remotes.")
		return
	}
	if len(remotes) == 0 {
		alias = "origin"
	}
	if alias == "" {
		fail("Alias is required.")
		return
	}
	if !validGitRemoteAlias(alias) {
		fail("Invalid alias.")
		return
	}
	for _, remote := range remotes {
		if strings.EqualFold(remote.Alias, alias) {
			fail("Remote alias already exists.")
			return
		}
	}
	if err := addGitRemote(r.Context(), repoPath, alias, rawURL); err != nil {
		fail(err.Error())
		return
	}
	if user != "" && token != "" {
		dataPath := strings.TrimSpace(s.cfg.DataPath)
		if dataPath == "" && s.cfg.RepoPath != "" {
			dataPath = filepath.Join(s.cfg.RepoPath, ".wiki")
		}
		if absPath, err := filepath.Abs(dataPath); err == nil {
			dataPath = absPath
		}
		if err := upsertGitCredential(dataPath, owner, rawURL, user, token); err != nil {
			fail("Failed to save credentials.")
			return
		}
	}
	s.addToast(r, Toast{
		ID:              uuid.NewString(),
		Message:         "Remote added.",
		Kind:            "success",
		DurationSeconds: 4,
		CreatedAt:       time.Now(),
	})
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

func (s *Server) handleSettingsRemoteRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	returnURL := sanitizeReturnURL(r, r.FormValue("return"))
	if returnURL == "" {
		returnURL = "/settings"
	}
	fail := func(message string) {
		s.addToast(r, Toast{
			ID:              uuid.NewString(),
			Message:         message,
			Kind:            "error",
			DurationSeconds: 6,
			CreatedAt:       time.Now(),
		})
		http.Redirect(w, r, returnURL, http.StatusSeeOther)
	}
	alias := strings.TrimSpace(r.FormValue("alias"))
	if alias == "" {
		fail("Alias required.")
		return
	}
	owner := currentUserName(r.Context())
	if owner == "" {
		fail("Owner required.")
		return
	}
	repoPath := s.ownerRepoPath(owner)
	if repoPath == "" {
		fail("Repo path required.")
		return
	}
	remotes, err := listGitRemotes(repoPath)
	if err != nil {
		fail("Failed to list git remotes.")
		return
	}
	host := ""
	for _, remote := range remotes {
		if strings.EqualFold(remote.Alias, alias) {
			host = remote.Host
			break
		}
	}
	if host == "" {
		fail("Remote not found.")
		return
	}
	if err := removeGitRemote(r.Context(), repoPath, alias); err != nil {
		fail(err.Error())
		return
	}
	dataPath := strings.TrimSpace(s.cfg.DataPath)
	if dataPath == "" && s.cfg.RepoPath != "" {
		dataPath = filepath.Join(s.cfg.RepoPath, ".wiki")
	}
	if absPath, err := filepath.Abs(dataPath); err == nil {
		dataPath = absPath
	}
	if err := removeGitCredential(dataPath, owner, host); err != nil {
		fail("Failed to update credentials.")
		return
	}
	s.addToast(r, Toast{
		ID:              uuid.NewString(),
		Message:         "Remote removed.",
		Kind:            "success",
		DurationSeconds: 4,
		CreatedAt:       time.Now(),
	})
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

func (s *Server) handleSettingsUserDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if !isAdmin(r.Context()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	returnURL := sanitizeReturnURL(r, r.FormValue("return"))
	if returnURL == "" {
		returnURL = "/settings"
	}
	fail := func(message string) {
		s.addToast(r, Toast{
			ID:              uuid.NewString(),
			Message:         message,
			Kind:            "error",
			DurationSeconds: 6,
			CreatedAt:       time.Now(),
		})
		http.Redirect(w, r, returnURL, http.StatusSeeOther)
	}
	if err := r.ParseForm(); err != nil {
		fail("Invalid request.")
		return
	}
	userName := strings.TrimSpace(r.FormValue("username"))
	confirm := strings.TrimSpace(r.FormValue("confirm"))
	if userName == "" || confirm == "" {
		fail("Username confirmation required.")
		return
	}
	if !strings.EqualFold(userName, confirm) {
		fail("Confirmation does not match username.")
		return
	}
	if strings.EqualFold(userName, currentUserName(r.Context())) {
		fail("Cannot delete current user.")
		return
	}
	if strings.TrimSpace(s.cfg.AuthFile) == "" {
		fail("Auth file not configured.")
		return
	}
	repoPath := s.ownerRepoPath(userName)
	if repoPath != "" {
		if err := os.RemoveAll(repoPath); err != nil {
			fail("Failed to remove repo folder: " + err.Error())
			return
		}
	}
	removed, err := removeAuthUser(s.cfg.AuthFile, userName)
	if err != nil {
		fail(err.Error())
		return
	}
	if !removed {
		fail("User not found.")
		return
	}
	if s.auth != nil {
		dbUsers, err := s.idx.ListUsers(r.Context())
		if err == nil {
			_ = s.auth.ReloadWithExtra(dbUsers)
		} else {
			_ = s.auth.Reload()
		}
	}
	s.addToast(r, Toast{
		ID:              uuid.NewString(),
		Message:         "User deleted: " + userName,
		Kind:            "success",
		DurationSeconds: 4,
		CreatedAt:       time.Now(),
	})
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

func (s *Server) handleSettingsUserCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAuth(w, r) {
		return
	}
	if !isAdmin(r.Context()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	returnURL := sanitizeReturnURL(r, r.FormValue("return"))
	if returnURL == "" {
		returnURL = "/settings"
	}
	fail := func(message string) {
		s.addToast(r, Toast{
			ID:              uuid.NewString(),
			Message:         message,
			Kind:            "error",
			DurationSeconds: 6,
			CreatedAt:       time.Now(),
		})
		http.Redirect(w, r, returnURL, http.StatusSeeOther)
	}
	if err := r.ParseForm(); err != nil {
		fail("Invalid request.")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))
	if username == "" || password == "" {
		fail("All fields are required.")
		return
	}
	if _, ok := ownerHomeName("/" + username); !ok {
		fail("Invalid username.")
		return
	}
	if strings.TrimSpace(s.cfg.AuthFile) == "" {
		fail("Auth file not configured.")
		return
	}
	repoPath := filepath.Join(s.cfg.RepoPath, username)
	if _, err := os.Stat(repoPath); err == nil {
		fail("Repo already exists at " + repoPath + ".")
		return
	} else if !os.IsNotExist(err) {
		fail("Failed to check repo path.")
		return
	}
	cleanup := func() {
		_ = os.RemoveAll(repoPath)
	}
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		fail("Failed to create repo folder.")
		return
	}
	if err := initRepo(r.Context(), repoPath); err != nil {
		cleanup()
		fail(err.Error())
		return
	}
	if err := addAuthUser(s.cfg.AuthFile, username, password, "1900-01-01"); err != nil {
		cleanup()
		fail(err.Error())
		return
	}
	if s.auth != nil {
		dbUsers, err := s.idx.ListUsers(r.Context())
		if err == nil {
			_ = s.auth.ReloadWithExtra(dbUsers)
		} else {
			_ = s.auth.Reload()
		}
	}
	s.addToast(r, Toast{
		ID:              uuid.NewString(),
		Message:         "User created: " + username,
		Kind:            "success",
		DurationSeconds: 4,
		CreatedAt:       time.Now(),
	})
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
}

func initRepo(ctx context.Context, repoPath string) error {
	cmd := exec.CommandContext(ctx, "git", "init", repoPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git init failed: %s", msg)
	}
	return nil
}

func addAuthUser(path string, username string, password string, expiry string) error {
	users, err := auth.LoadFile(path)
	if err != nil {
		return err
	}
	for user := range users {
		if strings.EqualFold(user, username) {
			return fmt.Errorf("user already exists")
		}
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err == nil && info.Size() > 0 {
		buf := make([]byte, 1)
		if _, err := f.ReadAt(buf, info.Size()-1); err == nil && buf[0] != '\n' {
			if _, err := f.WriteString("\n"); err != nil {
				return err
			}
		}
	}
	_, err = f.WriteString(username + ":" + hash + ":" + expiry + "\n")
	return err
}

func updateAuthUserPassword(path string, username string, hash string, expiry string) error {
	if _, err := time.Parse("2006-01-02", expiry); err != nil {
		return fmt.Errorf("invalid password expiry %q", expiry)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	updated := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}
		parts := strings.SplitN(trimmed, ":", 4)
		if len(parts) < 3 {
			return fmt.Errorf("invalid auth entry for %q", username)
		}
		user := strings.TrimSpace(parts[0])
		if strings.EqualFold(user, username) {
			roleRaw := ""
			if len(parts) >= 4 {
				roleRaw = strings.TrimSpace(parts[3])
			}
			updatedLine := user + ":" + hash + ":" + expiry
			if roleRaw != "" {
				updatedLine += ":" + roleRaw
			}
			lines = append(lines, updatedLine)
			updated = true
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !updated {
		return fmt.Errorf("user not found")
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func removeAuthUser(path string, username string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	removed := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) < 2 {
			lines = append(lines, line)
			continue
		}
		user := strings.TrimSpace(parts[0])
		if strings.EqualFold(user, username) {
			removed = true
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	if !removed {
		return false, nil
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return false, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return false, err
	}
	return true, nil
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
	if !s.requireWriteAccessForPath(w, r, notePath) {
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
	lineBody := taskDoneTokenRe.ReplaceAllString(match[3], "")
	lineBody = strings.TrimRight(lineBody, " \t")
	if newMark == "x" {
		timestamp := time.Now().Format("2006-01-02T15:04:05")
		lineBody = strings.TrimRight(lineBody, " \t") + " done:" + timestamp
	}
	newLine := match[1] + newMark + lineBody
	if newMark != "x" {
		newLine = taskDoneTokenRe.ReplaceAllString(newLine, "")
		newLine = strings.TrimRight(newLine, " \t")
	}
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
	if ownerName, _, err := s.ownerFromNotePath(notePath); err == nil {
		if strings.TrimSpace(newMark) == "" {
			s.commitOwnerRepoAsync(ownerName, "unchecked todo "+notePath)
		} else {
			s.commitOwnerRepoAsync(ownerName, "checked todo "+notePath)
		}
	}
	fullBody := index.StripFrontmatter(normalizeLineEndings(updatedContent))
	meta := index.FrontmatterAttributes(updatedContent)
	renderCtx := r.Context()
	renderSource := fullBody
	var tasksForNote []index.Task
	currentURL := r.Header.Get("HX-Current-URL")
	isIndex := false
	if currentURL != "" {
		if parsed, err := url.Parse(currentURL); err == nil && parsed.Path == "/" {
			isIndex = true
		}
	}
	if strings.Contains(currentURL, "/todo") {
		noteTags, activeDue, dueDate, activeFolder, activeRoot, activeJournal := todoFiltersFromURL(currentURL)
		tasks, err := s.idx.OpenTasks(renderCtx, noteTags, 300, activeDue, dueDate, activeFolder, activeRoot, activeJournal)
		if err == nil {
			tasksByNote := make(map[string][]index.TaskItem)
			for _, task := range tasks {
				tasksByNote[task.Path] = append(tasksByNote[task.Path], task)
			}
			noteTasks := tasksByNote[notePath]
			sort.Slice(noteTasks, func(i, j int) bool {
				return noteTasks[i].LineNo < noteTasks[j].LineNo
			})
			if len(noteTasks) > 0 {
				lines := strings.Split(fullBody, "\n")
				snippet, checkboxTasks := buildTodoDebugSnippet(lines, noteTasks)
				renderSource = snippet
				tasksForNote = checkboxTasks
			}
		}
	} else if isIndex {
		filtered, _, tasks := index.FilterCompletedTasksSnippet(updatedContent)
		renderSource = filtered
		tasksForNote = tasks
	} else {
		metaTasks := index.ParseContent(updatedContent).Tasks
		tasksForNote = make([]index.Task, 0, len(metaTasks))
		for _, t := range metaTasks {
			tasksForNote = append(tasksForNote, index.Task{
				LineNo: t.LineNo,
				Hash:   t.Hash,
				Done:   t.Done,
			})
		}
	}
	renderedBody, err := s.renderNoteBody(renderCtx, []byte(renderSource))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if fileID > 0 && len(tasksForNote) > 0 {
		renderedBody = decorateTaskCheckboxes(renderedBody, fileID, tasksForNote)
	}
	noteBody := fmt.Sprintf(
		`<div class="note-body text-sm leading-relaxed text-slate-200" data-note-id="%s" data-note-path="%s">%s</div>`,
		html.EscapeString(meta.ID),
		html.EscapeString(notePath),
		renderedBody,
	)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(noteBody))
}

func (s *Server) handleToastList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	toasts := s.toasts.List(toastKey(r))
	data := ViewData{
		ContentTemplate: "toast",
		ToastItems:      toasts,
	}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "toast", data)
}

func (s *Server) handleToastDismiss(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/toast/")
	id = strings.TrimSpace(id)
	if id == "" {
		http.Error(w, "toast id required", http.StatusBadRequest)
		return
	}
	s.toasts.Remove(toastKey(r), id)
	toasts := s.toasts.List(toastKey(r))
	data := ViewData{
		ContentTemplate: "toast",
		ToastItems:      toasts,
	}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "toast", data)
}

func (s *Server) handleSidebar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sidebarReq, basePath := sidebarRequest(r)
	if maxTime, err := s.idx.MaxEtagTime(sidebarReq.Context()); err == nil {
		etag := pageETag("sidebar", currentURLString(sidebarReq), maxTime, currentUserName(r.Context()))
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.Header().Set("ETag", etag)
			setPrivateCacheHeaders(w)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		setPrivateCacheHeaders(w)
	}
	data := ViewData{
		ContentTemplate: "sidebar",
	}
	if err := s.populateSidebarData(sidebarReq, basePath, &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.attachViewData(sidebarReq, &data)
	s.views.RenderTemplate(w, "sidebar", data)
}

func (s *Server) handleCalendar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pageURL := quickLauncherURL(r)
	if pageURL == nil {
		pageURL = r.URL
	}
	basePath := sidebarBasePath(pageURL.Path)
	if basePath == "/calendar" {
		basePath = "/"
	}
	pageReq := *r
	pageReq.URL = pageURL
	if maxTime, err := s.idx.MaxEtagTime(pageReq.Context()); err == nil {
		etag := pageETag("calendar", currentURLString(&pageReq), maxTime, currentUserName(r.Context()))
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.Header().Set("ETag", etag)
			setPrivateCacheHeaders(w)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		setPrivateCacheHeaders(w)
	}
	baseURL := baseURLForLinks(&pageReq, basePath)
	query := pageURL.Query()
	activeDate := parseDateParam(query.Get("d"))
	activeFolder, activeRoot := parseFolderParam(query.Get("f"))
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	calendar := buildCalendarMonth(calendarReferenceDate(&pageReq), updateDays, baseURL, activeDate)
	data := ViewData{
		CalendarMonth: calendar,
	}
	applyCalendarLinks(&data, baseURL)
	s.views.RenderTemplate(w, "calendar", data)
}

func (s *Server) handleCalendarSkeleton(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pageURL := quickLauncherURL(r)
	if pageURL == nil {
		pageURL = r.URL
	}
	basePath := sidebarBasePath(pageURL.Path)
	if basePath == "/calendar-skeleton" {
		basePath = "/"
	}
	pageReq := *r
	pageReq.URL = pageURL
	baseURL := baseURLForLinks(&pageReq, basePath)
	activeDate := parseDateParam(pageURL.Query().Get("d"))
	calendar := buildCalendarMonth(calendarReferenceDate(&pageReq), nil, baseURL, activeDate)
	data := ViewData{
		CalendarMonth: calendar,
	}
	cacheControl := "public, max-age=300, stale-while-revalidate=600"
	s.views.RenderTemplateWithCache(w, "calendar_skeleton", data, cacheControl)
}

func extractFirstListItem(htmlStr string) string {
	start := strings.Index(htmlStr, "<li")
	if start == -1 {
		return ""
	}
	end := strings.Index(htmlStr[start:], "</li>")
	if end == -1 {
		return ""
	}
	end += start + len("</li>")
	return strings.TrimSpace(htmlStr[start:end])
}

func calendarMonthParam(r *http.Request, sidebarReq *http.Request) string {
	if r != nil {
		if month := strings.TrimSpace(r.URL.Query().Get("month")); month != "" {
			return month
		}
		if month := strings.TrimSpace(r.URL.Query().Get("m")); month != "" {
			return month
		}
	}
	if sidebarReq != nil && sidebarReq.URL != nil {
		if month := strings.TrimSpace(sidebarReq.URL.Query().Get("month")); month != "" {
			return month
		}
		if month := strings.TrimSpace(sidebarReq.URL.Query().Get("m")); month != "" {
			return month
		}
	}
	return ""
}

func parseCalendarMonth(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if len(raw) > 7 {
		raw = raw[:7]
	}
	parsed, err := time.Parse("2006-01", raw)
	if err == nil {
		return parsed, true
	}
	parsedDay, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, false
	}
	return time.Date(parsedDay.Year(), parsedDay.Month(), 1, 0, 0, 0, 0, time.UTC), true
}

func calendarReferenceDate(r *http.Request) time.Time {
	if r == nil {
		return time.Now()
	}
	monthStr := calendarMonthParam(r, nil)
	if monthStr == "" {
		return time.Now()
	}
	if parsed, ok := parseCalendarMonth(monthStr); ok {
		return parsed
	}
	return time.Now()
}

func (s *Server) loadHomeNotes(ctx context.Context, offset int, tags []string, activeDate string, activeSearch string, folder string, rootOnly bool, journalOnly bool, ownerName string) ([]NoteCard, int, bool, error) {
	if offset > 0 {
		return []NoteCard{}, offset, false, nil
	}
	notes, err := s.idx.NoteList(ctx, index.NoteListFilter{
		Tags:         tags,
		Date:         activeDate,
		Query:        activeSearch,
		Folder:       folder,
		Root:         rootOnly,
		JournalOnly:  journalOnly,
		OwnerName:    ownerName,
		HomeSections: true,
		Limit:        homeSectionsMaxNotes,
		Offset:       0,
	})
	if err != nil {
		return nil, offset, false, err
	}
	hasMore := false
	cards, err := s.buildNoteCardsFromSummaries(ctx, notes)
	if err != nil {
		return nil, offset, false, err
	}
	return cards, len(notes), hasMore, nil
}

func (s *Server) buildNoteCardsFromSummaries(ctx context.Context, notes []index.NoteSummary) ([]NoteCard, error) {
	cards := make([]NoteCard, 0, len(notes))
	for _, note := range notes {
		fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, note.Path)
		if err != nil {
			return nil, err
		}
		content, err := os.ReadFile(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				_ = s.idx.RemoveNoteByPath(ctx, note.Path)
				continue
			}
			return nil, err
		}
		normalized := normalizeLineEndings(string(content))
		labelTime := note.MTime
		metaAttrs := index.FrontmatterAttributes(normalized)
		if metaAttrs.Updated.IsZero() {
			metaAttrs.Updated = labelTime.Local()
		}
		folderLabel := s.noteFolderLabel(ctx, note.Path, metaAttrs.Folder)
		cards = append(cards, NoteCard{
			Path:        note.Path,
			Title:       note.Title,
			FileName:    filepath.Base(note.Path),
			Meta:        metaAttrs,
			FolderLabel: folderLabel,
			SectionRank: note.SectionRank,
		})
	}
	return cards, nil
}

func splitHomeSections(notes []NoteCard) ([]NoteCard, []NoteCard, []NoteCard, []NoteCard, []NoteCard, []NoteCard, []NoteCard, []NoteCard) {
	priority := make([]NoteCard, 0, len(notes))
	today := make([]NoteCard, 0, len(notes))
	planned := make([]NoteCard, 0, len(notes))
	week := make([]NoteCard, 0, len(notes))
	month := make([]NoteCard, 0, len(notes))
	year := make([]NoteCard, 0, len(notes))
	lastYear := make([]NoteCard, 0, len(notes))
	others := make([]NoteCard, 0, len(notes))
	for _, note := range notes {
		switch note.SectionRank {
		case 0:
			priority = append(priority, note)
		case 1:
			today = append(today, note)
		case 2:
			planned = append(planned, note)
		case 3:
			week = append(week, note)
		case 4:
			month = append(month, note)
		case 5:
			year = append(year, note)
		case 6:
			lastYear = append(lastYear, note)
		default:
			others = append(others, note)
		}
	}
	return priority, today, planned, week, month, year, lastYear, others
}

func homeSectionBounds(now time.Time) (time.Time, time.Time, time.Time, time.Time, time.Time, time.Time) {
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	endOfDay := startOfDay.Add(24 * time.Hour)
	weekday := int(now.Weekday())
	if weekday == 0 {
		weekday = 7
	}
	startOfWeek := startOfDay.AddDate(0, 0, -(weekday - 1))
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	startOfYear := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, now.Location())
	startOfLastYear := time.Date(now.Year()-1, 1, 1, 0, 0, 0, 0, now.Location())
	return startOfDay, endOfDay, startOfWeek, startOfMonth, startOfYear, startOfLastYear
}

func (s *Server) loadHomeSectionNotes(ctx context.Context, section string, tags []string, activeSearch string, folder string, rootOnly bool, journalOnly bool, ownerName string) ([]NoteCard, error) {
	filter := index.NoteListFilter{
		Tags:        tags,
		Query:       activeSearch,
		Folder:      folder,
		Root:        rootOnly,
		JournalOnly: journalOnly,
		OwnerName:   ownerName,
		Limit:       homeSectionsMaxNotes,
		Offset:      0,
	}
	priorityMin := 6
	priorityMax := 5
	now := time.Now()
	startOfDay, endOfDay, startOfWeek, startOfMonth, startOfYear, startOfLastYear := homeSectionBounds(now)
	switch section {
	case "priority":
		filter.PriorityMax = &priorityMax
	case "today":
		filter.PriorityMin = &priorityMin
		updatedAfter := startOfDay.Unix()
		updatedBefore := endOfDay.Unix()
		filter.UpdatedAfter = &updatedAfter
		filter.UpdatedBefore = &updatedBefore
	case "planned":
		filter.PriorityMin = &priorityMin
		updatedAfter := endOfDay.Unix()
		filter.UpdatedAfter = &updatedAfter
		filter.UpdatedAsc = true
	case "week":
		filter.PriorityMin = &priorityMin
		updatedAfter := startOfWeek.Unix()
		updatedBefore := startOfDay.Unix()
		filter.UpdatedAfter = &updatedAfter
		filter.UpdatedBefore = &updatedBefore
	case "month":
		filter.PriorityMin = &priorityMin
		updatedAfter := startOfMonth.Unix()
		updatedBefore := startOfWeek.Unix()
		filter.UpdatedAfter = &updatedAfter
		filter.UpdatedBefore = &updatedBefore
	case "year":
		filter.PriorityMin = &priorityMin
		updatedAfter := startOfYear.Unix()
		updatedBefore := startOfMonth.Unix()
		filter.UpdatedAfter = &updatedAfter
		filter.UpdatedBefore = &updatedBefore
	case "lastYear":
		filter.PriorityMin = &priorityMin
		updatedAfter := startOfLastYear.Unix()
		updatedBefore := startOfYear.Unix()
		filter.UpdatedAfter = &updatedAfter
		filter.UpdatedBefore = &updatedBefore
	case "others":
		filter.PriorityMin = &priorityMin
		updatedBefore := startOfLastYear.Unix()
		filter.UpdatedBefore = &updatedBefore
	default:
		return nil, fmt.Errorf("unknown section %q", section)
	}
	notes, err := s.idx.NoteList(ctx, filter)
	if err != nil {
		return nil, err
	}
	return s.buildNoteCardsFromSummaries(ctx, notes)
}

func (s *Server) handleNewNote(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method == http.MethodGet {
		ownerOptions, defaultOwner, err := s.ownerOptionsForUser(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		selectedOwner := strings.TrimSpace(r.URL.Query().Get("owner"))
		if selectedOwner == "" {
			selectedOwner = defaultOwner
		}
		if selectedOwner == "" && len(ownerOptions) > 0 {
			selectedOwner = ownerOptions[0].Name
		}
		if selectedOwner != "" && len(ownerOptions) > 0 {
			found := false
			for _, option := range ownerOptions {
				if option.Name == selectedOwner {
					found = true
					break
				}
			}
			if !found {
				selectedOwner = defaultOwner
			}
		}
		uploadToken := strings.TrimSpace(r.URL.Query().Get("upload_token"))
		if uploadToken == "" {
			uploadToken = uuid.NewString()
		} else if _, err := uuid.Parse(uploadToken); err != nil {
			uploadToken = uuid.NewString()
		}
		rawRef := strings.TrimSpace(r.URL.Query().Get("path"))
		presetTitle := ""
		presetFolder := ""
		if rawRef != "" {
			rawRef = strings.ReplaceAll(rawRef, "\\", "/")
			clean := path.Clean(rawRef)
			if clean != "." && !strings.HasPrefix(clean, "..") && !strings.HasPrefix(clean, "/") && !strings.Contains(clean, "/../") {
				dir := path.Dir(clean)
				if dir != "." {
					presetFolder = dir
				}
				base := path.Base(clean)
				if ext := path.Ext(base); ext != "" {
					base = strings.TrimSuffix(base, ext)
				}
				presetTitle = strings.TrimSpace(base)
			}
		}
		rawContent := ""
		noteMeta := index.FrontmatterAttrs{Priority: "10"}
		if presetFolder != "" {
			noteMeta.Folder = presetFolder
		}
		if presetTitle != "" {
			rawContent = "# " + presetTitle + "\n\n"
		}
		data := ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			NoteTitle:        presetTitle,
			RawContent:       rawContent,
			FrontmatterBlock: "",
			NoteMeta:         noteMeta,
			FolderOptions:    s.folderOptions(r.Context()),
			OwnerOptions:     ownerOptions,
			SelectedOwner:    selectedOwner,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(selectedOwner, uploadToken)),
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
		ownerName := strings.TrimSpace(r.Form.Get("owner"))
		if ownerName == "" {
			ownerName = currentUserName(r.Context())
		}
		ownerOptions, defaultOwner, optionsErr := s.ownerOptionsForUser(r.Context())
		if optionsErr != nil {
			http.Error(w, optionsErr.Error(), http.StatusInternalServerError)
			return
		}
		if ownerName == "" {
			ownerName = defaultOwner
		}
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       r.Form.Get("content"),
			FrontmatterBlock: r.Form.Get("frontmatter"),
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	}
	content := normalizeLineEndings(r.Form.Get("content"))
	frontmatter := normalizeLineEndings(r.Form.Get("frontmatter"))
	uploadToken := r.Form.Get("upload_token")
	ownerName := strings.TrimSpace(r.Form.Get("owner"))
	if ownerName == "" {
		ownerName = currentUserName(r.Context())
	}
	if ownerName == "" {
		http.Error(w, "owner required", http.StatusBadRequest)
		return
	}
	if err := s.ensureOwnerNotesDir(ownerName); err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	visibility := strings.TrimSpace(r.Form.Get("visibility"))
	folderInput := r.Form.Get("folder")
	priorityInput := strings.TrimSpace(r.Form.Get("priority"))
	if content == "" {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       "",
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
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
	now := time.Now()
	journalMode := false
	journalDay := now
	lines := strings.Split(content, "\n")
	firstLine := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		firstLine = i
		break
	}
	if firstLine >= 0 {
		line := strings.TrimSpace(lines[firstLine])
		if matches := journalDateH1.FindStringSubmatch(line); len(matches) == 2 {
			if parsed, err := time.Parse("2006-01-02", matches[1]); err == nil {
				journalMode = true
				journalDay = parsed
				remaining := append([]string{}, lines[:firstLine]...)
				remaining = append(remaining, lines[firstLine+1:]...)
				content = strings.TrimLeft(strings.Join(remaining, "\n"), "\n")
			}
		}
	}
	title := index.DeriveTitleFromBody(content)
	if title == "" {
		journalMode = true
	}
	if journalMode {
		journalDate := journalDay.Format("2 Jan 2006")
		journalTime := now.Format("15:04")
		journalEntry := "## " + journalTime + "\n\n" + strings.TrimSpace(content) + "\n"
		journalRel := filepath.ToSlash(filepath.Join(journalDay.Format("2006-01"), journalDay.Format("02")+".md"))
		notePath := filepath.ToSlash(filepath.Join(ownerName, journalRel))
		fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
		if err != nil {
			ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
			s.renderEditError(w, r, ViewData{
				Title:            "New note",
				ContentTemplate:  "edit",
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				OwnerOptions:     ownerOptions,
				SelectedOwner:    ownerName,
				SaveAction:       "/notes/new",
				UploadToken:      uploadToken,
				Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
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
				ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
				s.renderEditError(w, r, ViewData{
					Title:            "New note",
					ContentTemplate:  "edit",
					RawContent:       content,
					FrontmatterBlock: frontmatter,
					OwnerOptions:     ownerOptions,
					SelectedOwner:    ownerName,
					SaveAction:       "/notes/new",
					UploadToken:      uploadToken,
					Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
					ErrorMessage:     err.Error(),
					ErrorReturnURL:   "/notes/new",
				}, http.StatusInternalServerError)
				return
			}
			unlock := s.locker.Lock(notePath)
			if err := fs.WriteFileAtomic(fullPath, []byte(updatedContent), 0o644); err != nil {
				unlock()
				ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
				s.renderEditError(w, r, ViewData{
					Title:            "New note",
					ContentTemplate:  "edit",
					RawContent:       content,
					FrontmatterBlock: frontmatter,
					OwnerOptions:     ownerOptions,
					SelectedOwner:    ownerName,
					SaveAction:       "/notes/new",
					UploadToken:      uploadToken,
					Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
					ErrorMessage:     err.Error(),
					ErrorReturnURL:   "/notes/new",
				}, http.StatusInternalServerError)
				return
			}
			unlock()
			if err := s.promoteTempAttachments(ownerName, uploadToken, updatedContent); err != nil {
				ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
				s.renderEditError(w, r, ViewData{
					Title:            "New note",
					ContentTemplate:  "edit",
					RawContent:       content,
					FrontmatterBlock: frontmatter,
					OwnerOptions:     ownerOptions,
					SelectedOwner:    ownerName,
					SaveAction:       "/notes/new",
					UploadToken:      uploadToken,
					Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
					ErrorMessage:     err.Error(),
					ErrorReturnURL:   "/notes/new",
				}, http.StatusInternalServerError)
				return
			}
			if info, err := os.Stat(fullPath); err == nil {
				_ = s.idx.IndexNote(r.Context(), notePath, []byte(updatedContent), info.ModTime(), info.Size())
			}
			s.commitOwnerRepoAsync(ownerName, "save "+notePath)
			s.addToast(r, Toast{
				ID:              uuid.NewString(),
				Message:         "Journal entry saved.",
				Kind:            "success",
				DurationSeconds: 3,
				CreatedAt:       time.Now(),
			})
			targetURL := "/notes/" + notePath
			if isHTMX(r) {
				w.Header().Set("HX-Redirect", targetURL)
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Redirect(w, r, targetURL, http.StatusSeeOther)
			return
		} else if err != nil && !os.IsNotExist(err) {
			ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
			s.renderEditError(w, r, ViewData{
				Title:            "New note",
				ContentTemplate:  "edit",
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				OwnerOptions:     ownerOptions,
				SelectedOwner:    ownerName,
				SaveAction:       "/notes/new",
				UploadToken:      uploadToken,
				Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
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
		folderInput = journalDay.Format("2006-01")
	} else {
		mergedContent = normalizeLineEndings(mergedContent)
	}

	mergedContent, err := index.EnsureFrontmatterWithTitleAndUser(mergedContent, now, s.cfg.UpdatedHistoryMax, title, historyUser(r.Context()))
	if err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	folder, err := normalizeFolderPath(folderInput)
	if err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     "invalid folder",
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	}
	checkPath := "placeholder.md"
	if folder != "" {
		checkPath = folder + "/placeholder.md"
	}
	if !s.requireWriteAccessForRelPath(w, r, ownerName, checkPath) {
		return
	}
	priority := "10"
	if priorityInput != "" {
		val, err := strconv.Atoi(priorityInput)
		if err != nil || val <= 0 {
			ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
			s.renderEditError(w, r, ViewData{
				Title:            "New note",
				ContentTemplate:  "edit",
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				OwnerOptions:     ownerOptions,
				SelectedOwner:    ownerName,
				SaveAction:       "/notes/new",
				UploadToken:      uploadToken,
				Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
				ErrorMessage:     "invalid priority",
				ErrorReturnURL:   "/notes/new",
			}, http.StatusBadRequest)
			return
		}
		priority = strconv.Itoa(val)
	}
	if updated, err := index.SetVisibility(mergedContent, visibility); err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}
	if updated, err := index.SetPriority(mergedContent, priority); err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}
	if updated, err := index.SetFolder(mergedContent, folder); err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	} else {
		mergedContent = updated
	}

	var notePath string
	if journalMode {
		relPath := filepath.ToSlash(filepath.Join(folder, journalDay.Format("02")+".md"))
		notePath = filepath.ToSlash(filepath.Join(ownerName, relPath))
	} else {
		slug := slugify(title)
		notePath = fs.EnsureMDExt(slug)
		if folder != "" {
			notePath = filepath.ToSlash(filepath.Join(folder, notePath))
		}
		notePath = filepath.ToSlash(filepath.Join(ownerName, notePath))
	}
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(fullPath); err == nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     "note already exists",
			ErrorReturnURL:   "/notes/new",
		}, http.StatusConflict)
		return
	}
	if err != nil && !os.IsNotExist(err) {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}

	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	if err := fs.WriteFileAtomic(fullPath, []byte(mergedContent), 0o644); err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	if err := s.promoteTempAttachments(ownerName, uploadToken, mergedContent); err != nil {
		ownerOptions, _, _ := s.ownerOptionsForUser(r.Context())
		s.renderEditError(w, r, ViewData{
			Title:            "New note",
			ContentTemplate:  "edit",
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			OwnerOptions:     ownerOptions,
			SelectedOwner:    ownerName,
			SaveAction:       "/notes/new",
			UploadToken:      uploadToken,
			Attachments:      listAttachmentNames(s.tempAttachmentsDir(ownerName, uploadToken)),
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/new",
		}, http.StatusInternalServerError)
		return
	}
	info, err := os.Stat(fullPath)
	if err == nil {
		_ = s.idx.IndexNote(r.Context(), notePath, []byte(mergedContent), info.ModTime(), info.Size())
	}
	s.commitOwnerRepoAsync(ownerName, "create "+notePath)

	s.addToast(r, Toast{
		ID:              uuid.NewString(),
		Message:         "Note created.",
		Kind:            "success",
		DurationSeconds: 3,
		CreatedAt:       time.Now(),
	})
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
	if s.auth != nil && !IsAuthenticated(r.Context()) {
		if pathPart == "new/attachments/delete" || pathPart == "new/upload" ||
			strings.HasSuffix(pathPart, "/edit") || strings.HasSuffix(pathPart, "/save") ||
			strings.HasSuffix(pathPart, "/upload") || strings.HasSuffix(pathPart, "/attachments/delete") ||
			strings.HasSuffix(pathPart, "/delete") || strings.HasSuffix(pathPart, "/wikilink") ||
			strings.HasSuffix(pathPart, "/collapsed") || strings.HasSuffix(pathPart, "/preview") {
			s.renderLoginPrompt(w, r, sanitizeReturnURL(r, r.URL.RequestURI()), "", http.StatusUnauthorized)
			return
		}
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
	if strings.HasSuffix(pathPart, "/wikilink") {
		base := strings.TrimSuffix(pathPart, "/wikilink")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleUpdateWikiLink(w, r, resolved)
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
	if strings.HasSuffix(pathPart, "/backlinks") {
		base := strings.TrimSuffix(pathPart, "/backlinks")
		resolved, err := s.resolveNotePath(r.Context(), base)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.handleNoteBacklinksFragment(w, r, resolved)
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
		if status == http.StatusUnauthorized {
			s.renderLoginPrompt(w, r, sanitizeReturnURL(r, r.URL.RequestURI()), "", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), status)
		return
	}
	if maxTime, err := s.idx.MaxEtagTime(r.Context()); err == nil {
		combined := data.NoteEtagTime
		if maxTime > combined {
			combined = maxTime
		}
		etag := pageETag("note", currentURLString(r), combined, currentUserName(r.Context()))
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.Header().Set("ETag", etag)
			setPrivateCacheHeaders(w)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		setPrivateCacheHeaders(w)
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
		if status == http.StatusUnauthorized {
			s.renderLoginPrompt(w, r, sanitizeReturnURL(r, r.URL.RequestURI()), "", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.attachViewData(r, &data)
	etag := noteCardETag(data.NoteMeta, data.NoteHash, data.NoteEtagTime, currentUserName(r.Context()))
	if etag != "" && strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
		w.Header().Set("ETag", etag)
		setPrivateCacheHeaders(w)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	s.views.RenderTemplateWithCache(w, "note_detail", data, "private, max-age=0, must-revalidate, no-transform")
}

func (s *Server) handleNoteBacklinksFragment(w http.ResponseWriter, r *http.Request, notePath string) {
	data, status, err := s.buildNoteViewData(r, notePath, false)
	if err != nil {
		if status == http.StatusNotFound {
			http.NotFound(w, r)
			return
		}
		if status == http.StatusUnauthorized {
			s.renderLoginPrompt(w, r, sanitizeReturnURL(r, r.URL.RequestURI()), "", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), status)
		return
	}
	if maxTime, err := s.idx.MaxEtagTime(r.Context()); err == nil {
		combined := data.NoteEtagTime
		if maxTime > combined {
			combined = maxTime
		}
		etag := pageETag("backlinks", currentURLString(r), combined, currentUserName(r.Context()))
		if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
			w.Header().Set("ETag", etag)
			setPrivateCacheHeaders(w)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		setPrivateCacheHeaders(w)
	}
	s.attachViewData(r, &data)
	s.views.RenderTemplate(w, "note_backlinks", data)
}

func (s *Server) handleNoteCardFragment(w http.ResponseWriter, r *http.Request, notePath string) {
	data, status, err := s.buildNoteCardData(r, notePath, true)
	if err != nil {
		if status == http.StatusNotFound {
			http.NotFound(w, r)
			return
		}
		if status == http.StatusUnauthorized {
			s.renderLoginPrompt(w, r, sanitizeReturnURL(r, r.URL.RequestURI()), "", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), status)
		return
	}
	s.attachViewData(r, &data)
	data.Short = data.CompactNoteList
	etag := noteCardETag(data.NoteMeta, data.NoteHash, data.NoteEtagTime, currentUserName(r.Context()))
	if etag != "" && strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate, no-transform")
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	s.views.RenderTemplateWithCache(w, "note_detail", data, "private, max-age=0, must-revalidate, no-transform")
}

func (s *Server) renderLoginPrompt(w http.ResponseWriter, r *http.Request, returnTo, message string, status int) {
	if s.auth == nil {
		http.NotFound(w, r)
		return
	}
	data := ViewData{
		Title:           "Login",
		ContentTemplate: "login",
		ErrorMessage:    message,
		ReturnURL:       returnTo,
	}
	s.attachViewData(r, &data)
	if status <= 0 {
		status = http.StatusUnauthorized
	}
	w.WriteHeader(status)
	s.views.RenderPage(w, data)
}

func (s *Server) buildNoteCard(r *http.Request, notePath string) (NoteCard, error) {
	data, status, err := s.buildNoteCardData(r, notePath, false)
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
		FolderLabel:  data.FolderLabel,
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
			if !IsAuthenticated(r.Context()) {
				return ViewData{}, http.StatusUnauthorized, errors.New("unauthorized")
			}
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
		return ViewData{}, http.StatusUnauthorized, errors.New("unauthorized")
	}
	folderLabel := s.noteFolderLabel(r.Context(), notePath, noteMeta.Folder)
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
	activeDate := ""
	baseURL := baseURLForLinks(r, "/")
	activeTodo, activeDue, activeJournal, noteTags := splitSpecialTags(activeTags)
	isAuth := IsAuthenticated(r.Context())
	if !isAuth {
		activeTodo = false
		activeDue = false
		activeJournal = false
		activeTags = noteTags
	}
	urlTags := append([]string{}, noteTags...)
	if activeJournal {
		urlTags = append(urlTags, journalTagName)
	}
	tags, err := s.idx.ListTags(r.Context(), 100, activeFolder, activeRoot, activeJournal, "")
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	allowed := map[string]struct{}{}
	todoCount := 0
	dueCount := 0
	if isAuth {
		todoCount, dueCount, err = s.loadSpecialTagCounts(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
	}
	if len(activeTags) > 0 || activeDate != "" {
		filteredTags, err := s.loadFilteredTags(r, noteTags, activeTodo, activeDue, activeDate, activeFolder, activeRoot, activeJournal, "")
		if err != nil {
			return ViewData{}, http.StatusInternalServerError, err
		}
		for _, tag := range filteredTags {
			allowed[tag.Name] = struct{}{}
		}
		_ = dueCount
	}
	tagLinks := buildTagLinks(urlTags, tags, allowed, baseURL)
	journalCount, err := s.idx.CountJournalNotes(r.Context(), activeFolder, activeRoot, "")
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	tagLinks = appendJournalTagLink(tagLinks, activeJournal, journalCount, baseURL, noteTags)
	updateDays, err := s.idx.ListUpdateDays(r.Context(), 60, activeFolder, activeRoot, "")
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	tagQuery := buildTagsQuery(urlTags)
	filterQuery := queryWithout(baseURL, "d")
	calendar := buildCalendarMonth(calendarReferenceDate(r), updateDays, baseURL, activeDate)
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

	folders, hasRoot, err := s.idx.ListFolders(r.Context(), "")
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	folderTree := buildFolderTree(folders, hasRoot, activeFolder, activeRoot, baseURL)
	journalSidebar, err := s.buildJournalSidebar(r.Context(), time.Now(), "")
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	data := ViewData{
		Title:            meta.Title,
		ContentTemplate:  "view",
		NotePath:         notePath,
		NoteTitle:        meta.Title,
		NoteFileName:     filepath.Base(notePath),
		NoteMeta:         noteMeta,
		FolderLabel:      folderLabel,
		RenderedHTML:     template.HTML(htmlStr),
		Tags:             tags,
		TagLinks:         tagLinks,
		TodoCount:        todoCount,
		DueCount:         dueCount,
		ActiveTags:       urlTags,
		TagQuery:         tagQuery,
		FolderTree:       folderTree,
		ActiveFolder:     activeFolder,
		FolderQuery:      buildFolderQuery(activeFolder, activeRoot),
		FilterQuery:      filterQuery,
		HomeURL:          baseURL,
		ActiveDate:       activeDate,
		DateQuery:        buildDateQuery(activeDate),
		SearchQuery:      activeSearch,
		SearchQueryParam: buildSearchQuery(activeSearch),
		UpdateDays:       updateDays,
		CalendarMonth:    calendar,
		Backlinks:        backlinkViews,
		JournalSidebar:   journalSidebar,
	}
	applyCalendarLinks(&data, baseURL)
	return data, http.StatusOK, nil
}

func (s *Server) buildNoteCardData(r *http.Request, notePath string, hideCompleted bool) (ViewData, int, error) {
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		return ViewData{}, http.StatusBadRequest, err
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			if !IsAuthenticated(r.Context()) {
				return ViewData{}, http.StatusUnauthorized, errors.New("unauthorized")
			}
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
		return ViewData{}, http.StatusUnauthorized, errors.New("unauthorized")
	}
	folderLabel := s.noteFolderLabel(r.Context(), notePath, noteMeta.Folder)
	renderCtx := r.Context()
	if state, ok, err := s.collapsedSectionState(renderCtx, noteMeta.ID); err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	} else if ok {
		renderCtx = withCollapsibleSectionState(renderCtx, state)
	}
	renderContent := normalizedContent
	renderTasks := meta.Tasks
	completedCount := 0
	if hideCompleted {
		filtered, count, tasks := index.FilterCompletedTasksSnippet(string(normalizedContent))
		renderContent = []byte(filtered)
		completedCount = count
		renderTasks = tasks
	}
	htmlStr, err := s.renderNoteBody(renderCtx, renderContent)
	if err != nil {
		return ViewData{}, http.StatusInternalServerError, err
	}
	fileID, err := s.idx.FileIDByPath(r.Context(), notePath)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ViewData{}, http.StatusInternalServerError, err
	}
	if err == nil && IsAuthenticated(r.Context()) {
		htmlStr = decorateTaskCheckboxes(htmlStr, fileID, renderTasks)
	}
	if info != nil {
		labelTime := info.ModTime()
		if noteMeta.Updated.IsZero() {
			noteMeta.Updated = labelTime.Local()
		}
	}

	noteHash := ""
	noteEtagTime := int64(0)
	if summary, err := s.idx.NoteHashByPath(r.Context(), notePath); err == nil {
		noteHash = summary.Hash
		noteEtagTime = summary.EtagTime
		if !summary.UpdatedAt.IsZero() {
			noteMeta.Updated = summary.UpdatedAt
		}
	} else {
		if len(content) > 0 {
			noteHash = index.ContentHash(content)
		}
	}

	noteURL := baseURLForLinks(r, "/notes/"+notePath)

	data := ViewData{
		NotePath:             notePath,
		NoteTitle:            meta.Title,
		NoteMeta:             noteMeta,
		NoteHash:             noteHash,
		NoteEtagTime:         noteEtagTime,
		RenderedHTML:         template.HTML(htmlStr),
		NoteURL:              noteURL,
		FolderLabel:          folderLabel,
		CompletedTaskCount:   completedCount,
		ShowCompletedSummary: hideCompleted,
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
	if !s.requireWriteAccessForPath(w, r, notePath) {
		return
	}
	ownerName, _, err := s.ownerFromNotePath(notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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
		attachments = listAttachmentNames(s.noteAttachmentsDir(ownerName, metaAttrs.ID))
		attachmentBase = "/" + filepath.ToSlash(filepath.Join("attachments", metaAttrs.ID))
	}
	returnURL := sanitizeReturnURL(r, r.URL.Query().Get("return"))
	if returnURL == "" {
		returnURL = sanitizeReturnURL(r, r.Referer())
	}
	if returnURL == "" {
		returnURL = "/"
	}
	ownerOptions, defaultOwner, err := s.ownerOptionsForUser(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	selectedOwner := ownerName
	if selectedOwner == "" {
		selectedOwner = defaultOwner
	}
	if selectedOwner != "" && len(ownerOptions) > 0 {
		found := false
		for _, option := range ownerOptions {
			if option.Name == selectedOwner {
				found = true
				break
			}
		}
		if !found {
			selectedOwner = defaultOwner
		}
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
		OwnerOptions:     ownerOptions,
		SelectedOwner:    selectedOwner,
	}
	s.attachViewData(r, &data)
	s.views.RenderPage(w, data)
}

func (s *Server) handleDeleteNote(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireWriteAccessForPath(w, r, notePath) {
		return
	}
	ctx := r.Context()
	ownerName, _, err := s.ownerFromNotePath(notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
			attachmentPath = s.noteAttachmentsDir(ownerName, meta.ID)
		}
	}
	writeLock, err := s.acquireNoteWriteLock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer writeLock.Release()
	commitPaths := []string{fullPath}
	if attachmentPath != "" {
		commitPaths = append(commitPaths, attachmentPath)
	}
	if err := commitRepoIfDirty(ctx, s.ownerRepoPath(ownerName), "auto: backup before delete", commitPaths...); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	s.commitOwnerRepoAsync(ownerName, "delete "+notePath)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleUpdateWikiLink(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireWriteAccessForPath(w, r, notePath) {
		return
	}
	ownerName, _, err := s.ownerFromNotePath(notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var payload struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		payload.From = r.Form.Get("from")
		payload.To = r.Form.Get("to")
	}
	from := strings.TrimSpace(payload.From)
	to := strings.TrimSpace(payload.To)
	if from == "" || to == "" {
		http.Error(w, "missing wiki link", http.StatusBadRequest)
		return
	}
	to = strings.TrimPrefix(to, "/notes/")
	to = strings.TrimPrefix(to, "notes/")
	to = strings.TrimPrefix(to, "/")
	normalized, err := fs.NormalizeNotePath(to)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !strings.HasSuffix(strings.ToLower(normalized), ".md") {
		normalized = normalized + ".md"
	}
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	contentBytes, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	content := normalizeLineEndings(string(contentBytes))
	frontmatter := index.FrontmatterBlock(content)
	body := index.StripFrontmatter(content)
	re := regexp.MustCompile(`\[\[\s*` + regexp.QuoteMeta(from) + `\s*\]\]`)
	updatedBody := re.ReplaceAllString(body, "[["+normalized+"]]")
	if updatedBody == body {
		http.Error(w, "wiki link not found", http.StatusConflict)
		return
	}
	mergedContent := updatedBody
	if frontmatter != "" {
		mergedContent = frontmatter + "\n" + updatedBody
	}
	mergedContent = normalizeLineEndings(mergedContent)
	mergedContent, err = index.EnsureFrontmatterWithTitleAndUser(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, "", historyUser(r.Context()))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeLock, err := s.acquireNoteWriteLock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer writeLock.Release()
	if err := commitRepoIfDirty(r.Context(), s.ownerRepoPath(ownerName), "auto: backup before edit", fullPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	unlock := s.locker.Lock(notePath)
	if err := fs.WriteFileAtomic(fullPath, []byte(mergedContent), 0o644); err != nil {
		unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	unlock()
	if info, err := os.Stat(fullPath); err == nil {
		_ = s.idx.IndexNote(r.Context(), notePath, []byte(mergedContent), info.ModTime(), info.Size())
	}
	title := ""
	if note, err := s.idx.NoteSummaryByPath(r.Context(), normalized); err == nil {
		title = note.Title
	}
	resp := map[string]string{"path": normalized, "title": title}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleUploadAttachment(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireWriteAccessForPath(w, r, notePath) {
		return
	}
	ownerName, _, err := s.ownerFromNotePath(notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	attachmentsDir := s.noteAttachmentsDir(ownerName, meta.ID)
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

	if isHTMX(r) {
		attachments := listAttachmentNames(s.noteAttachmentsDir(ownerName, meta.ID))
		attachmentBase := "/" + filepath.ToSlash(filepath.Join("attachments", meta.ID))
		data := ViewData{
			NotePath:       notePath,
			Attachments:    attachments,
			AttachmentBase: attachmentBase,
		}
		s.views.RenderTemplate(w, "attachments_list", data)
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
	ownerName := strings.TrimSpace(r.FormValue("owner"))
	if ownerName == "" {
		ownerName = currentUserName(r.Context())
	}
	if ownerName == "" {
		http.Error(w, "owner required", http.StatusBadRequest)
		return
	}
	if !s.requireWriteAccess(w, r, ownerName) {
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

	attachmentsDir := s.tempAttachmentsDir(ownerName, token)
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

	if isHTMX(r) {
		attachments := listAttachmentNames(s.tempAttachmentsDir(ownerName, token))
		data := ViewData{
			Attachments:   attachments,
			UploadToken:   token,
			OwnerOptions:  []OwnerOption{{Name: ownerName, Label: ownerName}},
			SelectedOwner: ownerName,
		}
		s.views.RenderTemplate(w, "attachments_list", data)
		return
	}

	redirectURL := "/notes/new?upload_token=" + url.QueryEscape(token)
	if ownerName != "" {
		redirectURL += "&owner=" + url.QueryEscape(ownerName)
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
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
	ownerName := strings.TrimSpace(r.FormValue("owner"))
	if ownerName == "" {
		ownerName = currentUserName(r.Context())
	}
	if ownerName == "" {
		http.Error(w, "owner required", http.StatusBadRequest)
		return
	}
	if !s.requireWriteAccess(w, r, ownerName) {
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

	targetPath := filepath.Join(s.tempAttachmentsDir(ownerName, token), name)
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectURL := "/notes/new?upload_token=" + url.QueryEscape(token)
	if ownerName != "" {
		redirectURL += "&owner=" + url.QueryEscape(ownerName)
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (s *Server) handleDeleteAttachment(w http.ResponseWriter, r *http.Request, notePath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireWriteAccessForPath(w, r, notePath) {
		return
	}
	ownerName, _, err := s.ownerFromNotePath(notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	targetPath := filepath.Join(s.noteAttachmentsDir(ownerName, meta.ID), name)
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
	noteID, ok := firstPathSegment(clean)
	if !ok || !s.noteIDAccessible(r.Context(), noteID) {
		http.NotFound(w, r)
		return
	}
	ownerName, _, err := s.ownerFromNoteID(r.Context(), noteID)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	attachmentsRoot := filepath.Clean(s.attachmentsRoot(ownerName))
	fullPath := filepath.Clean(filepath.Join(attachmentsRoot, clean))
	if !strings.HasPrefix(fullPath, attachmentsRoot+string(filepath.Separator)) && fullPath != attachmentsRoot {
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

func (s *Server) handleStaticFile(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/static/")
	if rel == "" {
		http.NotFound(w, r)
		return
	}
	clean := filepath.Clean(rel)
	staticRoot := s.staticRoot()
	if staticRoot == "" {
		http.NotFound(w, r)
		return
	}
	fullPath := filepath.Clean(filepath.Join(staticRoot, clean))
	if !strings.HasPrefix(fullPath, staticRoot+string(filepath.Separator)) && fullPath != staticRoot {
		http.NotFound(w, r)
		return
	}
	if info, err := os.Stat(fullPath); err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, fullPath)
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = "/static/scroll.png"
	s.handleStaticFile(w, r)
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

func (s *Server) ensureVideoThumbnail(ctx context.Context, noteID, relPath string) (string, bool) {
	if noteID == "" || relPath == "" {
		return "", false
	}
	assetsRoot := s.assetsRoot()
	if assetsRoot == "" {
		return "", false
	}
	var (
		ownerName string
		videoPath string
		videoInfo os.FileInfo
	)
	if owner, _, err := s.ownerFromNoteID(ctx, noteID); err == nil {
		ownerName = owner
		videoPath = filepath.Join(s.noteAttachmentsDir(ownerName, noteID), filepath.FromSlash(relPath))
		info, err := os.Stat(videoPath)
		if err != nil || info.IsDir() {
			return "", false
		}
		videoInfo = info
	} else {
		userName := currentUserName(ctx)
		if userName == "" {
			return "", false
		}
		candidates := []string{userName}
		if owners, err := s.idx.AccessibleOwnersForUser(ctx, userName); err == nil {
			candidates = append(candidates, owners...)
		}
		for _, candidate := range candidates {
			path := filepath.Join(s.noteAttachmentsDir(candidate, noteID), filepath.FromSlash(relPath))
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			ownerName = candidate
			videoPath = path
			videoInfo = info
			break
		}
		if ownerName == "" {
			return "", false
		}
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
	generated := false
	if needsUpdate {
		if err := os.MkdirAll(thumbDir, 0o755); err != nil {
			slog.Warn("video thumbnail mkdir failed", "err", err)
			return "", false
		}
		if err := generateVideoThumbnail(videoPath, thumbPath); err != nil {
			slog.Warn("video thumbnail generation failed", "err", err)
			return "", false
		}
		generated = true
	}
	if generated {
		if touched, err := s.idx.TouchNoteETagByUID(context.WithoutCancel(ctx), noteID); err != nil {
			slog.Debug("video thumbnail etag touch failed", "note_id", noteID, "err", err)
		} else if touched > 0 {
			slog.Debug("video thumbnail etag touch", "note_id", noteID, "notes", touched)
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

func (s *Server) promoteTempAttachments(owner, token, content string) error {
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
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return fmt.Errorf("owner required")
	}
	tempDir := s.tempAttachmentsDir(owner, token)
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

	attachmentsDir := s.noteAttachmentsDir(owner, meta.ID)
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
	if !s.requireWriteAccessForPath(w, r, notePath) {
		return
	}
	ownerName, _, err := s.ownerFromNotePath(notePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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
	targetOwner := strings.TrimSpace(r.Form.Get("owner"))
	if targetOwner == "" {
		targetOwner = ownerName
	}
	if targetOwner != ownerName {
		if !s.requireWriteAccess(w, r, targetOwner) {
			return
		}
	}
	if err := s.ensureOwnerNotesDir(targetOwner); err != nil {
		returnURL := sanitizeReturnURL(r, r.Form.Get("return_url"))
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			RawContent:       r.Form.Get("content"),
			FrontmatterBlock: normalizeLineEndings(r.Form.Get("frontmatter")),
			ReturnURL:        returnURL,
			ErrorMessage:     err.Error(),
			ErrorReturnURL:   "/notes/" + notePath + "/edit",
		}, http.StatusInternalServerError)
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

	priorityValue := 0
	if priorityInput != "" {
		val, err := strconv.Atoi(priorityInput)
		if err != nil || val <= 0 {
			s.renderEditError(w, r, ViewData{
				Title:            "Edit note",
				ContentTemplate:  "edit",
				NotePath:         notePath,
				RawContent:       content,
				FrontmatterBlock: frontmatter,
				ErrorMessage:     "invalid priority",
				ErrorReturnURL:   "/notes/" + notePath + "/edit",
				ReturnURL:        returnURL,
			}, http.StatusBadRequest)
			return
		}
		priorityValue = val
	}

	saveResult, apiErr := s.saveNoteCommon(r.Context(), saveNoteInput{
		NotePath:       notePath,
		TargetOwner:    targetOwner,
		Content:        content,
		Frontmatter:    frontmatter,
		Visibility:     visibility,
		Folder:         folderInput,
		Priority:       priorityValue,
		RenameDecision: r.Form.Get("rename_decision"),
	})
	if apiErr != nil {
		if apiErr.message == "journal note title cannot change" {
			s.addToast(r, Toast{
				ID:              uuid.NewString(),
				Message:         "Journal note title cannot change.",
				Kind:            "error",
				DurationSeconds: 0,
				CreatedAt:       time.Now(),
			})
			if isHTMX(r) {
				w.Header().Set("HX-Retarget", "#toast-stack")
				w.Header().Set("HX-Reswap", "outerHTML")
				toasts := s.toasts.List(toastKey(r))
				data := ViewData{
					ContentTemplate: "toast",
					ToastItems:      toasts,
				}
				s.attachViewData(r, &data)
				s.views.RenderTemplate(w, "toast", data)
				return
			}
			http.Redirect(w, r, "/notes/"+notePath+"/edit", http.StatusSeeOther)
			return
		}
		status := apiErr.status
		if status == 0 {
			status = http.StatusInternalServerError
		}
		s.renderEditError(w, r, ViewData{
			Title:            "Edit note",
			ContentTemplate:  "edit",
			NotePath:         notePath,
			RawContent:       content,
			FrontmatterBlock: frontmatter,
			ErrorMessage:     apiErr.message,
			ErrorReturnURL:   "/notes/" + notePath + "/edit",
			ReturnURL:        returnURL,
		}, status)
		return
	}

	if saveResult.NoChange {
		targetURL := "/notes/" + saveResult.Path
		if returnURL != "" {
			targetURL = returnURL
		}
		if isHTMX(r) {
			s.addToast(r, Toast{
				ID:              uuid.NewString(),
				Message:         "No changes to save.",
				Kind:            "success",
				DurationSeconds: 3,
				CreatedAt:       time.Now(),
			})
			w.Header().Set("HX-Trigger", "toast:refresh")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.addToast(r, Toast{
			ID:              uuid.NewString(),
			Message:         "No changes to save.",
			Kind:            "success",
			DurationSeconds: 3,
			CreatedAt:       time.Now(),
		})
		http.Redirect(w, r, targetURL, http.StatusSeeOther)
		return
	}

	s.addToast(r, Toast{
		ID:              uuid.NewString(),
		Message:         "Note updated.",
		Kind:            "success",
		DurationSeconds: 3,
		CreatedAt:       time.Now(),
	})
	targetURL := "/notes/" + saveResult.TargetPath
	if returnURL != "" {
		targetURL = returnURL
	}
	if isHTMX(r) {
		w.Header().Set("X-Redirect-Location", targetURL)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}

type apiNoteSaveRequest struct {
	Path           string `json:"path"`
	Content        string `json:"content"`
	Frontmatter    string `json:"frontmatter"`
	Visibility     string `json:"visibility"`
	Folder         string `json:"folder"`
	Priority       int    `json:"priority"`
	Owner          string `json:"owner"`
	RenameDecision string `json:"rename_decision"`
}

type apiNoteSaveResponse struct {
	Path       string `json:"path"`
	TargetPath string `json:"target_path"`
	Created    bool   `json:"created"`
	Moved      bool   `json:"moved"`
	Message    string `json:"message"`
}

type saveNoteInput struct {
	NotePath       string
	TargetOwner    string
	Content        string
	Frontmatter    string
	Visibility     string
	Folder         string
	Priority       int
	RenameDecision string
}

type saveNoteResult struct {
	Path       string
	TargetPath string
	Created    bool
	Moved      bool
	NoChange   bool
}

func (s *Server) handleAPINotes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !IsAuthenticated(r.Context()) {
		writeAPIError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10<<20))
	decoder.DisallowUnknownFields()
	var payload apiNoteSaveRequest
	if err := decoder.Decode(&payload); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(payload.Path) == "" {
		writeAPIError(w, http.StatusBadRequest, "path required")
		return
	}
	noteRef := strings.TrimPrefix(strings.TrimSpace(payload.Path), "/")
	notePath, err := s.resolveNotePath(r.Context(), noteRef)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if notePath == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid path")
		return
	}
	saveResult, apiErr := s.saveNoteCommon(r.Context(), saveNoteInput{
		NotePath:       notePath,
		TargetOwner:    payload.Owner,
		Content:        payload.Content,
		Frontmatter:    payload.Frontmatter,
		Visibility:     payload.Visibility,
		Folder:         payload.Folder,
		Priority:       payload.Priority,
		RenameDecision: payload.RenameDecision,
	})
	if apiErr != nil {
		writeAPIError(w, apiErr.status, apiErr.message)
		return
	}
	message := "Note updated."
	if saveResult.Created {
		message = "Note created."
	}
	if saveResult.NoChange {
		message = "No changes to save."
	}
	writeAPIJSON(w, http.StatusOK, apiNoteSaveResponse{
		Path:       saveResult.Path,
		TargetPath: saveResult.TargetPath,
		Created:    saveResult.Created,
		Moved:      saveResult.Moved,
		Message:    message,
	})
}

func sanitizeTaskDoneTokens(content string) string {
	frontmatter := index.FrontmatterBlock(content)
	body := content
	if frontmatter != "" {
		body = strings.TrimPrefix(content, frontmatter)
		body = strings.TrimPrefix(body, "\n")
	}
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		match := taskToggleLineRe.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		if strings.ToLower(match[2]) != "x" {
			cleaned := taskDoneTokenRe.ReplaceAllString(line, "")
			lines[i] = strings.TrimRight(cleaned, " \t")
		}
	}
	body = strings.Join(lines, "\n")
	if frontmatter == "" {
		return body
	}
	return frontmatter + "\n" + body
}

func (s *Server) saveNoteCommon(ctx context.Context, input saveNoteInput) (saveNoteResult, *apiError) {
	notePath := strings.TrimSpace(input.NotePath)
	if notePath == "" {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: "invalid path"}
	}
	notePath = strings.TrimPrefix(notePath, "/")
	ownerName, relPath, err := s.ownerFromNotePath(notePath)
	if err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: err.Error()}
	}
	if apiErr := s.apiWriteAccessForRelPath(ctx, ownerName, relPath); apiErr != nil {
		return saveNoteResult{}, apiErr
	}

	targetOwner := strings.TrimSpace(input.TargetOwner)
	if targetOwner == "" {
		targetOwner = ownerName
	}
	if targetOwner != ownerName {
		if apiErr := s.apiWriteAccessForOwner(ctx, targetOwner); apiErr != nil {
			return saveNoteResult{}, apiErr
		}
	}
	if err := s.ensureOwnerNotesDir(targetOwner); err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
	}

	content := normalizeLineEndings(input.Content)
	if content == "" {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: "content required"}
	}
	frontmatter := normalizeLineEndings(input.Frontmatter)
	visibility := strings.TrimSpace(input.Visibility)
	folderInput := input.Folder
	priorityInput := input.Priority
	if priorityInput < 0 {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: "invalid priority"}
	}

	derivedTitle := index.DeriveTitleFromBody(content)
	if derivedTitle == "" {
		derivedTitle = time.Now().Format("2006-01-02 15-04")
	}
	preserveUpdated := isJournalNotePath(notePath)
	folder, err := normalizeFolderPath(folderInput)
	if err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: "invalid folder"}
	}
	fullPath, err := fs.NoteFilePath(s.cfg.RepoPath, notePath)
	if err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: err.Error()}
	}
	existingContent, err := os.ReadFile(fullPath)
	created := false
	if err != nil {
		if os.IsNotExist(err) {
			created = true
		} else {
			return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
		}
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
			mergedContent, err = index.EnsureFrontmatterWithTitleAndUserNoUpdated(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(ctx))
		} else {
			mergedContent, err = index.EnsureFrontmatterWithTitleAndUser(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(ctx))
		}
		if err != nil {
			return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
		}
	}
	if updated, err := index.SetVisibility(mergedContent, visibility); err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: err.Error()}
	} else {
		mergedContent = updated
	}
	priority := ""
	if priorityInput > 0 {
		priority = strconv.Itoa(priorityInput)
	}
	if updated, err := index.SetPriority(mergedContent, priority); err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: err.Error()}
	} else {
		mergedContent = updated
	}
	if updated, err := index.SetFolder(mergedContent, folder); err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: err.Error()}
	} else {
		mergedContent = updated
	}
	mergedContent = sanitizeTaskDoneTokens(mergedContent)
	titleChanged := oldTitle != "" && oldTitle != derivedTitle
	if preserveUpdated && titleChanged {
		return saveNoteResult{}, &apiError{status: http.StatusConflict, message: "journal note title cannot change"}
	}
	desiredRel := fs.EnsureMDExt(slugify(derivedTitle))
	if folder != "" {
		desiredRel = filepath.ToSlash(filepath.Join(folder, desiredRel))
	}
	desiredPath := filepath.ToSlash(filepath.Join(targetOwner, desiredRel))
	pathChanged := filepath.ToSlash(notePath) != desiredPath
	decision := input.RenameDecision
	autoMove := !preserveUpdated && pathChanged

	if err == nil && hadFrontmatter && mergedContent == existingContentNormalized {
		return saveNoteResult{
			Path:       notePath,
			TargetPath: notePath,
			Created:    created,
			Moved:      false,
			NoChange:   true,
		}, nil
	}

	if hadFrontmatter {
		if preserveUpdated {
			mergedContent, err = index.EnsureFrontmatterWithTitleAndUserNoUpdated(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(ctx))
		} else {
			mergedContent, err = index.EnsureFrontmatterWithTitleAndUser(mergedContent, time.Now(), s.cfg.UpdatedHistoryMax, derivedTitle, historyUser(ctx))
		}
		if err != nil {
			return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
		}
	}

	unlock := s.locker.Lock(notePath)
	defer unlock()

	targetPath := notePath
	targetFullPath := fullPath
	moveConfirmed := (decision != "cancel") && (autoMove || (!preserveUpdated && titleChanged))
	if !preserveUpdated && (titleChanged || pathChanged) && moveConfirmed {
		targetPath = desiredPath
		targetFullPath, err = fs.NoteFilePath(s.cfg.RepoPath, targetPath)
		if err != nil {
			return saveNoteResult{}, &apiError{status: http.StatusBadRequest, message: err.Error()}
		}
		if targetPath != notePath {
			if _, err := os.Stat(targetFullPath); err == nil {
				return saveNoteResult{}, &apiError{status: http.StatusConflict, message: "note already exists"}
			}
			if err != nil && !os.IsNotExist(err) {
				return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(targetFullPath), 0o755); err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
	}
	writeLock, err := s.acquireNoteWriteLock()
	if err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
	}
	defer writeLock.Release()
	metaAttrs := index.FrontmatterAttributes(mergedContent)
	commitPaths := []string{fullPath}
	if metaAttrs.ID != "" {
		commitPaths = append(commitPaths, s.noteAttachmentsDir(ownerName, metaAttrs.ID))
	}
	if err := commitRepoIfDirty(ctx, s.ownerRepoPath(ownerName), "auto: backup before edit", commitPaths...); err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
	}
	if err := fs.WriteFileAtomic(targetFullPath, []byte(mergedContent), 0o644); err != nil {
		return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
	}
	if targetPath != notePath && metaAttrs.ID != "" && targetOwner != ownerName {
		oldAttach := s.noteAttachmentsDir(ownerName, metaAttrs.ID)
		newAttach := s.noteAttachmentsDir(targetOwner, metaAttrs.ID)
		if _, err := os.Stat(oldAttach); err == nil {
			if _, err := os.Stat(newAttach); err == nil {
				return saveNoteResult{}, &apiError{status: http.StatusConflict, message: "attachments already exist for new owner"}
			}
			if err := os.MkdirAll(filepath.Dir(newAttach), 0o755); err != nil {
				return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
			}
			if err := os.Rename(oldAttach, newAttach); err != nil {
				return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
			}
		}
	}
	if targetPath != notePath {
		if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
			return saveNoteResult{}, &apiError{status: http.StatusInternalServerError, message: err.Error()}
		}
		_ = s.idx.RemoveNoteByPath(ctx, notePath)
	}
	info, err := os.Stat(targetFullPath)
	if err == nil {
		_ = s.idx.IndexNote(ctx, targetPath, []byte(mergedContent), info.ModTime(), info.Size())
	}
	s.commitOwnerRepoAsync(targetOwner, "save "+targetPath)
	if targetOwner != ownerName {
		s.commitOwnerRepoAsync(ownerName, "move "+notePath)
	}

	return saveNoteResult{
		Path:       notePath,
		TargetPath: targetPath,
		Created:    created,
		Moved:      targetPath != notePath,
		NoChange:   false,
	}, nil
}

func commitRepoIfDirty(ctx context.Context, repoPath string, message string, paths ...string) error {
	if repoPath == "" {
		return nil
	}
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	pathspecs, err := gitPathspecs(repoPath, paths)
	if err != nil {
		return err
	}
	statusArgs := []string{"status", "--porcelain"}
	if len(pathspecs) > 0 {
		statusArgs = append(statusArgs, "--")
		statusArgs = append(statusArgs, pathspecs...)
	}
	statusCmd := exec.CommandContext(ctx, "git", statusArgs...)
	statusCmd.Dir = repoPath
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(statusOut))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git status failed: %s", msg)
	}
	if len(bytes.TrimSpace(statusOut)) == 0 {
		return nil
	}
	addCmd := exec.CommandContext(ctx, "git", "add", "-A")
	addCmd.Dir = repoPath
	if output, err := addCmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git add failed: %s", msg)
	}
	commitCmd := exec.CommandContext(ctx, "git", "commit", "-m", message)
	commitCmd.Dir = repoPath
	if output, err := commitCmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("git commit failed: %s", msg)
	}
	return nil
}

func (s *Server) commitOwnerRepoAsync(ownerName string, message string) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = "auto: notes"
	}
	repoPath := s.ownerRepoPath(ownerName)
	if repoPath == "" {
		return
	}
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
		if os.IsNotExist(err) {
			slog.Debug("commit skipped (no git repo)", "owner", ownerName, "repo", repoPath)
			return
		}
		slog.Warn("commit skipped (stat git repo failed)", "owner", ownerName, "repo", repoPath, "err", err)
		return
	}
	slog.Debug("commit queued", "owner", ownerName)
	go func() {
		unlock, err := syncer.Acquire(10 * time.Second)
		if err != nil {
			slog.Debug("commit skipped", "owner", ownerName, "err", err)
			return
		}
		defer unlock()
		opts := syncer.Options{
			HomeDir:            s.cfg.DataPath,
			GitCredentialsFile: filepath.Join(s.cfg.DataPath, ownerName+".cred"),
			GitConfigGlobal:    filepath.Join(s.cfg.DataPath, ownerName+".gitconfig"),
			UserName:           ownerName,
			CommitMessage:      message,
		}
		output, err := syncer.CommitOnlyWithOptions(context.Background(), repoPath, opts)
		logCommitOutput(ownerName, output, err)
	}()
}

func logCommitOutput(owner string, output string, runErr error) {
	if runErr != nil {
		slog.Warn("commit failed", "owner", owner, "err", runErr)
	}
	if strings.TrimSpace(output) == "" {
		return
	}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(trimmed, "$ "):
			slog.Debug("commit cmd", "owner", owner, "cmd", strings.TrimPrefix(trimmed, "$ "))
		case strings.Contains(lower, "-> error") || strings.HasPrefix(lower, "error:"):
			slog.Warn("commit cmd error", "owner", owner, "line", trimmed)
		default:
			slog.Debug("commit cmd output", "owner", owner, "line", trimmed)
		}
	}
}

func gitPathspecs(repoPath string, paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	seen := map[string]struct{}{}
	pathspecs := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		rel, err := filepath.Rel(repoPath, p)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(rel, "..") || rel == "." {
			continue
		}
		rel = filepath.ToSlash(rel)
		if _, ok := seen[rel]; ok {
			continue
		}
		seen[rel] = struct{}{}
		pathspecs = append(pathspecs, rel)
	}
	return pathspecs, nil
}

type collapsedSectionsPayload struct {
	Collapsed []collapsedSectionPayloadItem `json:"collapsed"`
}

type collapsedSectionPayloadItem struct {
	LineNo int `json:"line_no"`
}

type gitCredentialEntry struct {
	Host string
	Path string
	User string
	Pass string
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
	lineNos := make([]int, 0, len(payload.Collapsed))
	for _, item := range payload.Collapsed {
		if item.LineNo <= 0 {
			continue
		}
		lineNos = append(lineNos, item.LineNo)
	}
	writeLock, err := s.acquireNoteWriteLock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer writeLock.Release()
	updatedContent, err := index.SetCollapsedH2LineNumbers(string(content), lineNos)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := fs.WriteFileAtomic(fullPath, []byte(updatedContent), 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if info, err := os.Stat(fullPath); err == nil {
		_ = s.idx.IndexNoteIfChanged(r.Context(), notePath, []byte(updatedContent), info.ModTime(), info.Size())
	}
	w.WriteHeader(http.StatusNoContent)
}

func listGitRemotes(repoDir string) ([]GitRemoteCred, error) {
	if strings.TrimSpace(repoDir) == "" {
		return nil, nil
	}
	cmd := exec.Command("git", "remote", "-v")
	cmd.Dir = repoDir
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(output), "\n")
	seen := map[string]GitRemoteCred{}
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		alias := fields[0]
		rawURL := fields[1]
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			continue
		}
		host := parsed.Host
		path := strings.TrimPrefix(parsed.Path, "/")
		key := alias + "|" + host + "|" + path
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = GitRemoteCred{
			Alias: alias,
			URL:   rawURL,
			Host:  host,
		}
	}
	out := make([]GitRemoteCred, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Alias == "origin" && out[j].Alias != "origin" {
			return true
		}
		if out[j].Alias == "origin" && out[i].Alias != "origin" {
			return false
		}
		if out[i].Alias == out[j].Alias {
			return out[i].Host < out[j].Host
		}
		return out[i].Alias < out[j].Alias
	})
	return out, nil
}

func parseGitCredentialsFile(path string) []gitCredentialEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	entries := make([]gitCredentialEntry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed, err := url.Parse(line)
		if err != nil || parsed.Host == "" {
			continue
		}
		user := ""
		pass := ""
		if parsed.User != nil {
			user = parsed.User.Username()
			pass, _ = parsed.User.Password()
		}
		entries = append(entries, gitCredentialEntry{
			Host: parsed.Host,
			Path: strings.TrimPrefix(parsed.Path, "/"),
			User: user,
			Pass: pass,
		})
	}
	return entries
}

func mergeGitRemoteCreds(remotes []GitRemoteCred, creds []gitCredentialEntry) []GitRemoteCred {
	for i := range remotes {
		for _, cred := range creds {
			if remotes[i].Host == cred.Host {
				remotes[i].User = cred.User
				remotes[i].HasToken = cred.Pass != ""
				break
			}
		}
	}
	return remotes
}

func (s *Server) renderEditError(w http.ResponseWriter, r *http.Request, data ViewData, status int) {
	if status >= http.StatusInternalServerError || data.ErrorMessage != "" {
		slog.Error(
			"edit error",
			"path", r.URL.Path,
			"status", status,
			"error", data.ErrorMessage,
		)
	}
	if data.ErrorMessage != "" {
		s.addToast(r, Toast{
			ID:              uuid.NewString(),
			Message:         data.ErrorMessage,
			Kind:            "error",
			DurationSeconds: 5,
			CreatedAt:       time.Now(),
		})
	}
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
	parseContext.Set(chatgptEmbedContextKey, ctx)
	parseContext.Set(attachmentVideoEmbedContextKey, attachmentVideoEmbedContextValue{ctx: ctx, server: s})
	parseContext.Set(linkTitleContextKey, ctx)
	if state, ok := collapsibleSectionStateFromContext(ctx); ok {
		parseContext.Set(collapsibleSectionContextKey, state)
	}
	if err := mdRenderer.Convert([]byte(body), &b, parser.WithContext(parseContext)); err != nil {
		return "", err
	}
	return applyRenderReplacements(b.String()), nil
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
	parseContext.Set(chatgptEmbedContextKey, ctx)
	parseContext.Set(attachmentVideoEmbedContextKey, attachmentVideoEmbedContextValue{ctx: ctx, server: s})
	parseContext.Set(linkTitleContextKey, ctx)
	if state, ok := collapsibleSectionStateFromContext(ctx); ok {
		parseContext.Set(collapsibleSectionContextKey, state)
	}
	if err := mdRenderer.Convert([]byte(body), &b, parser.WithContext(parseContext)); err != nil {
		return "", err
	}
	return applyRenderReplacements(b.String()), nil
}

func (s *Server) renderLineMarkdown(ctx context.Context, line string) (template.HTML, error) {
	if strings.TrimSpace(line) == "" {
		return template.HTML(""), nil
	}
	line = s.expandWikiLinks(ctx, line)
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
		if label == "" {
			label = trimmed
		}
		if err == nil && target != "" {
			return fmt.Sprintf("[%s](/notes/%s)", label, target)
		}
		return fmt.Sprintf("[%s](/__missing__?ref=%s)", label, url.QueryEscape(trimmed))
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
	candidates, err := s.expandWikiLinkCandidates(ctx, candidates)
	if err != nil {
		return "", "", err
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
				note, err := s.idx.NoteSummaryByPath(ctx, variant)
				if err != nil {
					return "", "", err
				}
				return variant, note.Title, nil
			}
		}
	}
	return "", "", nil
}

func (s *Server) expandWikiLinkCandidates(ctx context.Context, candidates []string) ([]string, error) {
	owner := currentUserName(ctx)
	if owner == "" {
		return candidates, nil
	}
	out := make([]string, 0, len(candidates)*2)
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		out = append(out, candidate)
		first, ok := leadingPathSegment(candidate)
		if ok {
			isOwner, err := s.isOwnerName(ctx, first)
			if err != nil {
				return nil, err
			}
			if isOwner {
				continue
			}
		}
		out = append(out, owner+"/"+candidate)
	}
	return out, nil
}

func (s *Server) isOwnerName(ctx context.Context, name string) (bool, error) {
	if strings.TrimSpace(name) == "" {
		return false, nil
	}
	_, err := s.idx.LookupOwnerIDs(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func leadingPathSegment(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	parts := strings.SplitN(value, "/", 2)
	if len(parts) < 2 {
		return "", false
	}
	if strings.TrimSpace(parts[0]) == "" {
		return "", false
	}
	return parts[0], true
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

func sidebarRequest(r *http.Request) (*http.Request, string) {
	raw := strings.TrimSpace(r.Header.Get("HX-Current-URL"))
	if raw == "" {
		raw = strings.TrimSpace(r.Referer())
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return r, "/"
	}
	basePath := sidebarBasePath(parsed.Path)
	clone := *r
	clone.URL = parsed
	return &clone, basePath
}

func sidebarBasePath(path string) string {
	if strings.HasPrefix(path, "/daily/") {
		return path
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}
