package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gwiki/internal/auth"
	"gwiki/internal/config"
	"gwiki/internal/index"
	"gwiki/internal/syncer"
	"gwiki/internal/web"

	"golang.org/x/term"
)

func main() {
	level := parseLogLevel(os.Getenv("WIKI_DEBUG_LEVEL"))
	pretty := strings.EqualFold(os.Getenv("WIKI_LOG_PRETTY"), "1") || strings.EqualFold(os.Getenv("WIKI_LOG_PRETTY"), "true")
	if strings.TrimSpace(os.Getenv("DEV")) != "" {
		file, err := os.Create("dev.log")
		if err != nil {
			slog.Error("open log file", "path", "dev.log", "err", err)
		} else {
			defer file.Close()
			_, _ = fmt.Fprintf(file, "=== gwiki dev log start %s ===\n", time.Now().Format(time.RFC3339))
			fileHandler := slog.NewTextHandler(file, &slog.HandlerOptions{Level: slog.LevelDebug})
			consoleHandler := newPrettyHandler(os.Stdout, level)
			if !pretty {
				consoleHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
			}
			slog.SetDefault(slog.New(&teeHandler{handlers: []slog.Handler{consoleHandler, fileHandler}}))
		}
	} else {
		var handler slog.Handler
		if pretty {
			handler = newPrettyHandler(os.Stdout, level)
		} else {
			handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
		}
		slog.SetDefault(slog.New(handler))
	}

	cfg := config.Load()
	version := strings.TrimSpace(web.BuildVersion)
	if version == "" {
		version = "dev"
	}
	slog.Info("startup", "build_version", version)
	index.SetBuildVersion(web.BuildVersion)
	if cfg.RepoPath == "" {
		slog.Error("WIKI_REPO_PATH is required")
		os.Exit(1)
	}
	if cfg.DataPath == "" {
		slog.Error("WIKI_DATA_PATH is required")
		os.Exit(1)
	}

	dataPath, err := resolveDataPath(cfg)
	if err != nil {
		slog.Error("resolve data path", "err", err)
		os.Exit(1)
	}
	cfg.DataPath = dataPath
	if err := os.MkdirAll(cfg.DataPath, 0o755); err != nil {
		slog.Error("create data dir", "err", err)
		os.Exit(1)
	}

	idx, err := index.OpenWithOptions(filepath.Join(cfg.DataPath, "index.sqlite"), index.OpenOptions{
		BusyTimeout: cfg.DBBusyTimeout,
	})
	if err != nil {
		slog.Error("open index", "err", err)
		os.Exit(1)
	}
	defer idx.Close()
	idx.SetLockTimeout(cfg.DBLockTimeout)

	users := make([]string, 0)
	if cfg.AuthFile != "" {
		fileUsers, err := auth.LoadFile(cfg.AuthFile)
		if err != nil {
			slog.Error("load auth file", "err", err)
			os.Exit(1)
		}
		for user := range fileUsers {
			users = append(users, user)
		}
	}
	if cfg.AuthUser != "" {
		users = append(users, cfg.AuthUser)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := idx.InitWithOwners(ctx, cfg.RepoPath, users); err != nil {
		slog.Error("init index", "err", err)
		os.Exit(1)
	}
	accessFile, err := auth.LoadAccessFromRepo(cfg.RepoPath)
	if err != nil {
		slog.Error("load access file", "err", err)
		os.Exit(1)
	}
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
	if _, _, err := idx.SyncAuthSources(ctx, users, accessRules); err != nil {
		slog.Error("sync access", "err", err)
		os.Exit(1)
	}
	syncGitHistoryOnStartup(ctx, cfg, idx, users)

	srv, err := web.NewServer(cfg, idx)
	if err != nil {
		slog.Error("auth init", "err", err)
		os.Exit(1)
	}
	srv.StartSignalPoller()
	startGitScheduler(cfg, idx)
	slog.Info("listening", "addr", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Handler()); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func parseLogLevel(raw string) slog.Leveler {
	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		level.Set(slog.LevelDebug)
	case "info":
		level.Set(slog.LevelInfo)
	case "warn", "warning":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	}
	return level
}

type teeHandler struct {
	handlers []slog.Handler
}

func (t *teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range t.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (t *teeHandler) Handle(ctx context.Context, record slog.Record) error {
	for _, h := range t.handlers {
		if h.Enabled(ctx, record.Level) {
			if err := h.Handle(ctx, record); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, 0, len(t.handlers))
	for _, h := range t.handlers {
		out = append(out, h.WithAttrs(attrs))
	}
	return &teeHandler{handlers: out}
}

func (t *teeHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, 0, len(t.handlers))
	for _, h := range t.handlers {
		out = append(out, h.WithGroup(name))
	}
	return &teeHandler{handlers: out}
}

func resolveDataPath(cfg config.Config) (string, error) {
	dataPath := strings.TrimSpace(cfg.DataPath)
	if dataPath == "" && cfg.RepoPath != "" {
		dataPath = filepath.Join(cfg.RepoPath, ".wiki")
	}
	if dataPath == "" {
		return "", fmt.Errorf("data path is required")
	}
	return filepath.Abs(dataPath)
}

type syncTarget struct {
	Owner string
	Path  string
}

func startGitScheduler(cfg config.Config, idx *index.Index) {
	if cfg.GitSchedule <= 0 {
		slog.Info("git scheduler disabled")
		return
	}
	ctx := context.Background()
	ticker := time.NewTicker(cfg.GitSchedule)
	slog.Info("git scheduler enabled", "interval", cfg.GitSchedule.String())
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runScheduledSync(ctx, cfg, idx)
			}
		}
	}()
}

func runScheduledSync(ctx context.Context, cfg config.Config, idx *index.Index) {
	users, err := loadAuthUsers(cfg)
	if err != nil {
		slog.Warn("sync schedule: load auth users failed", "err", err)
		return
	}
	targets, err := discoverSyncTargets(cfg.RepoPath, users)
	if err != nil {
		slog.Warn("sync schedule: list targets failed", "err", err)
		return
	}
	if len(targets) == 0 {
		return
	}
	anySuccess := false
	for _, target := range targets {
		if removed, err := pruneEmptyNotesDirs(target.Path); err != nil {
			slog.Warn("sync schedule prune notes", "owner", target.Owner, "err", err)
		} else if removed > 0 {
			slog.Debug("sync schedule prune notes", "owner", target.Owner, "removed", removed)
		}
		unlock, err := syncer.Acquire(10 * time.Second)
		if err != nil {
			slog.Warn("sync schedule: busy", "owner", target.Owner, "err", err)
			continue
		}
		opts := syncer.Options{
			HomeDir:            cfg.DataPath,
			GitCredentialsFile: filepath.Join(cfg.DataPath, target.Owner+".cred"),
			GitConfigGlobal:    filepath.Join(cfg.DataPath, target.Owner+".gitconfig"),
			UserName:           target.Owner,
			CommitMessage:      "scheduler sync",
		}
		if cleaned, err := cleanupExpiredFiles(ctx, idx, target); err != nil {
			slog.Warn("sync schedule cleanup failed", "owner", target.Owner, "err", err)
		} else if cleaned > 0 {
			commitOpts := opts
			commitOpts.CommitMessage = "cleanup attachments"
			output, commitErr := syncer.CommitOnlyWithOptions(ctx, target.Path, commitOpts)
			if commitErr != nil {
				slog.Warn("sync schedule cleanup commit failed", "owner", target.Owner, "err", commitErr)
			}
			logOutput, logErr := syncer.LogGraphWithOptions(ctx, target.Path, 10, commitOpts)
			if logErr != nil {
				slog.Warn("sync schedule cleanup log graph failed", "owner", target.Owner, "err", logErr)
			}
			logSyncOutput(target.Owner, output+logOutput)
		}
		output, runErr := syncer.RunWithOptions(ctx, target.Path, opts)
		unlock()
		if runErr != nil {
			slog.Warn("sync schedule failed", "owner", target.Owner, "err", runErr)
			if err := idx.SetUserSyncState(ctx, target.Owner, "failed", time.Now()); err != nil {
				slog.Warn("sync schedule state update failed", "owner", target.Owner, "status", "failed", "err", err)
			}
			continue
		}
		logOutput, logErr := syncer.LogGraphWithOptions(ctx, target.Path, 10, opts)
		output += logOutput
		if logErr != nil {
			slog.Warn("sync schedule log graph failed", "owner", target.Owner, "err", logErr)
		}
		logSyncOutput(target.Owner, output)
		if inserted, histErr := idx.SyncGitHistory(ctx, target.Owner, target.Path); histErr != nil {
			slog.Warn("sync schedule history failed", "owner", target.Owner, "err", histErr)
		} else if inserted > 0 {
			slog.Info("sync schedule history updated", "owner", target.Owner, "inserted", inserted)
		}
		if err := idx.SetUserSyncState(ctx, target.Owner, "success", time.Now()); err != nil {
			slog.Warn("sync schedule state update failed", "owner", target.Owner, "status", "success", "err", err)
		}
		anySuccess = true
	}
	if anySuccess {
		scanned, updated, cleaned, recheckErr := idx.RecheckFromFS(ctx, cfg.RepoPath)
		if recheckErr != nil {
			slog.Warn("sync schedule recheck failed", "err", recheckErr)
			return
		}
		slog.Info("sync schedule recheck", "scanned", scanned, "updated", updated, "cleaned", cleaned)
		if err := refreshAuthSources(ctx, cfg, idx, users); err != nil {
			slog.Warn("sync schedule auth refresh failed", "err", err)
		}
	}
}

func cleanupExpiredFiles(ctx context.Context, idx *index.Index, target syncTarget) (int, error) {
	if idx == nil {
		return 0, nil
	}
	now := time.Now()
	removed := 0
	for {
		expired, err := idx.ListExpiredFileCleanup(ctx, target.Owner, now, 200)
		if err != nil {
			return removed, err
		}
		if len(expired) == 0 {
			return removed, nil
		}
		removedPaths := make([]string, 0, len(expired))
		for _, rel := range expired {
			rel = filepath.Clean(filepath.FromSlash(rel))
			if rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			full := filepath.Join(target.Path, rel)
			if !strings.HasPrefix(full, target.Path+string(filepath.Separator)) && full != target.Path {
				continue
			}
			if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
				slog.Warn("cleanup expired file", "owner", target.Owner, "path", rel, "err", err)
				continue
			}
			removedPaths = append(removedPaths, rel)
		}
		if len(removedPaths) == 0 {
			return removed, nil
		}
		if _, err := idx.ClearFileCleanup(ctx, target.Owner, removedPaths); err != nil {
			return removed, err
		}
		removed += len(removedPaths)
		if len(expired) < 200 {
			return removed, nil
		}
	}
}

func loadAuthUsers(cfg config.Config) ([]string, error) {
	users := make([]string, 0)
	if cfg.AuthFile != "" {
		fileUsers, err := auth.LoadFile(cfg.AuthFile)
		if err != nil {
			return nil, err
		}
		for user := range fileUsers {
			users = append(users, user)
		}
	}
	if cfg.AuthUser != "" {
		users = append(users, cfg.AuthUser)
	}
	return users, nil
}

func refreshAuthSources(ctx context.Context, cfg config.Config, idx *index.Index, users []string) error {
	accessFile, err := auth.LoadAccessFromRepo(cfg.RepoPath)
	if err != nil {
		return err
	}
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
	_, _, err = idx.SyncAuthSources(ctx, users, accessRules)
	return err
}

func pruneEmptyNotesDirs(repoPath string) (int, error) {
	notesRoot := filepath.Join(repoPath, "notes")
	if info, err := os.Stat(notesRoot); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	} else if !info.IsDir() {
		return 0, nil
	}
	var dirs []string
	err := filepath.WalkDir(notesRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	removed := 0
	for i := len(dirs) - 1; i >= 0; i-- {
		dir := dirs[i]
		entries, err := os.ReadDir(dir)
		if err != nil {
			return removed, err
		}
		if len(entries) > 0 {
			continue
		}
		if err := os.Remove(dir); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, err
		}
		removed++
	}
	if removed == 0 {
		return 0, nil
	}
	if entries, err := os.ReadDir(notesRoot); err == nil && len(entries) == 0 {
		_ = os.Remove(notesRoot)
	}
	return removed, nil
}

func syncGitHistoryOnStartup(ctx context.Context, cfg config.Config, idx *index.Index, users []string) {
	targets, err := discoverSyncTargets(cfg.RepoPath, users)
	if err != nil {
		slog.Warn("git history startup: list targets failed", "err", err)
		return
	}
	for _, target := range targets {
		inserted, err := idx.SyncGitHistory(ctx, target.Owner, target.Path)
		if err != nil {
			slog.Warn("git history startup failed", "owner", target.Owner, "err", err)
			continue
		}
		if inserted > 0 {
			slog.Info("git history startup updated", "owner", target.Owner, "inserted", inserted)
		}
	}
}

func discoverSyncTargets(repoPath string, users []string) ([]syncTarget, error) {
	owners := make(map[string]struct{})
	for _, user := range users {
		user = strings.TrimSpace(user)
		if user == "" {
			continue
		}
		owners[user] = struct{}{}
	}
	if len(owners) == 0 {
		return nil, nil
	}
	targets := make([]syncTarget, 0, len(owners))
	for owner := range owners {
		if strings.HasPrefix(owner, ".") {
			continue
		}
		repoDir := filepath.Join(repoPath, owner)
		if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
			continue
		}
		targets = append(targets, syncTarget{Owner: owner, Path: repoDir})
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Owner < targets[j].Owner
	})
	return targets, nil
}

func logSyncOutput(owner string, output string) {
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
			slog.Info("sync cmd", "owner", owner, "cmd", strings.TrimPrefix(trimmed, "$ "))
		case strings.Contains(lower, "-> error") || strings.HasPrefix(lower, "error:"):
			slog.Error("sync cmd error", "owner", owner, "line", trimmed)
		default:
			slog.Info("sync cmd output", "owner", owner, "line", trimmed)
		}
	}
}

type prettyHandler struct {
	w            io.Writer
	level        slog.Leveler
	colorEnabled bool
	attrs        []slog.Attr
	groups       []string
}

func newPrettyHandler(w io.Writer, level slog.Leveler) slog.Handler {
	return &prettyHandler{
		w:            w,
		level:        level,
		colorEnabled: isTerminalWriter(w),
	}
}

func (h *prettyHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= h.level.Level()
}

func (h *prettyHandler) Handle(_ context.Context, r slog.Record) error {
	if !h.Enabled(context.Background(), r.Level) {
		return nil
	}
	var b strings.Builder
	ts := r.Time.Format("2006-01-02 15:04:05")
	b.WriteString(ts)
	b.WriteString(" ")
	b.WriteString(colorizeLevel(r.Level, h.colorEnabled))
	b.WriteString(" ")
	b.WriteString(r.Message)
	b.WriteString("\n")
	for _, attr := range h.attrs {
		h.writeAttr(&b, attr)
	}
	r.Attrs(func(attr slog.Attr) bool {
		h.writeAttr(&b, attr)
		return true
	})
	b.WriteString("\n")
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &prettyHandler{
		w:            h.w,
		level:        h.level,
		colorEnabled: h.colorEnabled,
		attrs:        append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups:       append([]string{}, h.groups...),
	}
	return next
}

func (h *prettyHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := &prettyHandler{
		w:            h.w,
		level:        h.level,
		colorEnabled: h.colorEnabled,
		attrs:        append([]slog.Attr{}, h.attrs...),
		groups:       append(append([]string{}, h.groups...), name),
	}
	return next
}

func (h *prettyHandler) writeAttr(b *strings.Builder, attr slog.Attr) {
	if attr.Equal(slog.Attr{}) {
		return
	}
	key := attr.Key
	if len(h.groups) > 0 {
		key = strings.Join(h.groups, ".") + "." + key
	}
	value := attr.Value
	if key == "headers" {
		if headers, ok := attr.Value.Any().(http.Header); ok {
			h.writeHeaderMap(b, key, headers)
			return
		}
		if headers, ok := attr.Value.Any().(map[string][]string); ok {
			h.writeHeaderMap(b, key, http.Header(headers))
			return
		}
	}
	if key == "body" {
		if raw, ok := attr.Value.Any().(string); ok {
			h.writeBody(b, key, raw)
			return
		}
	}
	if value.Kind() == slog.KindGroup {
		group := value.Group()
		groupHandler := &prettyHandler{
			w:      h.w,
			level:  h.level,
			attrs:  h.attrs,
			groups: append(append([]string{}, h.groups...), key),
		}
		for _, child := range group {
			groupHandler.writeAttr(b, child)
		}
		return
	}
	b.WriteString("  ")
	b.WriteString(key)
	b.WriteString(": ")
	b.WriteString(value.String())
	b.WriteString("\n")
}

func (h *prettyHandler) writeHeaderMap(b *strings.Builder, key string, headers http.Header) {
	b.WriteString("  ")
	b.WriteString(key)
	b.WriteString(":\n")
	keys := make([]string, 0, len(headers))
	for name := range headers {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		values := headers[name]
		b.WriteString("    ")
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(strings.Join(values, ", "))
		b.WriteString("\n")
	}
}

func (h *prettyHandler) writeBody(b *strings.Builder, key string, body string) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return
	}
	b.WriteString("  ")
	b.WriteString(key)
	b.WriteString(":\n")
	if pretty := prettyJSON(body); pretty != "" {
		for _, line := range strings.Split(pretty, "\n") {
			b.WriteString("    ")
			b.WriteString(line)
			b.WriteString("\n")
		}
		return
	}
	for _, line := range strings.Split(body, "\n") {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteString("\n")
	}
}

func prettyJSON(raw string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(raw), "", "  "); err != nil {
		return ""
	}
	return buf.String()
}

const (
	colorReset = "\x1b[0m"
	colorDebug = "\x1b[36m"
	colorInfo  = "\x1b[32m"
	colorWarn  = "\x1b[33m"
	colorError = "\x1b[31m"
)

func colorizeLevel(level slog.Level, enabled bool) string {
	label := level.String()
	if !enabled {
		return label
	}
	switch {
	case level <= slog.LevelDebug:
		return colorDebug + label + colorReset
	case level < slog.LevelWarn:
		return colorInfo + label + colorReset
	case level < slog.LevelError:
		return colorWarn + label + colorReset
	default:
		return colorError + label + colorReset
	}
}

func isTerminalWriter(w io.Writer) bool {
	if file, ok := w.(*os.File); ok {
		return term.IsTerminal(int(file.Fd()))
	}
	return false
}
