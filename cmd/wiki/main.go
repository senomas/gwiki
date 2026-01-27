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
	level := parseLogLevel(os.Getenv("WIKI_LOG_LEVEL"))
	logWriter, logCloser := selectLogWriter()
	if logCloser != nil {
		defer logCloser.Close()
	}
	pretty := strings.EqualFold(os.Getenv("WIKI_LOG_PRETTY"), "1") || strings.EqualFold(os.Getenv("WIKI_LOG_PRETTY"), "true")
	if pretty {
		slog.SetDefault(slog.New(newPrettyHandler(logWriter, level)))
	} else {
		slog.SetDefault(slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{Level: level})))
	}

	cfg := config.Load()
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

	idx, err := index.Open(filepath.Join(cfg.DataPath, "index.sqlite"))
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
	groupFile, err := auth.LoadGroupsFromRepo(cfg.RepoPath)
	if err != nil {
		slog.Error("load group file", "err", err)
		os.Exit(1)
	}
	groupMembers := make(map[string][]index.GroupMember, len(groupFile))
	groupNames := make([]string, 0, len(groupFile))
	for group, members := range groupFile {
		groupNames = append(groupNames, group)
		list := make([]index.GroupMember, 0, len(members))
		for _, member := range members {
			list = append(list, index.GroupMember{User: member.User, Access: member.Access})
		}
		groupMembers[group] = list
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := idx.InitWithOwners(ctx, cfg.RepoPath, users, groupMembers); err != nil {
		slog.Error("init index", "err", err)
		os.Exit(1)
	}
	syncGitHistoryOnStartup(ctx, cfg, idx, users, groupNames)

	srv, err := web.NewServer(cfg, idx)
	if err != nil {
		slog.Error("auth init", "err", err)
		os.Exit(1)
	}
	startGitScheduler(cfg, idx, users, groupNames)
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

func selectLogWriter() (io.Writer, io.Closer) {
	path := strings.TrimSpace(os.Getenv("LOG_FILE"))
	if path == "" {
		return os.Stdout, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		slog.Error("open log file", "path", path, "err", err)
		return os.Stdout, nil
	}
	return file, file
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

func startGitScheduler(cfg config.Config, idx *index.Index, users []string, groups []string) {
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
				runScheduledSync(ctx, cfg, idx, users, groups)
			}
		}
	}()
}

func runScheduledSync(ctx context.Context, cfg config.Config, idx *index.Index, users []string, groups []string) {
	targets, err := discoverSyncTargets(cfg.RepoPath, users, groups)
	if err != nil {
		slog.Warn("sync schedule: list targets failed", "err", err)
		return
	}
	if len(targets) == 0 {
		return
	}
	anySuccess := false
	for _, target := range targets {
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
		output, runErr := syncer.RunWithOptions(ctx, target.Path, opts)
		unlock()
		if runErr != nil {
			slog.Warn("sync schedule failed", "owner", target.Owner, "err", runErr)
			continue
		}
		logSyncOutput(target.Owner, output)
		if inserted, histErr := idx.SyncGitHistory(ctx, target.Owner, target.Path); histErr != nil {
			slog.Warn("sync schedule history failed", "owner", target.Owner, "err", histErr)
		} else if inserted > 0 {
			slog.Info("sync schedule history updated", "owner", target.Owner, "inserted", inserted)
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
	}
}

func syncGitHistoryOnStartup(ctx context.Context, cfg config.Config, idx *index.Index, users []string, groups []string) {
	targets, err := discoverSyncTargets(cfg.RepoPath, users, groups)
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

func discoverSyncTargets(repoPath string, users []string, groups []string) ([]syncTarget, error) {
	owners := make(map[string]struct{})
	for _, user := range users {
		user = strings.TrimSpace(user)
		if user == "" {
			continue
		}
		owners[user] = struct{}{}
	}
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		owners[group] = struct{}{}
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
