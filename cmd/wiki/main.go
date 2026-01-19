package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/index"
	"gwiki/internal/web"
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

	if err := os.MkdirAll(cfg.DataPath, 0o755); err != nil {
		slog.Error("create .wiki dir", "err", err)
		os.Exit(1)
	}
	notesDir := filepath.Join(cfg.RepoPath, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		slog.Error("create notes dir", "err", err)
		os.Exit(1)
	}

	idx, err := index.Open(filepath.Join(cfg.DataPath, "index.sqlite"))
	if err != nil {
		slog.Error("open index", "err", err)
		os.Exit(1)
	}
	defer idx.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := idx.Init(ctx, cfg.RepoPath); err != nil {
		slog.Error("init index", "err", err)
		os.Exit(1)
	}

	srv, err := web.NewServer(cfg, idx)
	if err != nil {
		slog.Error("auth init", "err", err)
		os.Exit(1)
	}
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

type prettyHandler struct {
	w      io.Writer
	level  slog.Leveler
	attrs  []slog.Attr
	groups []string
}

func newPrettyHandler(w io.Writer, level slog.Leveler) slog.Handler {
	return &prettyHandler{w: w, level: level}
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
	b.WriteString(colorizeLevel(r.Level))
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
		w:      h.w,
		level:  h.level,
		attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups: append([]string{}, h.groups...),
	}
	return next
}

func (h *prettyHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := &prettyHandler{
		w:      h.w,
		level:  h.level,
		attrs:  append([]slog.Attr{}, h.attrs...),
		groups: append(append([]string{}, h.groups...), name),
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
	colorReset   = "\x1b[0m"
	colorDebug   = "\x1b[36m"
	colorInfo    = "\x1b[32m"
	colorWarn    = "\x1b[33m"
	colorError   = "\x1b[31m"
	colorDefault = "\x1b[37m"
)

func colorizeLevel(level slog.Level) string {
	label := level.String()
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
