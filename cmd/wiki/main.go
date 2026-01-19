package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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
	handler := slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))

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
