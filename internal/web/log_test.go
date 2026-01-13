package web

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	setupTestLogger()
	os.Exit(m.Run())
}

func setupTestLogger() {
	level := new(slog.LevelVar)
	level.Set(slog.LevelDebug)
	switch strings.ToLower(strings.TrimSpace(os.Getenv("WIKI_LOG_LEVEL"))) {
	case "info":
		level.Set(slog.LevelInfo)
	case "warn", "warning":
		level.Set(slog.LevelWarn)
	case "error":
		level.Set(slog.LevelError)
	}
	writer := selectTestLogWriter()
	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
	slog.Debug("test logger active", "log_file", os.Getenv("LOG_FILE"))
}

func selectTestLogWriter() io.Writer {
	path := strings.TrimSpace(os.Getenv("LOG_FILE"))
	if path == "" {
		return os.Stdout
	}
	if dir := filepath.Dir(path); dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return os.Stdout
	}
	return file
}
