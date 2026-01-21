package config

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	RepoPath          string
	DataPath          string
	ListenAddr        string
	AuthUser          string
	AuthPass          string
	AuthFile          string
	GitDebounce       time.Duration
	GitPushDebounce   time.Duration
	NoteLockTimeout   time.Duration
	UpdatedHistoryMax int
	DBLockTimeout     time.Duration
}

func Load() Config {
	initEnvFile()
	cfg := Config{
		RepoPath:   os.Getenv("WIKI_REPO_PATH"),
		DataPath:   os.Getenv("WIKI_DATA_PATH"),
		ListenAddr: envOr("WIKI_LISTEN_ADDR", "127.0.0.1:8080"),
		AuthUser:   os.Getenv("WIKI_AUTH_USER"),
		AuthPass:   os.Getenv("WIKI_AUTH_PASS"),
		AuthFile:   os.Getenv("WIKI_AUTH_FILE"),
	}
	if cfg.DataPath == "" && cfg.RepoPath != "" {
		cfg.DataPath = filepath.Join(cfg.RepoPath, ".wiki")
	}
	if cfg.AuthFile == "" && cfg.DataPath != "" {
		cfg.AuthFile = filepath.Join(cfg.DataPath, "auth.txt")
	}

	cfg.GitDebounce = parseDurationOr("WIKI_GIT_DEBOUNCE", 3*time.Minute)
	cfg.GitPushDebounce = parseDurationOr("WIKI_GIT_PUSH_DEBOUNCE", 10*time.Minute)
	cfg.NoteLockTimeout = parseDurationOr("WIKI_NOTE_LOCK_TIMEOUT", 5*time.Second)
	cfg.UpdatedHistoryMax = parseIntOr("WIKI_UPDATED_HISTORY_MAX", 100)
	cfg.DBLockTimeout = time.Duration(parseIntOr("WIKI_DB_LOCK_TIMEOUT_MS", 5000)) * time.Millisecond
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDurationOr(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func parseIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil && i > 0 {
			return i
		}
	}
	return fallback
}
