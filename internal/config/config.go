package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	RepoPath             string
	DataPath             string
	ListenAddr           string
	AuthUser             string
	AuthPass             string
	AuthFile             string
	SignalURL            string
	SignalNumber         string
	SignalOwner          string
	SignalGroup          string
	SignalPoll           time.Duration
	GitDebounce          time.Duration
	GitPushDebounce      time.Duration
	GitSchedule          time.Duration
	NoteLockTimeout      time.Duration
	UpdatedHistoryMax    int
	DBLockTimeout        time.Duration
	DBBusyTimeout        time.Duration
	PasswordExpiryMonths int
}

func Load() Config {
	initEnvFile()
	cfg := Config{
		RepoPath:     os.Getenv("WIKI_REPO_PATH"),
		DataPath:     os.Getenv("WIKI_DATA_PATH"),
		ListenAddr:   envOr("WIKI_LISTEN_ADDR", "127.0.0.1:8080"),
		AuthUser:     os.Getenv("WIKI_AUTH_USER"),
		AuthPass:     os.Getenv("WIKI_AUTH_PASS"),
		AuthFile:     os.Getenv("WIKI_AUTH_FILE"),
		SignalURL:    strings.TrimSpace(os.Getenv("WIKI_SIGNAL_URL")),
		SignalNumber: strings.TrimSpace(os.Getenv("WIKI_SIGNAL_NUMBER")),
		SignalOwner:  strings.TrimSpace(os.Getenv("WIKI_SIGNAL_OWNER")),
		SignalGroup:  envOr("WIKI_SIGNAL_GROUP", "gwiki"),
	}
	if cfg.DataPath == "" && cfg.RepoPath != "" {
		cfg.DataPath = filepath.Join(cfg.RepoPath, ".wiki")
	}
	if cfg.AuthFile == "" && cfg.DataPath != "" {
		cfg.AuthFile = filepath.Join(cfg.DataPath, "auth.txt")
	}

	cfg.GitDebounce = parseDurationOr("WIKI_GIT_DEBOUNCE", 3*time.Minute)
	cfg.GitPushDebounce = parseDurationOr("WIKI_GIT_PUSH_DEBOUNCE", 10*time.Minute)
	cfg.GitSchedule = parseDurationOr("WIKI_GIT_SCHEDULE", 10*time.Minute)
	cfg.SignalPoll = parseDurationOr("WIKI_SIGNAL_POLL", 30*time.Second)
	cfg.NoteLockTimeout = parseDurationOr("WIKI_NOTE_LOCK_TIMEOUT", 5*time.Second)
	cfg.UpdatedHistoryMax = parseIntOr("WIKI_UPDATED_HISTORY_MAX", 100)
	cfg.DBLockTimeout = time.Duration(parseIntOr("WIKI_DB_LOCK_TIMEOUT_MS", 5000)) * time.Millisecond
	cfg.DBBusyTimeout = time.Duration(parseIntOr("WIKI_DB_BUSY_TIMEOUT_MS", 10000)) * time.Millisecond
	cfg.PasswordExpiryMonths = parseExpiryMonthsOr("WIKI_PASSWORD_EXPIRY", 6)
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

func parseExpiryMonthsOr(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if strings.HasSuffix(strings.ToLower(raw), "mo") {
		raw = strings.TrimSpace(raw[:len(raw)-2])
	}
	if raw == "" {
		return fallback
	}
	if v, err := strconv.Atoi(raw); err == nil && v > 0 {
		return v
	}
	return fallback
}
