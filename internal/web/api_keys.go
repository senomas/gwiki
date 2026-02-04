package web

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type apiKeyEntry struct {
	Alias  string
	Expiry time.Time
}

func loadAPIKeys(dataPath string) (map[string]apiKeyEntry, error) {
	if strings.TrimSpace(dataPath) == "" {
		return map[string]apiKeyEntry{}, nil
	}
	path := filepath.Join(dataPath, "api-keys.txt")
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]apiKeyEntry{}, nil
		}
		return nil, err
	}
	defer file.Close()

	keys := map[string]apiKeyEntry{}
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.Split(raw, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("api keys: invalid format at line %d", lineNo)
		}
		alias := strings.TrimSpace(parts[0])
		key := strings.TrimSpace(parts[1])
		expiryRaw := strings.TrimSpace(parts[2])
		if alias == "" || key == "" || expiryRaw == "" {
			return nil, fmt.Errorf("api keys: invalid format at line %d", lineNo)
		}
		expiry, err := time.Parse("2006-01-02", expiryRaw)
		if err != nil {
			return nil, fmt.Errorf("api keys: invalid expiry at line %d", lineNo)
		}
		if _, exists := keys[key]; exists {
			return nil, fmt.Errorf("api keys: duplicate key at line %d", lineNo)
		}
		keys[key] = apiKeyEntry{
			Alias:  alias,
			Expiry: expiry,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func apiKeyExpired(entry apiKeyEntry, now time.Time) bool {
	if entry.Expiry.IsZero() {
		return false
	}
	loc := time.Local
	if !now.IsZero() {
		loc = now.Location()
	}
	today := time.Date(now.In(loc).Year(), now.In(loc).Month(), now.In(loc).Day(), 0, 0, 0, 0, loc)
	expiry := time.Date(entry.Expiry.In(loc).Year(), entry.Expiry.In(loc).Month(), entry.Expiry.In(loc).Day(), 0, 0, 0, 0, loc)
	return expiry.Before(today)
}
