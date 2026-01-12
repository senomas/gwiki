package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const envFileName = ".env"

func initEnvFile() {
	if err := ensureEnvFile(); err != nil {
		return
	}
	_ = loadEnvFile()
}

func ensureEnvFile() error {
	if _, err := os.Stat(envFileName); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	secret, err := randomSecret()
	if err != nil {
		return err
	}
	content := []string{
		"WIKI_REPO_PATH=.",
		"WIKI_AUTH_SECRET=" + secret,
		"",
	}
	return os.WriteFile(envFileName, []byte(strings.Join(content, "\n")), 0o600)
}

func randomSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawStdEncoding.EncodeToString(buf), nil
}

func loadEnvFile() error {
	data, err := os.ReadFile(envFileName)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" {
			continue
		}
		val = strings.Trim(val, "\"")
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
	return nil
}
