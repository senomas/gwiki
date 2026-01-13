package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"gwiki/internal/auth"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/user-add <username>")
		os.Exit(2)
	}
	user := strings.TrimSpace(os.Args[1])
	if user == "" {
		fmt.Fprintln(os.Stderr, "username must not be empty")
		os.Exit(2)
	}
	if strings.Contains(user, ":") {
		fmt.Fprintln(os.Stderr, "username must not contain ':'")
		os.Exit(2)
	}

	authPath, err := authFilePath()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	exists, err := userExists(authPath, user)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if exists {
		ok, err := promptYesNo(fmt.Sprintf("User %q exists. Update password? [y/N]: ", user))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "no changes made")
			return
		}
	}

	password, err := promptPassword("Password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	confirm, err := promptPassword("Confirm: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if password != confirm {
		fmt.Fprintln(os.Stderr, "passwords do not match")
		os.Exit(1)
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := upsertAuthFile(authPath, user, hash); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "updated %s\n", authPath)
}

func authFilePath() (string, error) {
	if v := os.Getenv("WIKI_AUTH_FILE"); v != "" {
		return v, nil
	}
	repo := os.Getenv("WIKI_REPO_PATH")
	data := os.Getenv("WIKI_DATA_PATH")
	if repo == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("get working directory: %w", err)
		}
		repo = cwd
	}
	if data == "" {
		data = filepath.Join(repo, ".wiki")
	}
	return filepath.Join(data, "auth.txt"), nil
}

func promptPassword(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("stdin is not a terminal")
	}
	fmt.Fprint(os.Stderr, prompt)
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimSpace(string(pass)), nil
}

func promptYesNo(prompt string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errors.New("stdin is not a terminal")
	}
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read response: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes", nil
}

func userExists(path, user string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat auth file: %w", err)
	}
	users, err := auth.LoadFile(path)
	if err != nil {
		return false, err
	}
	_, ok := users[user]
	return ok, nil
}

func upsertAuthFile(path, user, hash string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create auth dir: %w", err)
	}

	var lines []string
	updated := false

	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("open auth file: %w", err)
		}
	} else {
		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			raw := scanner.Text()
			trim := strings.TrimSpace(raw)
			if trim == "" || strings.HasPrefix(trim, "#") {
				lines = append(lines, raw)
				continue
			}
			parts := strings.SplitN(trim, ":", 2)
			if len(parts) != 2 {
				f.Close()
				return fmt.Errorf("invalid auth line %d: expected user:hash", lineNum)
			}
			if parts[0] == user {
				lines = append(lines, fmt.Sprintf("%s:%s", user, hash))
				updated = true
			} else {
				lines = append(lines, raw)
			}
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return fmt.Errorf("read auth file: %w", err)
		}
		f.Close()
	}

	if !updated {
		lines = append(lines, fmt.Sprintf("%s:%s", user, hash))
	}
	content := strings.Join(lines, "\n") + "\n"

	tmp, err := os.CreateTemp(dir, ".auth.tmp.*")
	if err != nil {
		return fmt.Errorf("create temp auth file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod auth file: %w", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("write auth file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close auth file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("replace auth file: %w", err)
	}
	return nil
}
