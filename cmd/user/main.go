package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/term"

	"gwiki/internal/auth"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "list" {
		if err := listUsers(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	switch args[0] {
	case "add":
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := addUser(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "remove":
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := removeUser(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gwiki-user [list|add|remove] <username>")
}

func listUsers() error {
	authPath, err := authFilePath()
	if err != nil {
		return err
	}
	users, err := readAuthFile(authPath)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Fprintln(os.Stdout, "no users")
		return nil
	}
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintln(os.Stdout, name)
	}
	return nil
}

func addUser(user string) error {
	user = strings.TrimSpace(user)
	if user == "" {
		return errors.New("username must not be empty")
	}
	if strings.Contains(user, ":") {
		return errors.New("username must not contain ':'")
	}

	authPath, err := authFilePath()
	if err != nil {
		return err
	}

	exists, err := userExists(authPath, user)
	if err != nil {
		return err
	}
	if exists {
		ok, err := promptYesNo(fmt.Sprintf("User %q exists. Update password? [y/N]: ", user))
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "no changes made")
			return nil
		}
	}

	password, err := promptPassword("Password: ")
	if err != nil {
		return err
	}
	confirm, err := promptPassword("Confirm: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return errors.New("passwords do not match")
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := upsertAuthFile(authPath, user, hash); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "updated %s\n", authPath)
	return nil
}

func removeUser(user string) error {
	user = strings.TrimSpace(user)
	if user == "" {
		return errors.New("username must not be empty")
	}
	if strings.Contains(user, ":") {
		return errors.New("username must not contain ':'")
	}

	authPath, err := authFilePath()
	if err != nil {
		return err
	}
	users, err := readAuthFile(authPath)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Fprintln(os.Stderr, "no users")
		return nil
	}
	if _, ok := users[user]; !ok {
		fmt.Fprintf(os.Stderr, "user %q not found\n", user)
		return nil
	}
	ok, err := promptYesNo(fmt.Sprintf("Remove user %q? [y/N]: ", user))
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "no changes made")
		return nil
	}
	if err := writeAuthFile(authPath, users, user); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "updated %s\n", authPath)
	return nil
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
	users, err := readAuthFile(path)
	if err != nil {
		return false, err
	}
	_, ok := users[user]
	return ok, nil
}

func readAuthFile(path string) (map[string]string, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("stat auth file: %w", err)
	}
	users, err := auth.LoadFile(path)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func writeAuthFile(path string, users map[string]string, removeUser string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create auth dir: %w", err)
	}
	names := make([]string, 0, len(users))
	for name := range users {
		if name == removeUser {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	lines := make([]string, 0, len(names))
	for _, name := range names {
		lines = append(lines, fmt.Sprintf("%s:%s", name, users[name]))
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
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
