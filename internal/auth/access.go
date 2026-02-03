package auth

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type AccessMember struct {
	User   string
	Access string
}

type AccessPathRule struct {
	Path    string
	Members []AccessMember
}

type AccessFile map[string][]AccessPathRule

func LoadAccessFromRepo(repoPath string) (AccessFile, error) {
	if strings.TrimSpace(repoPath) == "" {
		return AccessFile{}, nil
	}
	entries, err := os.ReadDir(repoPath)
	if err != nil {
		return nil, fmt.Errorf("read repo dir: %w", err)
	}
	access := make(AccessFile)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ownerName := entry.Name()
		notesPath := filepath.Join(repoPath, ownerName, "notes")
		if _, err := os.Stat(notesPath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("stat notes dir %s: %w", notesPath, err)
		}
		rules := []AccessPathRule{}
		walkErr := filepath.WalkDir(notesPath, func(entryPath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() != ".access.txt" {
				return nil
			}
			f, err := os.Open(entryPath)
			if err != nil {
				return fmt.Errorf("open access file %s: %w", entryPath, err)
			}
			members, err := parseAccessFile(f)
			f.Close()
			if err != nil {
				return fmt.Errorf("parse access file %s: %w", entryPath, err)
			}
			relDir, err := filepath.Rel(notesPath, filepath.Dir(entryPath))
			if err != nil {
				return fmt.Errorf("resolve access path %s: %w", entryPath, err)
			}
			relDir = filepath.ToSlash(relDir)
			if relDir == "." {
				relDir = ""
			}
			relDir = strings.Trim(relDir, "/")
			relDir = path.Clean(relDir)
			if relDir == "." {
				relDir = ""
			}
			rules = append(rules, AccessPathRule{Path: relDir, Members: members})
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("scan access rules for %s: %w", ownerName, walkErr)
		}
		if len(rules) == 0 {
			continue
		}
		access[ownerName] = rules
	}
	return access, nil
}

func parseAccessFile(r io.Reader) ([]AccessMember, error) {
	members := map[string]string{}
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid access line %d: expected user:access", lineNum)
		}
		user := strings.TrimSpace(parts[0])
		access := strings.ToLower(strings.TrimSpace(parts[1]))
		if user == "" || access == "" {
			return nil, fmt.Errorf("invalid access line %d: empty user or access", lineNum)
		}
		if access != "ro" && access != "rw" {
			return nil, fmt.Errorf("invalid access line %d: access must be ro or rw", lineNum)
		}
		prev, ok := members[user]
		if ok && prev == "rw" {
			continue
		}
		members[user] = access
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read access file: %w", err)
	}
	merged := make([]AccessMember, 0, len(members))
	for user, level := range members {
		merged = append(merged, AccessMember{User: user, Access: level})
	}
	return merged, nil
}
