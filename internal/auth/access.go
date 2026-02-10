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
	Path       string
	Visibility string
	Members    []AccessMember
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
			visibility, members, err := parseAccessFile(f)
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
			rules = append(rules, AccessPathRule{
				Path:       relDir,
				Visibility: visibility,
				Members:    members,
			})
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("scan access rules for %s: %w", ownerName, walkErr)
		}
		if len(rules) == 0 {
			continue
		}
		access[ownerName] = resolveRuleVisibilities(rules)
	}
	return access, nil
}

func parseAccessFile(r io.Reader) (string, []AccessMember, error) {
	visibility := "inherited"
	members := map[string]string{}
	scanner := bufio.NewScanner(r)
	lineNum := 0
	firstDataLine := true
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if firstDataLine {
			firstDataLine = false
			if parsedVisibility, ok := parseFolderVisibilityToken(line); ok {
				visibility = parsedVisibility
				continue
			}
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return "", nil, fmt.Errorf("invalid access line %d: expected user:access", lineNum)
		}
		user := strings.TrimSpace(parts[0])
		access := strings.ToLower(strings.TrimSpace(parts[1]))
		if user == "" || access == "" {
			return "", nil, fmt.Errorf("invalid access line %d: empty user or access", lineNum)
		}
		if access != "ro" && access != "rw" {
			return "", nil, fmt.Errorf("invalid access line %d: access must be ro or rw", lineNum)
		}
		prev, ok := members[user]
		if ok && prev == "rw" {
			continue
		}
		members[user] = access
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("read access file: %w", err)
	}
	merged := make([]AccessMember, 0, len(members))
	for user, level := range members {
		merged = append(merged, AccessMember{User: user, Access: level})
	}
	return visibility, merged, nil
}

func parseFolderVisibilityToken(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "public", "protected", "private", "inherited":
		return value, true
	default:
		return "", false
	}
}

func resolveRuleVisibilities(rules []AccessPathRule) []AccessPathRule {
	if len(rules) == 0 {
		return rules
	}
	declaredByPath := make(map[string]string, len(rules))
	for _, rule := range rules {
		pathName := normalizeAccessPath(rule.Path)
		declared, ok := parseFolderVisibilityToken(rule.Visibility)
		if !ok {
			declared = "inherited"
		}
		declaredByPath[pathName] = declared
	}

	memo := map[string]string{}
	stack := map[string]bool{}
	var resolve func(pathName string) string
	resolve = func(pathName string) string {
		pathName = normalizeAccessPath(pathName)
		if resolved, ok := memo[pathName]; ok {
			return resolved
		}
		if stack[pathName] {
			return "private"
		}
		stack[pathName] = true
		declared, ok := declaredByPath[pathName]
		if !ok || declared == "inherited" {
			if pathName == "" {
				memo[pathName] = "private"
			} else {
				memo[pathName] = resolve(parentAccessPath(pathName))
			}
		} else {
			memo[pathName] = declared
		}
		stack[pathName] = false
		return memo[pathName]
	}

	resolved := make([]AccessPathRule, 0, len(rules))
	for _, rule := range rules {
		pathName := normalizeAccessPath(rule.Path)
		rule.Path = pathName
		rule.Visibility = resolve(pathName)
		resolved = append(resolved, rule)
	}
	return resolved
}

func normalizeAccessPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "\\", "/")
	value = strings.Trim(value, "/")
	value = path.Clean(value)
	if value == "." {
		return ""
	}
	return value
}

func parentAccessPath(value string) string {
	value = normalizeAccessPath(value)
	if value == "" {
		return ""
	}
	parent := path.Dir(value)
	if parent == "." {
		return ""
	}
	return normalizeAccessPath(parent)
}
