package auth

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type AccessMember struct {
	User   string
	Access string
}

type AccessFile map[string][]AccessMember

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
		accessPath := filepath.Join(repoPath, ownerName, ".access.txt")
		f, err := os.Open(accessPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open access file %s: %w", accessPath, err)
		}
		members, err := parseAccessFile(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse access file %s: %w", accessPath, err)
		}
		if len(members) == 0 {
			continue
		}
		access[ownerName] = members
	}
	return access, nil
}

func parseAccessFile(r *os.File) ([]AccessMember, error) {
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
