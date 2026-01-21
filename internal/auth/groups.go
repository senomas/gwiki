package auth

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type GroupMember struct {
	User   string
	Access string
}

type GroupFile map[string][]GroupMember

func LoadGroupsFromRepo(repoPath string) (GroupFile, error) {
	if strings.TrimSpace(repoPath) == "" {
		return GroupFile{}, nil
	}
	entries, err := os.ReadDir(repoPath)
	if err != nil {
		return nil, fmt.Errorf("read repo dir: %w", err)
	}
	groups := make(GroupFile)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		groupName := entry.Name()
		memberPath := filepath.Join(repoPath, groupName, ".member.txt")
		f, err := os.Open(memberPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("open member file %s: %w", memberPath, err)
		}
		members, err := parseMemberFile(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse member file %s: %w", memberPath, err)
		}
		if len(members) == 0 {
			continue
		}
		groups[groupName] = members
	}
	return groups, nil
}

func parseMemberFile(r *os.File) ([]GroupMember, error) {
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
			return nil, fmt.Errorf("invalid member line %d: expected user:access", lineNum)
		}
		user := strings.TrimSpace(parts[0])
		access := strings.ToLower(strings.TrimSpace(parts[1]))
		if user == "" || access == "" {
			return nil, fmt.Errorf("invalid member line %d: empty user or access", lineNum)
		}
		if access != "ro" && access != "rw" {
			return nil, fmt.Errorf("invalid member line %d: access must be ro or rw", lineNum)
		}
		prev, ok := members[user]
		if ok && prev == "rw" {
			continue
		}
		members[user] = access
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read member file: %w", err)
	}
	merged := make([]GroupMember, 0, len(members))
	for user, level := range members {
		merged = append(merged, GroupMember{User: user, Access: level})
	}
	return merged, nil
}
