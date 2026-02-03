package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type AccessFile map[string][]GroupMember

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
		members, err := parseMemberFile(f)
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
