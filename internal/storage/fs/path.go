package fs

import (
	"errors"
	"path"
	"path/filepath"
	"strings"
)

var ErrUnsafePath = errors.New("unsafe path")

func NormalizeNotePath(p string) (string, error) {
	if strings.ContainsRune(p, 0) {
		return "", ErrUnsafePath
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "/") {
		return "", ErrUnsafePath
	}
	clean := path.Clean(p)
	if clean == "." || strings.HasPrefix(clean, "..") {
		return "", ErrUnsafePath
	}
	return clean, nil
}

func SplitOwnerNotePath(p string) (string, string, error) {
	clean, err := NormalizeNotePath(p)
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(clean, "/", 2)
	if len(parts) < 2 {
		return "", "", ErrUnsafePath
	}
	owner := strings.TrimSpace(parts[0])
	notePath := strings.TrimSpace(parts[1])
	if owner == "" || notePath == "" {
		return "", "", ErrUnsafePath
	}
	return owner, notePath, nil
}

func NoteFilePath(repoPath, notePath string) (string, error) {
	owner, rel, err := SplitOwnerNotePath(notePath)
	if err != nil {
		return "", err
	}
	root := filepath.Join(repoPath, owner, "notes")
	full := filepath.Join(root, filepath.FromSlash(rel))
	rel, err = filepath.Rel(root, full)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", ErrUnsafePath
	}
	return full, nil
}

func EnsureMDExt(p string) string {
	if strings.HasSuffix(strings.ToLower(p), ".md") {
		return p
	}
	return p + ".md"
}
