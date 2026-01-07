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

func NoteFilePath(repoPath, notePath string) (string, error) {
	clean, err := NormalizeNotePath(notePath)
	if err != nil {
		return "", err
	}
	root := filepath.Join(repoPath, "notes")
	full := filepath.Join(root, filepath.FromSlash(clean))
	rel, err := filepath.Rel(root, full)
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
