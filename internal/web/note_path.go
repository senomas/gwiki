package web

import (
	"strings"

	"gwiki/internal/storage/fs"
)

// normalizeNoteRef accepts both owner-prefixed refs ("owner/path.md")
// and user-scoped refs ("@owner/path.md"), returning the canonical owner/path form.
func normalizeNoteRef(noteRef string) string {
	noteRef = strings.TrimSpace(noteRef)
	noteRef = strings.TrimPrefix(noteRef, "/")
	noteRef = strings.TrimPrefix(noteRef, "notes/")
	if strings.HasPrefix(noteRef, "@") {
		trimmed := strings.TrimPrefix(noteRef, "@")
		parts := strings.SplitN(trimmed, "/", 2)
		if len(parts) == 2 {
			owner := strings.TrimSpace(parts[0])
			rel := strings.TrimSpace(parts[1])
			if owner != "" && rel != "" {
				return owner + "/" + rel
			}
		}
	}
	return noteRef
}

func notePathWithUserPrefix(notePath string) string {
	notePath = strings.TrimPrefix(strings.TrimSpace(notePath), "/")
	owner, rel, err := fs.SplitOwnerNotePath(notePath)
	if err != nil {
		return notePath
	}
	return "@" + owner + "/" + rel
}

func noteHref(notePath string) string {
	return "/notes/" + notePathWithUserPrefix(notePath)
}

func noteHrefWithSuffix(notePath string, suffix string) string {
	base := noteHref(notePath)
	if suffix == "" {
		return base
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return base + suffix
}

// parseUserScopedNoteRef accepts only refs in the @owner/path form
// (optionally prefixed with "/" or "notes/"), returning canonical owner/path.
func parseUserScopedNoteRef(noteRef string) (string, bool) {
	noteRef = strings.TrimSpace(noteRef)
	noteRef = strings.TrimPrefix(noteRef, "/")
	noteRef = strings.TrimPrefix(noteRef, "notes/")
	if !strings.HasPrefix(noteRef, "@") {
		return "", false
	}
	trimmed := strings.TrimPrefix(noteRef, "@")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 {
		return "", false
	}
	owner := strings.TrimSpace(parts[0])
	rel := strings.TrimSpace(parts[1])
	if owner == "" || rel == "" {
		return "", false
	}
	return owner + "/" + rel, true
}
