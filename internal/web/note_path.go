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

func notePathForRoute(notePath, currentUser string) string {
	notePath = strings.TrimPrefix(strings.TrimSpace(notePath), "/")
	owner, rel, err := fs.SplitOwnerNotePath(notePath)
	if err != nil {
		return notePath
	}
	currentUser = strings.TrimSpace(currentUser)
	if currentUser != "" && strings.EqualFold(owner, currentUser) {
		return rel
	}
	return "@" + owner + "/" + rel
}

func noteHref(notePath string, currentUser ...string) string {
	user := ""
	if len(currentUser) > 0 {
		user = currentUser[0]
	}
	return "/notes/" + notePathForRoute(notePath, user)
}

func noteHrefWithSuffix(notePath string, suffix string, currentUser ...string) string {
	base := noteHref(notePath, currentUser...)
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

func parseNoteRefForUser(noteRef, currentUser string) (string, bool) {
	noteRef = strings.TrimSpace(noteRef)
	noteRef = strings.TrimPrefix(noteRef, "/")
	if noteRef == "" {
		return "", false
	}
	if parsed, ok := parseUserScopedNoteRef(noteRef); ok {
		return parsed, true
	}
	if strings.HasPrefix(noteRef, "@") {
		return "", false
	}
	if isUUIDLike(noteRef) {
		return noteRef, true
	}
	currentUser = strings.TrimSpace(currentUser)
	if currentUser == "" {
		return "", false
	}
	return currentUser + "/" + noteRef, true
}

func wikiLinkRefForTarget(sourceOwner, targetPath string) (string, string, error) {
	targetPath = strings.TrimPrefix(strings.TrimSpace(normalizeNoteRef(targetPath)), "/")
	normalized, err := fs.NormalizeNotePath(targetPath)
	if err != nil {
		return "", "", err
	}
	normalized = fs.EnsureMDExt(normalized)

	targetOwner, rel, err := fs.SplitOwnerNotePath(normalized)
	if err != nil {
		return "", "", err
	}
	sourceOwner = strings.TrimSpace(sourceOwner)
	if sourceOwner != "" && strings.EqualFold(targetOwner, sourceOwner) {
		return normalized, rel, nil
	}
	return normalized, "@"+targetOwner+"/"+rel, nil
}

func isUUIDLike(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}
