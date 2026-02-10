package index

import "strings"

const (
	VisibilityInherited = "inherited"
	VisibilityPublic    = "public"
	VisibilityProtected = "protected"
	VisibilityPrivate   = "private"
)

func normalizeDeclaredVisibility(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case VisibilityPublic, VisibilityProtected, VisibilityPrivate, VisibilityInherited:
		return value
	default:
		return VisibilityInherited
	}
}

func normalizeEffectiveVisibility(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case VisibilityPublic, VisibilityProtected, VisibilityPrivate:
		return value
	default:
		return VisibilityPrivate
	}
}

func isDeclaredVisibility(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case VisibilityInherited, VisibilityPublic, VisibilityProtected, VisibilityPrivate:
		return true
	default:
		return false
	}
}
