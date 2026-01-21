package index

import (
	"database/sql"
	"fmt"
	"path"
	"strings"
)

func splitOwnerPath(notePath string) (string, string, error) {
	notePath = strings.TrimSpace(notePath)
	if notePath == "" {
		return "", "", fmt.Errorf("empty note path")
	}
	if strings.Contains(notePath, `\`) {
		return "", "", fmt.Errorf("invalid note path")
	}
	clean := path.Clean(notePath)
	if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || strings.Contains(clean, "/../") {
		return "", "", fmt.Errorf("invalid note path")
	}
	parts := strings.SplitN(clean, "/", 2)
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid note path")
	}
	owner := strings.TrimSpace(parts[0])
	rel := strings.TrimSpace(parts[1])
	if owner == "" || rel == "" {
		return "", "", fmt.Errorf("invalid note path")
	}
	return owner, rel, nil
}

func joinOwnerPath(owner, rel string) string {
	owner = strings.TrimSpace(owner)
	rel = strings.TrimLeft(strings.TrimSpace(rel), "/")
	if owner == "" {
		return rel
	}
	if rel == "" {
		return owner
	}
	return owner + "/" + rel
}

func ownerWhereClause(userID int, groupID sql.NullInt64, table string) (string, []any) {
	if table == "" {
		table = "files"
	}
	if groupID.Valid {
		return table + ".group_id = ?", []any{groupID.Int64}
	}
	return table + ".group_id IS NULL AND " + table + ".user_id = ?", []any{userID}
}
