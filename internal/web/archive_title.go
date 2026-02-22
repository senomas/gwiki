package web

import (
	"regexp"
	"strings"
	"time"

	"gwiki/internal/storage/fs"
)

var archivedDailyJournalPathRE = regexp.MustCompile(`^(?:archive/)?(\d{4}-\d{2})/(\d{2})\.md$`)
var archivedSplitJournalPathRE = regexp.MustCompile(`^(?:archive/)?(\d{4}-\d{2})/(\d{2})-(\d{2})-(\d{2})(?:-\d+)?\.md$`)

func archivedJournalPathCandidates(notePath string) []string {
	clean := strings.TrimPrefix(strings.TrimSpace(notePath), "/")
	if clean == "" {
		return nil
	}
	candidates := []string{clean}
	if _, relPath, err := fs.SplitOwnerNotePath(clean); err == nil && relPath != "" && relPath != clean {
		candidates = append(candidates, relPath)
	}
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "/")
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func archivedJournalTitleFromPath(notePath string) (string, bool) {
	for _, candidate := range archivedJournalPathCandidates(notePath) {
		if matches := archivedSplitJournalPathRE.FindStringSubmatch(candidate); len(matches) == 5 {
			dateTimePart := matches[1] + "/" + matches[2] + "-" + matches[3] + "-" + matches[4]
			parsed, err := time.ParseInLocation("2006-01/02-15-04", dateTimePart, time.Local)
			if err == nil {
				return parsed.Format("2 Jan 2006 15:04"), true
			}
		}
		if matches := archivedDailyJournalPathRE.FindStringSubmatch(candidate); len(matches) == 3 {
			datePart := matches[1] + "/" + matches[2]
			parsed, err := time.ParseInLocation("2006-01/02", datePart, time.Local)
			if err == nil {
				return parsed.Format("2 Jan 2006"), true
			}
		}
	}
	return "", false
}

func archivedDisplayTitleForNotePath(notePath string, title string) string {
	if inferred, ok := archivedJournalTitleFromPath(notePath); ok {
		return inferred
	}
	return displayTitleForNotePath(notePath, title)
}
