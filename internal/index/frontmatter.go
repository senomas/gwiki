package index

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

func EnsureFrontmatter(content string, now time.Time, maxUpdated int) (string, error) {
	nowStr := now.UTC().Format(time.RFC3339)
	fmLines, body, ok := splitFrontmatterLines(content)
	if !ok {
		id := uuid.NewString()
		fm := []string{
			"---",
			"id: " + id,
			"created: " + nowStr,
			"updated: " + nowStr,
			"---",
		}
		if body == "" {
			return strings.Join(fm, "\n") + "\n", nil
		}
		return strings.Join(fm, "\n") + "\n\n" + body, nil
	}

	lineIdx := map[string]int{}
	for i, line := range fmLines {
		key, _ := parseFrontmatterLine(line)
		if key == "" {
			continue
		}
		key = strings.ToLower(key)
		if _, exists := lineIdx[key]; !exists {
			lineIdx[key] = i
		}
	}

	idVal := valueOrEmpty(fmLines, lineIdx, "id")
	if idVal == "" {
		idVal = uuid.NewString()
	}
	createdVal := valueOrEmpty(fmLines, lineIdx, "created")
	if createdVal == "" {
		createdVal = nowStr
	}
	updatedVal := valueOrEmpty(fmLines, lineIdx, "updated")
	updatedList := updatedHistory(updatedVal)
	updatedList = prependUnique(nowStr, updatedList)
	if maxUpdated <= 0 {
		maxUpdated = 1
	}
	if len(updatedList) > maxUpdated {
		updatedList = updatedList[:maxUpdated]
	}

	setFrontmatterLine(&fmLines, lineIdx, "id", idVal)
	setFrontmatterLine(&fmLines, lineIdx, "created", createdVal)
	setFrontmatterLine(&fmLines, lineIdx, "updated", strings.Join(updatedList, ", "))

	fmBlock := "---\n" + strings.Join(fmLines, "\n") + "\n---"
	if body == "" {
		return fmBlock + "\n", nil
	}
	return fmBlock + "\n" + body, nil
}

func splitFrontmatterLines(input string) ([]string, string, bool) {
	lines := strings.Split(input, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return nil, input, false
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return nil, input, false
	}
	return lines[1:end], strings.Join(lines[end+1:], "\n"), true
}

func parseFrontmatterLine(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func valueOrEmpty(lines []string, idx map[string]int, key string) string {
	pos, ok := idx[key]
	if !ok || pos < 0 || pos >= len(lines) {
		return ""
	}
	_, val := parseFrontmatterLine(lines[pos])
	val = strings.TrimSpace(strings.Trim(val, "\""))
	return val
}

func setFrontmatterLine(lines *[]string, idx map[string]int, key, val string) {
	line := key + ": " + val
	if pos, ok := idx[key]; ok && pos >= 0 && pos < len(*lines) {
		(*lines)[pos] = line
		return
	}
	*lines = append(*lines, line)
	idx[key] = len(*lines) - 1
}

func updatedHistory(raw string) []string {
	raw = strings.TrimSpace(strings.Trim(raw, "\""))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func prependUnique(value string, list []string) []string {
	seen := map[string]struct{}{value: {}}
	out := []string{value}
	for _, item := range list {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
