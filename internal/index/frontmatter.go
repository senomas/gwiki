package index

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

func EnsureFrontmatter(content string, now time.Time, maxUpdated int) (string, error) {
	nowStr := now.Format(time.RFC3339)
	fmLines, body, ok := splitFrontmatterLines(content)
	if !ok {
		id := uuid.NewString()
		fm := []string{
			"---",
			"id: " + id,
			"created: " + nowStr,
			"updated: " + nowStr,
			"priority: 10",
			"history:",
			"  - user: " + dummyHistoryUser,
			"    at: " + nowStr,
			"    action: create",
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
	createdMissing := createdVal == ""
	if createdVal == "" {
		createdVal = nowStr
	}
	priorityVal := valueOrEmpty(fmLines, lineIdx, "priority")
	if priorityVal == "" {
		priorityVal = "10"
	}
	if maxUpdated <= 0 {
		maxUpdated = 1
	}

	setFrontmatterLine(&fmLines, lineIdx, "id", idVal)
	setFrontmatterLine(&fmLines, lineIdx, "created", createdVal)
	setFrontmatterLine(&fmLines, lineIdx, "updated", nowStr)
	setFrontmatterLine(&fmLines, lineIdx, "priority", priorityVal)

	action := "edit"
	if createdMissing {
		action = "create"
	}
	addHistoryEntry(&fmLines, lineIdx, nowStr, action)
	trimHistoryEntries(&fmLines, lineIdx, maxUpdated)

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

const dummyHistoryUser = "dummy"

func addHistoryEntry(lines *[]string, idx map[string]int, at, action string) {
	item := []string{
		"  - user: " + dummyHistoryUser,
		"    at: " + at,
		"    action: " + action,
	}

	if pos, ok := idx["history"]; ok && pos >= 0 && pos < len(*lines) {
		insertLines(lines, idx, pos+1, item)
		return
	}
	historyPos := len(*lines)
	*lines = append(*lines, "history:")
	*lines = append(*lines, item...)
	idx["history"] = historyPos
}

func trimHistoryEntries(lines *[]string, idx map[string]int, maxEntries int) {
	if maxEntries <= 0 {
		return
	}
	pos, ok := idx["history"]
	if !ok || pos < 0 || pos >= len(*lines) {
		return
	}
	start := pos + 1
	end := start
	for end < len(*lines) && isIndentedLine((*lines)[end]) {
		end++
	}
	if end <= start {
		return
	}

	itemStarts := make([]int, 0)
	for i := start; i < end; i++ {
		trimmed := strings.TrimLeft((*lines)[i], " \t")
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "-\t") || strings.HasPrefix(trimmed, "-") {
			itemStarts = append(itemStarts, i)
		}
	}
	if len(itemStarts) <= maxEntries {
		return
	}

	for len(itemStarts) > maxEntries {
		lastStart := itemStarts[len(itemStarts)-1]
		lastEnd := end
		if len(itemStarts) > 1 {
			prevStart := itemStarts[len(itemStarts)-2]
			if prevStart < lastStart {
				lastEnd = end
			}
		}
		removeRange(lines, idx, lastStart, lastEnd)
		end = lastStart
		itemStarts = itemStarts[:len(itemStarts)-1]
	}
}

func isIndentedLine(line string) bool {
	return strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
}

func insertLines(lines *[]string, idx map[string]int, pos int, add []string) {
	if pos < 0 {
		pos = 0
	}
	if pos > len(*lines) {
		pos = len(*lines)
	}
	*lines = append(*lines, add...)
	copy((*lines)[pos+len(add):], (*lines)[pos:])
	copy((*lines)[pos:], add)
	for key, current := range idx {
		if current >= pos {
			idx[key] = current + len(add)
		}
	}
}

func removeRange(lines *[]string, idx map[string]int, start, end int) {
	if start < 0 {
		start = 0
	}
	if end > len(*lines) {
		end = len(*lines)
	}
	if start >= end {
		return
	}
	*lines = append((*lines)[:start], (*lines)[end:]...)
	shift := end - start
	for key, current := range idx {
		switch {
		case current >= end:
			idx[key] = current - shift
		case current >= start:
			delete(idx, key)
		}
	}
}
