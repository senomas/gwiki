package index

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

func EnsureFrontmatter(content string, now time.Time, maxUpdated int) (string, error) {
	return EnsureFrontmatterWithTitle(content, now, maxUpdated, "")
}

func EnsureFrontmatterWithTitle(content string, now time.Time, maxUpdated int, title string) (string, error) {
	return EnsureFrontmatterWithTitleAndUser(content, now, maxUpdated, title, dummyHistoryUser)
}

func EnsureFrontmatterWithTitleAndUser(content string, now time.Time, maxUpdated int, title, user string) (string, error) {
	return ensureFrontmatterWithTitleAndUser(content, now, maxUpdated, title, user, true)
}

func EnsureFrontmatterWithTitleAndUserNoUpdated(content string, now time.Time, maxUpdated int, title, user string) (string, error) {
	return ensureFrontmatterWithTitleAndUser(content, now, maxUpdated, title, user, false)
}

func ensureFrontmatterWithTitleAndUser(content string, now time.Time, maxUpdated int, title, user string, updateUpdated bool) (string, error) {
	if strings.TrimSpace(user) == "" {
		user = dummyHistoryUser
	}
	nowStr := now.Format(time.RFC3339)
	fmLines, body, ok := splitFrontmatterLines(content)
	if !ok {
		id := uuid.NewString()
		if title == "" {
			title = DeriveTitleFromBody(body)
		}
		updatedVal := nowStr
		if !updateUpdated {
			updatedVal = nowStr
		}
		fm := []string{
			"---",
			"id: " + id,
			"created: " + nowStr,
			"updated: " + updatedVal,
			"priority: 10",
			"visibility: private",
			"history:",
			"  - user: " + user,
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
	updatedVal := valueOrEmpty(fmLines, lineIdx, "updated")
	if updateUpdated {
		updatedVal = nowStr
	} else if updatedVal == "" {
		updatedVal = createdVal
	}
	priorityVal := valueOrEmpty(fmLines, lineIdx, "priority")
	if priorityVal == "" {
		priorityVal = "10"
	}
	visibilityVal := valueOrEmpty(fmLines, lineIdx, "visibility")
	if visibilityVal == "" {
		visibilityVal = "private"
	}
	if maxUpdated <= 0 {
		maxUpdated = 1
	}

	setFrontmatterLine(&fmLines, lineIdx, "id", idVal)
	setFrontmatterLine(&fmLines, lineIdx, "created", createdVal)
	setFrontmatterLine(&fmLines, lineIdx, "updated", updatedVal)
	setFrontmatterLine(&fmLines, lineIdx, "priority", priorityVal)
	setFrontmatterLine(&fmLines, lineIdx, "visibility", visibilityVal)
	removeFrontmatterLine(&fmLines, lineIdx, "title")

	action := "edit"
	if createdMissing {
		action = "create"
	}
	upsertHistoryEntry(&fmLines, lineIdx, now, action, user)
	trimHistoryEntries(&fmLines, lineIdx, maxUpdated)

	fmBlock := "---\n" + strings.Join(fmLines, "\n") + "\n---"
	if body == "" {
		return fmBlock + "\n", nil
	}
	return fmBlock + "\n" + body, nil
}

func SetVisibility(content string, visibility string) (string, error) {
	visibility = strings.ToLower(strings.TrimSpace(visibility))
	if visibility == "" {
		return content, nil
	}
	if visibility != "public" && visibility != "private" {
		return "", fmt.Errorf("invalid visibility")
	}
	fmLines, body, ok := splitFrontmatterLines(content)
	if !ok {
		return "", fmt.Errorf("frontmatter required")
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
	setFrontmatterLine(&fmLines, lineIdx, "visibility", visibility)
	fmBlock := "---\n" + strings.Join(fmLines, "\n") + "\n---"
	if body == "" {
		return fmBlock + "\n", nil
	}
	return fmBlock + "\n" + body, nil
}

func SetFolder(content string, folder string) (string, error) {
	folder = strings.TrimSpace(folder)
	if folder == "" {
		lines, body, ok := splitFrontmatterLines(content)
		if !ok {
			return "", fmt.Errorf("frontmatter required")
		}
		lineIdx := map[string]int{}
		for i, line := range lines {
			key, _ := parseFrontmatterLine(line)
			if key == "" {
				continue
			}
			key = strings.ToLower(key)
			if _, exists := lineIdx[key]; !exists {
				lineIdx[key] = i
			}
		}
		removeFrontmatterLine(&lines, lineIdx, "folder")
		fmBlock := "---\n" + strings.Join(lines, "\n") + "\n---"
		if body == "" {
			return fmBlock + "\n", nil
		}
		return fmBlock + "\n" + body, nil
	}
	lines, body, ok := splitFrontmatterLines(content)
	if !ok {
		return "", fmt.Errorf("frontmatter required")
	}
	lineIdx := map[string]int{}
	for i, line := range lines {
		key, _ := parseFrontmatterLine(line)
		if key == "" {
			continue
		}
		key = strings.ToLower(key)
		if _, exists := lineIdx[key]; !exists {
			lineIdx[key] = i
		}
	}
	setFrontmatterLine(&lines, lineIdx, "folder", folder)
	fmBlock := "---\n" + strings.Join(lines, "\n") + "\n---"
	if body == "" {
		return fmBlock + "\n", nil
	}
	return fmBlock + "\n" + body, nil
}

func SetPriority(content string, priority string) (string, error) {
	priority = strings.TrimSpace(priority)
	if priority == "" {
		return content, nil
	}
	lines, body, ok := splitFrontmatterLines(content)
	if !ok {
		return "", fmt.Errorf("frontmatter required")
	}
	lineIdx := map[string]int{}
	for i, line := range lines {
		key, _ := parseFrontmatterLine(line)
		if key == "" {
			continue
		}
		key = strings.ToLower(key)
		if _, exists := lineIdx[key]; !exists {
			lineIdx[key] = i
		}
	}
	setFrontmatterLine(&lines, lineIdx, "priority", priority)
	fmBlock := "---\n" + strings.Join(lines, "\n") + "\n---"
	if body == "" {
		return fmBlock + "\n", nil
	}
	return fmBlock + "\n" + body, nil
}

func HasFrontmatter(content string) bool {
	_, _, ok := splitFrontmatterLines(content)
	return ok
}

func FrontmatterBlock(content string) string {
	lines, _, ok := splitFrontmatterLines(content)
	if !ok {
		return ""
	}
	return "---\n" + strings.Join(lines, "\n") + "\n---"
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

func removeFrontmatterLine(lines *[]string, idx map[string]int, key string) {
	pos, ok := idx[key]
	if !ok || pos < 0 || pos >= len(*lines) {
		return
	}
	*lines = append((*lines)[:pos], (*lines)[pos+1:]...)
	delete(idx, key)
	for k, v := range idx {
		if v > pos {
			idx[k] = v - 1
		}
	}
}

const dummyHistoryUser = "dummy"

type HistoryEntry struct {
	User   string
	At     time.Time
	Action string
}

type FrontmatterAttrs struct {
	ID           string
	Created      time.Time
	CreatedRaw   string
	Updated      time.Time
	UpdatedRaw   string
	Priority     string
	Visibility   string
	Folder       string
	CollapsedH2  []int
	HistoryCount int
	History      []HistoryEntry
	Has          bool
}

func DeriveTitleFromBody(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
	}
	return ""
}

func ParseHistoryEntries(content string) []HistoryEntry {
	lines, _, ok := splitFrontmatterLines(content)
	if !ok {
		return nil
	}
	historyIdx := -1
	for i, line := range lines {
		key, _ := parseFrontmatterLine(line)
		if strings.EqualFold(key, "history") {
			historyIdx = i
			break
		}
	}
	if historyIdx == -1 {
		return nil
	}
	start := historyIdx + 1
	end := start
	for end < len(lines) && isIndentedLine(lines[end]) {
		end++
	}
	if end <= start {
		return nil
	}
	var entries []HistoryEntry
	var current HistoryEntry
	hasCurrent := false
	for i := start; i < end; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "-") {
			if hasCurrent {
				entries = append(entries, current)
			}
			current = HistoryEntry{}
			hasCurrent = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if line == "" {
				continue
			}
		}
		key, val := parseFrontmatterLine(line)
		if key == "" {
			continue
		}
		val = strings.TrimSpace(strings.Trim(val, "\""))
		switch strings.ToLower(key) {
		case "user":
			current.User = val
		case "action":
			current.Action = val
		case "at":
			if at, err := time.Parse(time.RFC3339, val); err == nil {
				current.At = at
			}
		}
	}
	if hasCurrent {
		entries = append(entries, current)
	}
	return entries
}

func LatestHistoryTime(content string) (time.Time, bool) {
	lines, _, ok := splitFrontmatterLines(content)
	if !ok {
		return time.Time{}, false
	}
	historyIdx := -1
	for i, line := range lines {
		key, _ := parseFrontmatterLine(line)
		if strings.EqualFold(key, "history") {
			historyIdx = i
			break
		}
	}
	if historyIdx == -1 {
		return time.Time{}, false
	}
	start := historyIdx + 1
	end := start
	for end < len(lines) && isIndentedLine(lines[end]) {
		end++
	}
	if end <= start {
		return time.Time{}, false
	}
	var latest time.Time
	found := false
	for i := start; i < end; i++ {
		key, val := parseFrontmatterLine(lines[i])
		if !strings.EqualFold(key, "at") {
			continue
		}
		val = strings.TrimSpace(strings.Trim(val, "\""))
		at, err := time.Parse(time.RFC3339, val)
		if err != nil {
			continue
		}
		if !found || at.After(latest) {
			latest = at
			found = true
		}
	}
	return latest, found
}

func FrontmatterAttributes(content string) FrontmatterAttrs {
	lines, _, ok := splitFrontmatterLines(content)
	if !ok {
		return FrontmatterAttrs{}
	}
	attrs := FrontmatterAttrs{Has: true}
	for _, line := range lines {
		key, val := parseFrontmatterLine(line)
		if key == "" {
			continue
		}
		val = strings.TrimSpace(strings.Trim(val, "\""))
		switch strings.ToLower(key) {
		case "id":
			attrs.ID = val
		case "created":
			attrs.Created, attrs.CreatedRaw = parseFrontmatterTime(val)
		case "updated":
			attrs.Updated, attrs.UpdatedRaw = parseFrontmatterTime(val)
		case "priority":
			attrs.Priority = val
		case "visibility":
			attrs.Visibility = val
		case "folder":
			attrs.Folder = val
		case "collapsed_h2":
			attrs.CollapsedH2 = parseFrontmatterIntList(val)
		}
	}
	attrs.HistoryCount = countHistoryEntries(lines)
	if attrs.HistoryCount > 0 {
		attrs.History = ParseHistoryEntries(content)
	}
	if attrs.Visibility == "" {
		attrs.Visibility = "private"
	}
	return attrs
}

func SetCollapsedH2LineNumbers(content string, lineNos []int) (string, error) {
	lines, body, ok := splitFrontmatterLines(content)
	if !ok {
		return "", fmt.Errorf("frontmatter required")
	}
	lineIdx := map[string]int{}
	for i, line := range lines {
		key, _ := parseFrontmatterLine(line)
		if key == "" {
			continue
		}
		key = strings.ToLower(key)
		if _, exists := lineIdx[key]; !exists {
			lineIdx[key] = i
		}
	}
	clean := make([]int, 0, len(lineNos))
	seen := map[int]struct{}{}
	for _, lineNo := range lineNos {
		if lineNo <= 0 {
			continue
		}
		if _, ok := seen[lineNo]; ok {
			continue
		}
		seen[lineNo] = struct{}{}
		clean = append(clean, lineNo)
	}
	sort.Ints(clean)
	if len(clean) == 0 {
		removeFrontmatterLine(&lines, lineIdx, "collapsed_h2")
	} else {
		parts := make([]string, 0, len(clean))
		for _, lineNo := range clean {
			parts = append(parts, strconv.Itoa(lineNo))
		}
		setFrontmatterLine(&lines, lineIdx, "collapsed_h2", "["+strings.Join(parts, ", ")+"]")
	}
	fmBlock := "---\n" + strings.Join(lines, "\n") + "\n---"
	if body == "" {
		return fmBlock + "\n", nil
	}
	return fmBlock + "\n" + body, nil
}

func parseFrontmatterIntList(raw string) []int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]int, 0, len(parts))
	seen := map[int]struct{}{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		val, err := strconv.Atoi(part)
		if err != nil || val <= 0 {
			continue
		}
		if _, ok := seen[val]; ok {
			continue
		}
		seen[val] = struct{}{}
		out = append(out, val)
	}
	sort.Ints(out)
	return out
}

func parseFrontmatterTime(raw string) (time.Time, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, ""
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, ""
	}
	return time.Time{}, raw
}

func countHistoryEntries(lines []string) int {
	historyIdx := -1
	for i, line := range lines {
		key, _ := parseFrontmatterLine(line)
		if strings.EqualFold(key, "history") {
			historyIdx = i
			break
		}
	}
	if historyIdx == -1 {
		return 0
	}
	start := historyIdx + 1
	end := start
	for end < len(lines) && isIndentedLine(lines[end]) {
		end++
	}
	if end <= start {
		return 0
	}
	count := 0
	for i := start; i < end; i++ {
		trimmed := strings.TrimLeft(lines[i], " \t")
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "-\t") || trimmed == "-" {
			count++
		}
	}
	return count
}

func addHistoryEntry(lines *[]string, idx map[string]int, at, action, user string) {
	if strings.TrimSpace(user) == "" {
		user = dummyHistoryUser
	}
	item := []string{
		"  - user: " + user,
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

func upsertHistoryEntry(lines *[]string, idx map[string]int, now time.Time, action, user string) {
	const mergeWindow = 15 * time.Minute
	nowStr := now.Format(time.RFC3339)
	pos, ok := idx["history"]
	if !ok || pos < 0 || pos >= len(*lines) {
		addHistoryEntry(lines, idx, nowStr, action, user)
		return
	}

	start := pos + 1
	end := start
	for end < len(*lines) && isIndentedLine((*lines)[end]) {
		end++
	}
	if end <= start {
		addHistoryEntry(lines, idx, nowStr, action, user)
		return
	}

	var lastStart int = -1
	for i := start; i < end; i++ {
		trimmed := strings.TrimLeft((*lines)[i], " \t")
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "-\t") || strings.HasPrefix(trimmed, "-") {
			lastStart = i
		}
	}
	if lastStart == -1 {
		addHistoryEntry(lines, idx, nowStr, action, user)
		return
	}

	lastAt := ""
	lastAction := ""
	for i := lastStart; i < end; i++ {
		key, val := parseFrontmatterLine((*lines)[i])
		switch strings.ToLower(key) {
		case "at":
			lastAt = strings.TrimSpace(strings.Trim(val, "\""))
		case "action":
			lastAction = strings.TrimSpace(strings.Trim(val, "\""))
		}
	}
	if lastAt == "" || lastAction == "" {
		addHistoryEntry(lines, idx, nowStr, action, user)
		return
	}
	lastTime, err := time.Parse(time.RFC3339, lastAt)
	if err != nil || action != lastAction || now.Sub(lastTime) > mergeWindow {
		addHistoryEntry(lines, idx, nowStr, action, user)
		return
	}

	for i := lastStart; i < end; i++ {
		key, _ := parseFrontmatterLine((*lines)[i])
		if strings.ToLower(key) == "at" {
			(*lines)[i] = "    at: " + nowStr
			return
		}
	}
	addHistoryEntry(lines, idx, nowStr, action, user)
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
