package index

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

type Link struct {
	Ref    string
	Kind   string
	LineNo int
	Line   string
}

type Task struct {
	LineNo int
	Text   string
	Done   bool
	Due    string
	Hash   string
	Tags   []string
}

type Metadata struct {
	Title    string
	Tags     []string
	Links    []Link
	Tasks    []Task
	Priority int
}

var (
	wikiLinkRe = regexp.MustCompile(`\[\[([^\]]+)\]\]`)
	mdLinkRe   = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	tagRe      = regexp.MustCompile(`(?:^|\s)#([A-Za-z0-9_/-]+!?)`)
	taskRe     = regexp.MustCompile(`^\s*- \[( |x|X)\] (.+)$`)
	dueRe      = regexp.MustCompile(`(?i)(?:@due\((\d{4}-\d{2}-\d{2})\)|due:(\d{4}-\d{2}-\d{2}))`)
)

func ParseContent(input string) Metadata {
	body, fm := splitFrontmatter(input)
	meta := Metadata{
		Title:    parseTitle(body, fm),
		Priority: parsePriority(fm),
	}

	tags := map[string]struct{}{}
	for _, t := range parseTagsFromFrontmatter(fm) {
		tags[t] = struct{}{}
	}
	for _, m := range tagRe.FindAllStringSubmatch(body, -1) {
		for _, tag := range expandTagPrefixes(m[1]) {
			tags[tag] = struct{}{}
		}
	}
	for t := range tags {
		meta.Tags = append(meta.Tags, t)
	}

	lines := strings.Split(body, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		for _, m := range wikiLinkRe.FindAllStringSubmatch(line, -1) {
			meta.Links = append(meta.Links, Link{
				Ref:    strings.TrimSpace(m[1]),
				Kind:   "wikilink",
				LineNo: i + 1,
				Line:   line,
			})
		}
		for _, m := range mdLinkRe.FindAllStringSubmatch(line, -1) {
			meta.Links = append(meta.Links, Link{
				Ref:    strings.TrimSpace(m[1]),
				Kind:   "mdlink",
				LineNo: i + 1,
				Line:   line,
			})
		}
		match := taskRe.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		taskTags := extractTaskTags(lines, i)
		due := ""
		if d := dueRe.FindStringSubmatch(match[2]); len(d) > 0 {
			if d[1] != "" {
				due = d[1]
			} else {
				due = d[2]
			}
		}
		meta.Tasks = append(meta.Tasks, Task{
			LineNo: i + 1,
			Text:   line,
			Done:   strings.TrimSpace(match[1]) != "",
			Due:    due,
			Hash:   TaskLineHash(line),
			Tags:   taskTags,
		})
	}

	return meta
}

func UncheckedTasksSnippet(input string) string {
	frontmatter := FrontmatterBlock(input)
	body := StripFrontmatter(input)
	lines := strings.Split(body, "\n")
	title := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") {
			title = trimmed
			break
		}
	}
	var tasks []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		indent := countIndentSpaces(line)
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- [ ]") {
			continue
		}
		paragraph := []string{line}
		baseIndent := indent + 2
		skipIndent := -1
		for j := i + 1; j < len(lines); j++ {
			next := lines[j]
			nextIndent := countIndentSpaces(next)
			if skipIndent >= 0 {
				if nextIndent > skipIndent {
					continue
				}
				if next == "" && j+1 < len(lines) && countIndentSpaces(lines[j+1]) > skipIndent {
					continue
				}
				skipIndent = -1
			}
			nextTrimmed := strings.TrimSpace(next)
			if strings.HasPrefix(nextTrimmed, "- [x]") || strings.HasPrefix(nextTrimmed, "- [X]") {
				skipIndent = nextIndent
				continue
			}
			if next == "" && j+1 < len(lines) && countIndentSpaces(lines[j+1]) >= baseIndent {
				paragraph = append(paragraph, next)
				continue
			}
			if nextIndent >= baseIndent {
				paragraph = append(paragraph, next)
				continue
			}
			break
		}
		tasks = append(tasks, strings.Join(paragraph, "\n"))
	}
	var out []string
	if frontmatter != "" {
		out = append(out, frontmatter, "")
	}
	if title != "" {
		out = append(out, title, "")
	}
	if len(tasks) > 0 {
		out = append(out, strings.Join(tasks, "\n\n"))
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
}

func extractTaskTags(lines []string, start int) []string {
	if start < 0 || start >= len(lines) {
		return nil
	}
	line := lines[start]
	baseIndent := countIndentSpaces(line) + 2
	paragraph := []string{line}
	for j := start + 1; j < len(lines); j++ {
		next := lines[j]
		if next == "" && j+1 < len(lines) && countIndentSpaces(lines[j+1]) >= baseIndent {
			paragraph = append(paragraph, next)
			continue
		}
		if countIndentSpaces(next) < baseIndent {
			break
		}
		paragraph = append(paragraph, next)
	}
	tags := map[string]struct{}{}
	for _, line := range paragraph {
		for _, m := range tagRe.FindAllStringSubmatch(line, -1) {
			for _, tag := range expandTagPrefixes(m[1]) {
				tags[tag] = struct{}{}
			}
		}
	}
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for tag := range tags {
		out = append(out, tag)
	}
	return out
}

func DueTasksSnippet(input string) string {
	return DueTasksSnippetWithDefaultDate(input, "")
}

func DueTasksSnippetWithDefaultDate(input string, defaultDue string) string {
	frontmatter := FrontmatterBlock(input)
	body := StripFrontmatter(input)
	lines := strings.Split(body, "\n")
	title := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") {
			title = trimmed
			break
		}
	}
	var tasks []string
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		indent := countIndentSpaces(line)
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- [ ]") {
			continue
		}
		match := taskRe.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		hasDue := false
		if d := dueRe.FindStringSubmatch(match[2]); len(d) > 0 {
			hasDue = true
		}
		if !hasDue && defaultDue == "" {
			continue
		}
		if !hasDue && defaultDue != "" {
			line = strings.TrimRight(line, " ") + " due:" + defaultDue
		}
		paragraph := []string{line}
		baseIndent := indent + 2
		for j := i + 1; j < len(lines); j++ {
			next := lines[j]
			nextIndent := countIndentSpaces(next)
			if next == "" && j+1 < len(lines) && countIndentSpaces(lines[j+1]) >= baseIndent {
				paragraph = append(paragraph, next)
				continue
			}
			if nextIndent >= baseIndent {
				paragraph = append(paragraph, next)
				continue
			}
			break
		}
		tasks = append(tasks, strings.Join(paragraph, "\n"))
	}
	var out []string
	if frontmatter != "" {
		out = append(out, frontmatter, "")
	}
	if title != "" {
		out = append(out, title, "")
	}
	if len(tasks) > 0 {
		out = append(out, strings.Join(tasks, "\n\n"))
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
}

func countIndentSpaces(line string) int {
	count := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		count++
	}
	return count
}

func TaskLineHash(line string) string {
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:])
}

func expandTagPrefixes(tag string) []string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil
	}
	parts := splitTagParts(tag)
	if len(parts) == 1 {
		return []string{tag}
	}
	out := make([]string, 0, len(parts))
	for i := range parts {
		segment := strings.Join(parts[:i+1], "/")
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

func splitTagParts(tag string) []string {
	parts := strings.FieldsFunc(tag, func(r rune) bool {
		return r == '/'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func StripFrontmatter(input string) string {
	body, _ := splitFrontmatter(input)
	return body
}

func splitFrontmatter(input string) (string, map[string]string) {
	lines := strings.Split(input, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return input, nil
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return input, nil
	}
	fm := parseFrontmatter(lines[1:end])
	return strings.Join(lines[end+1:], "\n"), fm
}

func parseFrontmatter(lines []string) map[string]string {
	fm := make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		fm[strings.ToLower(key)] = strings.Trim(val, "\"")
	}
	return fm
}

func parseTitle(body string, fm map[string]string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "# "))
		}
	}
	return ""
}

func parseTagsFromFrontmatter(fm map[string]string) []string {
	if fm == nil {
		return nil
	}
	raw, ok := fm["tags"]
	if !ok || raw == "" {
		return nil
	}
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = strings.TrimPrefix(raw, "[")
		raw = strings.TrimSuffix(raw, "]")
	}
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.Trim(p, "\""))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePriority(fm map[string]string) int {
	const defaultPriority = 10
	if fm == nil {
		return defaultPriority
	}
	raw := strings.TrimSpace(fm["priority"])
	if raw == "" {
		return defaultPriority
	}
	if val, err := strconv.Atoi(raw); err == nil && val > 0 {
		return val
	}
	return defaultPriority
}
