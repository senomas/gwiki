package index

import (
	"regexp"
	"strconv"
	"strings"
)

type Link struct {
	Ref  string
	Kind string
}

type Task struct {
	LineNo int
	Text   string
	Done   bool
	Due    string
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
	tagRe      = regexp.MustCompile(`#([A-Za-z0-9_-]+)`)
	taskRe     = regexp.MustCompile(`^\s*- \[( |x|X)\] (.+)$`)
	dueRe      = regexp.MustCompile(`(?:@due\((\d{4}-\d{2}-\d{2})\)|due:(\d{4}-\d{2}-\d{2}))`)
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
		tags[m[1]] = struct{}{}
	}
	for t := range tags {
		meta.Tags = append(meta.Tags, t)
	}

	for _, m := range wikiLinkRe.FindAllStringSubmatch(body, -1) {
		meta.Links = append(meta.Links, Link{Ref: strings.TrimSpace(m[1]), Kind: "wikilink"})
	}
	for _, m := range mdLinkRe.FindAllStringSubmatch(body, -1) {
		meta.Links = append(meta.Links, Link{Ref: strings.TrimSpace(m[1]), Kind: "mdlink"})
	}

	lines := strings.Split(body, "\n")
	for i, line := range lines {
		match := taskRe.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
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
			Text:   strings.TrimSpace(match[2]),
			Done:   strings.TrimSpace(match[1]) != "",
			Due:    due,
		})
	}

	return meta
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
