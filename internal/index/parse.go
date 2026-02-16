package index

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
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

type HiddenBlock struct {
	StartLine int
	EndLine   int
	Kind      string
	Markdown  string
}

type FilteredSnippet struct {
	Visible        string
	CompletedCount int
	OpenTasks      []Task
	Hidden         []HiddenBlock
}

type NoteBlock struct {
	ID        int
	ParentID  int
	Level     int
	StartLine int
	EndLine   int
	Markdown  string
}

type snippetLine struct {
	LineNo int
	Text   string
}

const (
	HiddenBlockKindCompleted = "completed_block"
	HiddenBlockKindEmptyH2   = "empty_h2"
)

var (
	wikiLinkRe = regexp.MustCompile(`\[\[([^\]]+)\]\]`)
	mdLinkRe   = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
	tagRe      = regexp.MustCompile(`(?:^|\s)#([A-Za-z0-9_/-]+!?)`)
	mentionRe  = regexp.MustCompile(`(?:^|\s)@([A-Za-z0-9_/-]+)`)
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
	for _, line := range nonCodeLines(body) {
		for _, m := range tagRe.FindAllStringSubmatch(line, -1) {
			for _, tag := range expandTagPrefixes(m[1]) {
				tags[tag] = struct{}{}
			}
		}
		for _, m := range mentionRe.FindAllStringSubmatch(line, -1) {
			tags["@"+m[1]] = struct{}{}
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

func ParseNoteBlocks(input string) []NoteBlock {
	body := StripFrontmatter(input)
	lines := strings.Split(body, "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}

	type blockBuilder struct {
		NoteBlock
		startIndent int
		isList      bool
	}

	builders := make([]blockBuilder, 0, 24)
	nextID := 1

	appendBlock := func(parentID, level, startLine, endLine, startIndent int, isList bool) int {
		builder := blockBuilder{
			NoteBlock: NoteBlock{
				ID:        nextID,
				ParentID:  parentID,
				Level:     level,
				StartLine: startLine,
				EndLine:   endLine,
			},
			startIndent: startIndent,
			isList:      isList,
		}
		builders = append(builders, builder)
		nextID++
		return len(builders) - 1
	}

	rootIdx := appendBlock(0, 0, 1, len(lines), 0, false)
	headerStack := []int{rootIdx}
	textStack := make([]int, 0, 16)

	closeTextStack := func(endLine int) {
		if endLine < 1 {
			endLine = 1
		}
		for len(textStack) > 0 {
			idx := textStack[len(textStack)-1]
			textStack = textStack[:len(textStack)-1]
			if endLine < builders[idx].StartLine {
				builders[idx].EndLine = builders[idx].StartLine
				continue
			}
			builders[idx].EndLine = endLine
		}
	}
	closeTextWhile := func(fn func(idx int) bool, endLine int) {
		if endLine < 1 {
			endLine = 1
		}
		for len(textStack) > 0 {
			topIdx := textStack[len(textStack)-1]
			if !fn(topIdx) {
				break
			}
			textStack = textStack[:len(textStack)-1]
			if endLine < builders[topIdx].StartLine {
				builders[topIdx].EndLine = builders[topIdx].StartLine
				continue
			}
			builders[topIdx].EndLine = endLine
		}
	}
	currentContainerIdx := func() int {
		if len(textStack) > 0 {
			return textStack[len(textStack)-1]
		}
		return headerStack[len(headerStack)-1]
	}
	appendTextBlock := func(parentIdx, lineNo, indent int, isList bool) int {
		parent := builders[parentIdx]
		return appendBlock(parent.ID, parent.Level+1, lineNo, lineNo, indent, isList)
	}
	updateActiveEnd := func(lineNo int) {
		for _, idx := range textStack {
			if builders[idx].EndLine < lineNo {
				builders[idx].EndLine = lineNo
			}
		}
	}

	for i, line := range lines {
		lineNo := i + 1
		indent := countIndentColumns(line)
		trimmed := strings.TrimSpace(line)
		isNonEmpty := trimmed != ""
		headingLevel, _, isHeading := parseATXHeading(line)
		isSeparator := isBlockSeparatorLine(line)
		isList := isListMarkerLine(line)

		if isHeading {
			closeTextStack(lineNo - 1)
			for len(headerStack) > 0 {
				topIdx := headerStack[len(headerStack)-1]
				if topIdx == rootIdx {
					break
				}
				if builders[topIdx].Level < headingLevel {
					break
				}
				headerStack = headerStack[:len(headerStack)-1]
			}
			parentIdx := headerStack[len(headerStack)-1]
			parentID := builders[parentIdx].ID
			idx := appendBlock(parentID, headingLevel, lineNo, lineNo, indent, false)
			headerStack = append(headerStack, idx)
			continue
		}

		if isSeparator {
			closeTextStack(lineNo - 1)
			parentIdx := currentContainerIdx()
			parent := builders[parentIdx]
			appendBlock(parent.ID, parent.Level+1, lineNo, lineNo, indent, false)
			continue
		}

		// For positive-indented blocks: dedent on non-empty lines closes nested text blocks.
		if isNonEmpty {
			closeTextWhile(func(idx int) bool {
				if builders[idx].isList && !isList {
					return indent <= builders[idx].startIndent
				}
				return builders[idx].startIndent > 0 && indent < builders[idx].startIndent
			}, lineNo-1)
		}

		if isList {
			closeTextWhile(func(idx int) bool {
				return builders[idx].startIndent > indent
			}, lineNo-1)
			closeTextWhile(func(idx int) bool {
				return builders[idx].startIndent == indent
			}, lineNo-1)
			parentIdx := currentContainerIdx()
			idx := appendTextBlock(parentIdx, lineNo, indent, true)
			textStack = append(textStack, idx)
			updateActiveEnd(lineNo)
			continue
		}

		if len(textStack) == 0 {
			parentIdx := currentContainerIdx()
			idx := appendTextBlock(parentIdx, lineNo, indent, false)
			textStack = append(textStack, idx)
			updateActiveEnd(lineNo)
			continue
		}

		if isNonEmpty {
			for {
				topIdx := textStack[len(textStack)-1]
				top := builders[topIdx]
				if indent <= top.startIndent {
					break
				}

				triggerIndent := top.startIndent + 1
				if top.isList {
					// Keep list continuation lines (usually startIndent+2) in parent list block.
					triggerIndent = top.startIndent + 3
				}
				if indent < triggerIndent {
					break
				}

				childIdx := appendTextBlock(topIdx, lineNo, indent, false)
				textStack = append(textStack, childIdx)
			}
		}

		updateActiveEnd(lineNo)
	}

	closeTextStack(len(lines))

	type headerSpan struct {
		builderIdx int
		level      int
		startLine  int
	}
	headerSpans := make([]headerSpan, 0, 8)
	for i, builder := range builders {
		if builder.Level <= 0 || builder.StartLine <= 0 || builder.StartLine > len(lines) {
			continue
		}
		level, _, ok := parseATXHeading(lines[builder.StartLine-1])
		if !ok {
			continue
		}
		headerSpans = append(headerSpans, headerSpan{
			builderIdx: i,
			level:      level,
			startLine:  builder.StartLine,
		})
	}
	for i := range headerSpans {
		endLine := len(lines)
		for j := i + 1; j < len(headerSpans); j++ {
			if headerSpans[j].level <= headerSpans[i].level {
				endLine = headerSpans[j].startLine - 1
				break
			}
		}
		builderIdx := headerSpans[i].builderIdx
		if endLine < builders[builderIdx].StartLine {
			endLine = builders[builderIdx].StartLine
		}
		builders[builderIdx].EndLine = endLine
	}

	blocks := make([]NoteBlock, 0, len(builders))
	for _, builder := range builders {
		block := builder.NoteBlock
		if block.StartLine <= 0 || block.StartLine > len(lines) {
			continue
		}
		if block.EndLine < block.StartLine {
			block.EndLine = block.StartLine
		}
		if block.EndLine > len(lines) {
			block.EndLine = len(lines)
		}
		startLine := block.StartLine
		endLine := block.EndLine
		for startLine <= endLine && strings.TrimSpace(lines[startLine-1]) == "" {
			startLine++
		}
		for endLine >= startLine && strings.TrimSpace(lines[endLine-1]) == "" {
			endLine--
		}
		if startLine > endLine {
			continue
		}
		block.StartLine = startLine
		block.EndLine = endLine
		block.Markdown = strings.Join(lines[startLine-1:endLine], "\n")
		if strings.TrimSpace(block.Markdown) == "" {
			continue
		}
		blocks = append(blocks, block)
	}
	return blocks
}

func isBlockSeparatorLine(line string) bool {
	return strings.TrimSpace(line) == "---"
}

func isListMarkerLine(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if len(trimmed) >= 2 {
		switch trimmed[0] {
		case '-', '*', '+':
			if trimmed[1] == ' ' || trimmed[1] == '\t' {
				return true
			}
		}
	}
	i := 0
	for i < len(trimmed) && trimmed[i] >= '0' && trimmed[i] <= '9' {
		i++
	}
	if i == 0 || i+1 >= len(trimmed) {
		return false
	}
	if trimmed[i] != '.' && trimmed[i] != ')' {
		return false
	}
	if trimmed[i+1] != ' ' && trimmed[i+1] != '\t' {
		return false
	}
	return true
}

func nonCodeLines(body string) []string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	inFence := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if isIndentedCodeLine(line) {
			continue
		}
		out = append(out, line)
	}
	return out
}

func isIndentedCodeLine(line string) bool {
	if line == "" {
		return false
	}
	spaces := 0
	for _, r := range line {
		if r == ' ' {
			spaces++
			continue
		}
		if r == '\t' {
			return true
		}
		break
	}
	return spaces >= 4
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

func FilterCompletedTasksSnippet(input string) (string, int, []Task) {
	result := FilterCompletedTasksWithHidden(input)
	return result.Visible, result.CompletedCount, result.OpenTasks
}

func FilterCompletedTasksWithHidden(input string) FilteredSnippet {
	body := StripFrontmatter(input)
	lines := strings.Split(body, "\n")
	type blockState struct {
		indent    int
		keep      bool
		hiddenIdx int
	}
	stack := make([]blockState, 0, 8)
	visible := make([]snippetLine, 0, len(lines))
	completed := 0
	tasks := make([]Task, 0)
	hidden := make([]HiddenBlock, 0)

	appendHiddenLine := func(idx int, lineNo int, line string) int {
		if idx < 0 || idx >= len(hidden) {
			hidden = append(hidden, HiddenBlock{
				StartLine: lineNo,
				EndLine:   lineNo,
				Kind:      HiddenBlockKindCompleted,
				Markdown:  line,
			})
			return len(hidden) - 1
		}
		if hidden[idx].StartLine <= 0 {
			hidden[idx].StartLine = lineNo
		}
		if hidden[idx].EndLine < lineNo {
			hidden[idx].EndLine = lineNo
		}
		if hidden[idx].Markdown == "" {
			hidden[idx].Markdown = line
		} else {
			hidden[idx].Markdown += "\n" + line
		}
		return idx
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		lineNo := i + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if len(stack) > 0 && i+1 < len(lines) && countIndentSpaces(lines[i+1]) > stack[len(stack)-1].indent {
				if stack[len(stack)-1].keep {
					visible = append(visible, snippetLine{LineNo: lineNo, Text: line})
				} else {
					top := &stack[len(stack)-1]
					top.hiddenIdx = appendHiddenLine(top.hiddenIdx, lineNo, line)
				}
				continue
			}
			for len(stack) > 0 && 0 <= stack[len(stack)-1].indent {
				stack = stack[:len(stack)-1]
			}
			visible = append(visible, snippetLine{LineNo: lineNo, Text: line})
			continue
		}

		indent := countIndentSpaces(line)
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		match := taskRe.FindStringSubmatch(line)
		if len(match) > 0 {
			done := strings.TrimSpace(match[1]) != ""
			if done {
				completed++
				hidden = append(hidden, HiddenBlock{
					StartLine: lineNo,
					EndLine:   lineNo,
					Kind:      HiddenBlockKindCompleted,
					Markdown:  line,
				})
			} else {
				visible = append(visible, snippetLine{LineNo: lineNo, Text: line})
				tasks = append(tasks, Task{
					LineNo: lineNo,
					Text:   line,
					Done:   false,
					Hash:   TaskLineHash(line),
				})
			}
			hiddenIdx := -1
			if done {
				hiddenIdx = len(hidden) - 1
			}
			stack = append(stack, blockState{indent: indent, keep: !done, hiddenIdx: hiddenIdx})
			continue
		}
		if len(stack) == 0 || stack[len(stack)-1].keep {
			visible = append(visible, snippetLine{LineNo: lineNo, Text: line})
		} else {
			top := &stack[len(stack)-1]
			top.hiddenIdx = appendHiddenLine(top.hiddenIdx, lineNo, line)
		}
	}

	visible, hiddenH2 := filterEmptyH2WithHidden(visible)
	hidden = append(hidden, hiddenH2...)
	sort.SliceStable(hidden, func(i, j int) bool {
		if hidden[i].StartLine == hidden[j].StartLine {
			return hidden[i].EndLine < hidden[j].EndLine
		}
		return hidden[i].StartLine < hidden[j].StartLine
	})

	out := make([]string, 0, len(visible))
	for _, line := range visible {
		out = append(out, line.Text)
	}
	return FilteredSnippet{
		Visible:        strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n",
		CompletedCount: completed,
		OpenTasks:      tasks,
		Hidden:         hidden,
	}
}

func filterEmptyH2(lines []string) []string {
	entries := make([]snippetLine, 0, len(lines))
	for i, line := range lines {
		entries = append(entries, snippetLine{LineNo: i + 1, Text: line})
	}
	filtered, _ := filterEmptyH2WithHidden(entries)
	out := make([]string, 0, len(filtered))
	for _, line := range filtered {
		out = append(out, line.Text)
	}
	return out
}

func filterEmptyH2WithHidden(lines []snippetLine) ([]snippetLine, []HiddenBlock) {
	if len(lines) == 0 {
		return lines, nil
	}
	keep := make([]bool, len(lines))
	for i := range lines {
		keep[i] = true
	}
	hidden := make([]HiddenBlock, 0)
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i].Text)
		if !strings.HasPrefix(line, "## ") {
			continue
		}
		hasContent := false
		for j := i + 1; j < len(lines); j++ {
			next := strings.TrimSpace(lines[j].Text)
			if strings.HasPrefix(next, "#") {
				break
			}
			if next != "" {
				hasContent = true
				break
			}
		}
		if !hasContent {
			keep[i] = false
			hidden = append(hidden, HiddenBlock{
				StartLine: lines[i].LineNo,
				EndLine:   lines[i].LineNo,
				Kind:      HiddenBlockKindEmptyH2,
				Markdown:  lines[i].Text,
			})
		}
	}
	filtered := make([]snippetLine, 0, len(lines))
	for i, line := range lines {
		if keep[i] {
			filtered = append(filtered, line)
		}
	}
	return filtered, hidden
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
	inFence := false
	for _, line := range paragraph {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || isIndentedCodeLine(line) {
			continue
		}
		for _, m := range tagRe.FindAllStringSubmatch(line, -1) {
			for _, tag := range expandTagPrefixes(m[1]) {
				tags[tag] = struct{}{}
			}
		}
		for _, m := range mentionRe.FindAllStringSubmatch(line, -1) {
			tags["@"+m[1]] = struct{}{}
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

func countIndentColumns(line string) int {
	columns := 0
	for _, r := range line {
		switch r {
		case ' ':
			columns++
		case '\t':
			columns += 4
		default:
			return columns
		}
	}
	return columns
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

func parseHeadingBuckets(body string) [6]string {
	var levels [6][]string
	for _, line := range nonCodeLines(body) {
		level, text, ok := parseATXHeading(line)
		if !ok {
			continue
		}
		levels[level-1] = append(levels[level-1], text)
	}
	var out [6]string
	for i := range levels {
		out[i] = strings.Join(levels[i], "\n")
	}
	return out
}

func parseATXHeading(line string) (int, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return 0, "", false
	}
	level := 0
	for level < len(trimmed) && trimmed[level] == '#' {
		level++
	}
	if level == 0 || level > 6 || len(trimmed) == level {
		return 0, "", false
	}
	if trimmed[level] != ' ' && trimmed[level] != '\t' {
		return 0, "", false
	}
	text := strings.TrimSpace(trimmed[level:])
	if text == "" {
		return 0, "", false
	}
	text = trimATXHeadingClosingHashes(text)
	if text == "" {
		return 0, "", false
	}
	return level, text, true
}

func trimATXHeadingClosingHashes(text string) string {
	text = strings.TrimSpace(text)
	i := len(text) - 1
	for i >= 0 && text[i] == '#' {
		i--
	}
	if i < len(text)-1 {
		if i < 0 {
			return ""
		}
		if text[i] == ' ' || text[i] == '\t' {
			text = strings.TrimRight(text[:i], " \t")
		}
	}
	return strings.TrimSpace(text)
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
