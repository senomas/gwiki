package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"gwiki/internal/index"
	fsio "gwiki/internal/storage/fs"
)

var (
	sourceJournalFileRe = regexp.MustCompile(`^\d{4}-\d{2}/\d{2}\.md$`)
	sectionHeadingTime  = regexp.MustCompile(`^##\s+([0-2][0-9]):([0-5][0-9])\s*$`)
)

type runOptions struct {
	Root    string
	DryRun  bool
	Verbose bool
	Out     io.Writer
	ErrOut  io.Writer
}

type runStats struct {
	OwnersScanned  int
	SourceFiles    int
	Migrated       int
	Skipped        int
	Failed         int
	CreatedTargets int
	UpdatedTargets int
	DeletedSources int
}

type sourceFile struct {
	Owner string
	Path  string
	Rel   string
}

type splitResult struct {
	Order   []string
	Buckets map[string]string
}

type migrateResult struct {
	Skipped        bool
	CreatedTargets int
	UpdatedTargets int
	DeletedSource  bool
}

type targetEntryPlan struct {
	Created              bool
	Updated              bool
	TargetID             string
	Content              string
	SourceAttachmentRefs map[string]struct{}
}

type attachmentRef struct {
	start  int
	end    int
	noteID string
	rel    string
	prefix string
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, out io.Writer, errOut io.Writer) int {
	flagSet := flag.NewFlagSet("migrate-journal", flag.ContinueOnError)
	flagSet.SetOutput(errOut)

	opts := runOptions{
		Out:    out,
		ErrOut: errOut,
	}
	flagSet.StringVar(&opts.Root, "repo", "", "wiki repository root (defaults to $WIKI_REPO_PATH or current directory)")
	flagSet.BoolVar(&opts.DryRun, "dry-run", false, "show migration actions without writing files")
	flagSet.BoolVar(&opts.Verbose, "verbose", false, "print per-file migration details")

	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	if flagSet.NArg() != 0 {
		_, _ = fmt.Fprintln(errOut, "usage: migrate-journal [--repo <path>] [--dry-run] [--verbose]")
		return 2
	}

	root, stats, err := execute(opts)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(
		out,
		"root=%s owners=%d source=%d migrated=%d skipped=%d failed=%d created=%d updated=%d deleted=%d dry_run=%t\n",
		root,
		stats.OwnersScanned,
		stats.SourceFiles,
		stats.Migrated,
		stats.Skipped,
		stats.Failed,
		stats.CreatedTargets,
		stats.UpdatedTargets,
		stats.DeletedSources,
		opts.DryRun,
	)

	if stats.Failed > 0 {
		return 1
	}
	return 0
}

func execute(opts runOptions) (string, runStats, error) {
	var stats runStats
	out := opts.Out
	errOut := opts.ErrOut
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}

	rootInput := strings.TrimSpace(opts.Root)
	if rootInput == "" {
		rootInput = strings.TrimSpace(os.Getenv("WIKI_REPO_PATH"))
	}
	if rootInput == "" {
		rootInput = "."
	}

	rootAbs, err := filepath.Abs(rootInput)
	if err != nil {
		return "", stats, fmt.Errorf("resolve repo root: %w", err)
	}
	info, err := os.Stat(rootAbs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rootAbs, stats, fmt.Errorf("repo root not found: %s", rootAbs)
		}
		return rootAbs, stats, fmt.Errorf("stat repo root %s: %w", rootAbs, err)
	}
	if !info.IsDir() {
		return rootAbs, stats, fmt.Errorf("repo root is not a directory: %s", rootAbs)
	}

	owners, err := discoverOwners(rootAbs)
	if err != nil {
		return rootAbs, stats, err
	}
	stats.OwnersScanned = len(owners)

	now := time.Now().In(time.Local)
	for _, owner := range owners {
		notesRoot := filepath.Join(rootAbs, owner, "notes")
		sources, srcErr := discoverSourceFiles(notesRoot, owner)
		if srcErr != nil {
			stats.Failed++
			_, _ = fmt.Fprintf(errOut, "ERROR: owner=%s discover source files: %v\n", owner, srcErr)
			continue
		}
		stats.SourceFiles += len(sources)
		for _, src := range sources {
			if opts.Verbose {
				_, _ = fmt.Fprintf(out, "scan %s\n", filepath.ToSlash(filepath.Join(src.Owner, src.Rel)))
			}
			result, migrateErr := migrateSourceFile(src, now, opts.DryRun)
			if migrateErr != nil {
				stats.Failed++
				_, _ = fmt.Fprintf(errOut, "ERROR: migrate %s: %v\n", filepath.ToSlash(filepath.Join(src.Owner, src.Rel)), migrateErr)
				continue
			}
			if result.Skipped {
				stats.Skipped++
				if opts.Verbose {
					_, _ = fmt.Fprintf(out, "skip %s\n", filepath.ToSlash(filepath.Join(src.Owner, src.Rel)))
				}
				continue
			}
			stats.Migrated++
			stats.CreatedTargets += result.CreatedTargets
			stats.UpdatedTargets += result.UpdatedTargets
			if result.DeletedSource {
				stats.DeletedSources++
			}
			if opts.Verbose {
				_, _ = fmt.Fprintf(
					out,
					"migrated %s created=%d updated=%d deleted=%t\n",
					filepath.ToSlash(filepath.Join(src.Owner, src.Rel)),
					result.CreatedTargets,
					result.UpdatedTargets,
					result.DeletedSource,
				)
			}
		}
	}

	return rootAbs, stats, nil
}

func discoverOwners(repoRoot string) ([]string, error) {
	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("read repo root: %w", err)
	}
	owners := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		notesDir := filepath.Join(repoRoot, name, "notes")
		info, statErr := os.Stat(notesDir)
		if statErr != nil || !info.IsDir() {
			continue
		}
		owners = append(owners, name)
	}
	sort.Strings(owners)
	return owners, nil
}

func discoverSourceFiles(notesRoot string, owner string) ([]sourceFile, error) {
	files := make([]sourceFile, 0, 32)
	err := filepath.WalkDir(notesRoot, func(path string, d iofs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if strings.EqualFold(d.Name(), "attachments") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		rel, err := filepath.Rel(notesRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !sourceJournalFileRe.MatchString(rel) {
			return nil
		}
		files = append(files, sourceFile{
			Owner: owner,
			Path:  path,
			Rel:   rel,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].Owner == files[j].Owner {
			return files[i].Rel < files[j].Rel
		}
		return files[i].Owner < files[j].Owner
	})
	return files, nil
}

func migrateSourceFile(src sourceFile, now time.Time, dryRun bool) (migrateResult, error) {
	var out migrateResult
	contentBytes, err := os.ReadFile(src.Path)
	if err != nil {
		return out, err
	}
	content := normalizeLineEndings(string(contentBytes))
	sourceAttrs := index.FrontmatterAttributes(content)
	sourceNoteID := strings.TrimSpace(sourceAttrs.ID)
	attachmentsRoot := filepath.Join(filepath.Dir(filepath.Dir(src.Path)), "attachments")
	sourceAttachmentsDir := ""
	if sourceNoteID != "" {
		sourceAttachmentsDir = filepath.Join(attachmentsRoot, sourceNoteID)
	}

	day, err := journalDayFromRel(src.Rel)
	if err != nil {
		return out, err
	}
	split := parseDailyJournal(content, day)
	if len(split.Order) == 0 {
		out.Skipped = true
		return out, nil
	}

	dateTitle := day.Format("2 Jan 2006")
	keepSourceAttachments := false
	for _, bucket := range split.Order {
		body := strings.TrimSpace(split.Buckets[bucket])
		if body == "" {
			continue
		}
		targetPath := filepath.Join(filepath.Dir(src.Path), targetFileName(day, bucket))
		plan, err := planTargetEntry(targetPath, dateTitle, body, now, sourceNoteID)
		if err != nil {
			return out, err
		}
		if !plan.Created && !plan.Updated {
			continue
		}
		if sourceNoteID != "" && plan.TargetID == sourceNoteID {
			keepSourceAttachments = true
		}
		if !dryRun {
			if err := copyAttachmentRefs(sourceAttachmentsDir, filepath.Join(attachmentsRoot, plan.TargetID), plan.SourceAttachmentRefs); err != nil {
				return out, err
			}
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return out, err
			}
			if err := fsio.WriteFileAtomic(targetPath, []byte(plan.Content), 0o644); err != nil {
				return out, err
			}
		}
		if plan.Created {
			out.CreatedTargets++
		}
		if plan.Updated {
			out.UpdatedTargets++
		}
	}

	if out.CreatedTargets == 0 && out.UpdatedTargets == 0 {
		out.Skipped = true
		return out, nil
	}

	if dryRun {
		out.DeletedSource = true
		return out, nil
	}
	if err := os.Remove(src.Path); err != nil {
		return out, err
	}
	if sourceAttachmentsDir != "" && !keepSourceAttachments {
		if err := removeAttachmentDir(sourceAttachmentsDir); err != nil {
			return out, err
		}
	}
	out.DeletedSource = true
	return out, nil
}

func planTargetEntry(targetPath, dateTitle, body string, now time.Time, sourceNoteID string) (targetEntryPlan, error) {
	var out targetEntryPlan
	body = strings.TrimSpace(normalizeLineEndings(body))
	if body == "" {
		return out, nil
	}

	existingBytes, err := os.ReadFile(targetPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}

	if errors.Is(err, os.ErrNotExist) {
		targetID := uuid.NewString()
		rewrittenBody, refs := rewriteAttachmentRefs(body, sourceNoteID, targetID)
		out.Created = true
		out.TargetID = targetID
		out.Content = buildMigratedNoteContent(dateTitle, rewrittenBody, now, targetID)
		out.SourceAttachmentRefs = refs
		return out, nil
	}

	existing := normalizeLineEndings(string(existingBytes))
	frontmatter, existingBody, hasFrontmatter := splitFrontmatterBlock(existing)

	targetID := ""
	hadID := false
	if hasFrontmatter {
		attrs := index.FrontmatterAttributes(frontmatter)
		targetID = strings.TrimSpace(attrs.ID)
		hadID = targetID != ""
	}
	if targetID == "" {
		targetID = uuid.NewString()
	}

	mergedBody := mergeBodies(existingBody, body)
	rewrittenBody, refs := rewriteAttachmentRefs(mergedBody, sourceNoteID, targetID)
	var next string
	if hasFrontmatter {
		if !hadID {
			withBody := composeFrontmatterBody(frontmatter, existingBody)
			withID, err := index.SetFrontmatterID(withBody, targetID)
			if err != nil {
				return out, err
			}
			var ok bool
			frontmatter, _, ok = splitFrontmatterBlock(normalizeLineEndings(withID))
			if !ok {
				return out, fmt.Errorf("frontmatter id update failed for %s", targetPath)
			}
		}
		next = composeFrontmatterBody(frontmatter, rewrittenBody)
	} else {
		next = buildMigratedNoteContent(dateTitle, rewrittenBody, now, targetID)
	}

	out.Updated = true
	out.TargetID = targetID
	out.Content = next
	out.SourceAttachmentRefs = refs
	return out, nil
}

func parseDailyJournal(content string, day time.Time) splitResult {
	body := normalizeLineEndings(index.StripFrontmatter(content))
	lines := strings.Split(body, "\n")
	lines = dropDateHeadingLine(lines, day)

	buckets := make(map[string][]string)
	order := make([]string, 0, 8)
	sectionCount := make(map[string]int)
	ensureBucket := func(key string) {
		if _, ok := buckets[key]; ok {
			return
		}
		buckets[key] = nil
		order = append(order, key)
	}

	current := ""
	inTimedSection := false
	for _, line := range lines {
		hour, minute, ok := parseSectionTimeHeading(line)
		if ok {
			current = fmt.Sprintf("%02d-%02d", hour, minute)
			ensureBucket(current)
			if sectionCount[current] > 0 && len(buckets[current]) > 0 {
				last := strings.TrimSpace(buckets[current][len(buckets[current])-1])
				if last != "" {
					buckets[current] = append(buckets[current], "")
				}
			}
			sectionCount[current]++
			inTimedSection = true
			continue
		}
		if inTimedSection {
			buckets[current] = append(buckets[current], line)
			continue
		}
		ensureBucket("00-00")
		buckets["00-00"] = append(buckets["00-00"], line)
	}

	out := splitResult{
		Order:   make([]string, 0, len(order)),
		Buckets: make(map[string]string, len(order)),
	}
	for _, key := range order {
		trimmed := trimBlankEdges(buckets[key])
		if len(trimmed) == 0 {
			continue
		}
		joined := strings.TrimSpace(strings.Join(trimmed, "\n"))
		if joined == "" {
			continue
		}
		out.Order = append(out.Order, key)
		out.Buckets[key] = joined
	}
	return out
}

func parseSectionTimeHeading(line string) (int, int, bool) {
	matches := sectionHeadingTime.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 3 {
		return 0, 0, false
	}
	hour, err := strconv.Atoi(matches[1])
	if err != nil || hour < 0 || hour > 23 {
		return 0, 0, false
	}
	minute, err := strconv.Atoi(matches[2])
	if err != nil || minute < 0 || minute > 59 {
		return 0, 0, false
	}
	return hour, minute, true
}

func dropDateHeadingLine(lines []string, day time.Time) []string {
	firstNonEmpty := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		firstNonEmpty = i
		break
	}
	if firstNonEmpty == -1 {
		return lines
	}
	trimmed := strings.TrimSpace(lines[firstNonEmpty])
	if !strings.HasPrefix(trimmed, "# ") {
		return lines
	}
	rawDate := strings.TrimSpace(strings.TrimPrefix(trimmed, "# "))
	if rawDate == "" {
		return lines
	}
	if !isSameDayTitle(rawDate, day) {
		return lines
	}
	return append(lines[:firstNonEmpty], lines[firstNonEmpty+1:]...)
}

func isSameDayTitle(raw string, day time.Time) bool {
	layouts := []string{
		"2006-01-02",
		"2 Jan 2006",
		"02 Jan 2006",
	}
	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(layout, raw, time.Local)
		if err != nil {
			continue
		}
		if parsed.Format("2006-01-02") == day.Format("2006-01-02") {
			return true
		}
	}
	return false
}

func trimBlankEdges(lines []string) []string {
	if len(lines) == 0 {
		return nil
	}
	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	end := len(lines) - 1
	for end >= start && strings.TrimSpace(lines[end]) == "" {
		end--
	}
	if start > end {
		return nil
	}
	return append([]string(nil), lines[start:end+1]...)
}

func mergeBodies(existing, incoming string) string {
	existing = strings.TrimSpace(normalizeLineEndings(existing))
	incoming = strings.TrimSpace(normalizeLineEndings(incoming))
	if existing == "" {
		return incoming
	}
	if incoming == "" {
		return existing
	}
	return existing + "\n\n" + incoming
}

func rewriteAttachmentRefs(content, sourceNoteID, targetNoteID string) (string, map[string]struct{}) {
	sourceNoteID = strings.TrimSpace(sourceNoteID)
	targetNoteID = strings.TrimSpace(targetNoteID)
	if sourceNoteID == "" || targetNoteID == "" || sourceNoteID == targetNoteID {
		return content, nil
	}

	refs := scanAttachmentRefs(content)
	if len(refs) == 0 {
		return content, nil
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].start == refs[j].start {
			return refs[i].end < refs[j].end
		}
		return refs[i].start < refs[j].start
	})

	replaced := map[string]struct{}{}
	var b strings.Builder
	b.Grow(len(content))
	cursor := 0
	for _, ref := range refs {
		if ref.noteID != sourceNoteID {
			continue
		}
		if ref.start < cursor {
			continue
		}
		b.WriteString(content[cursor:ref.start])
		b.WriteString(ref.prefix)
		b.WriteString(targetNoteID)
		b.WriteByte('/')
		b.WriteString(ref.rel)
		cursor = ref.end
		replaced[ref.rel] = struct{}{}
	}
	if len(replaced) == 0 {
		return content, nil
	}
	b.WriteString(content[cursor:])
	return b.String(), replaced
}

func scanAttachmentRefs(content string) []attachmentRef {
	refs := make([]attachmentRef, 0, 8)
	prefixes := []string{"/attachments/", "attachments/"}
	isDelim := func(r byte) bool {
		switch r {
		case ' ', '\n', '\r', '\t', ')', ']', '"', '\'', '<', '>', '(':
			return true
		default:
			return false
		}
	}
	for _, prefix := range prefixes {
		offset := 0
		for {
			idx := strings.Index(content[offset:], prefix)
			if idx == -1 {
				break
			}
			start := offset + idx
			cursor := start + len(prefix)
			if cursor >= len(content) {
				break
			}
			slash := strings.IndexByte(content[cursor:], '/')
			if slash <= 0 {
				offset = cursor
				continue
			}
			noteID := strings.TrimSpace(content[cursor : cursor+slash])
			if noteID == "" {
				offset = cursor + slash
				continue
			}
			pathStart := cursor + slash + 1
			pathEnd := pathStart
			for pathEnd < len(content) && !isDelim(content[pathEnd]) {
				pathEnd++
			}
			if pathEnd <= pathStart {
				offset = pathStart
				continue
			}
			rel := strings.TrimSpace(content[pathStart:pathEnd])
			rel = strings.TrimPrefix(rel, "./")
			rel = strings.TrimPrefix(rel, "/")
			rel = path.Clean(rel)
			if rel == "." || strings.HasPrefix(rel, "..") || strings.Contains(rel, "\\") || rel == "" {
				offset = pathEnd
				continue
			}
			refs = append(refs, attachmentRef{
				start:  start,
				end:    pathEnd,
				noteID: noteID,
				rel:    rel,
				prefix: prefix,
			})
			offset = pathEnd
		}
	}
	return refs
}

func copyAttachmentRefs(sourceDir, targetDir string, refs map[string]struct{}) error {
	if len(refs) == 0 {
		return nil
	}
	sourceDir = filepath.Clean(strings.TrimSpace(sourceDir))
	targetDir = filepath.Clean(strings.TrimSpace(targetDir))
	if sourceDir == "" || targetDir == "" {
		return fmt.Errorf("attachment copy requires source and target dirs")
	}
	if sourceDir == targetDir {
		return nil
	}
	if info, err := os.Stat(sourceDir); err != nil {
		return fmt.Errorf("stat source attachments dir %s: %w", sourceDir, err)
	} else if !info.IsDir() {
		return fmt.Errorf("source attachments path is not a directory: %s", sourceDir)
	}

	keys := make([]string, 0, len(refs))
	for rel := range refs {
		keys = append(keys, rel)
	}
	sort.Strings(keys)
	for _, rel := range keys {
		srcPath, err := safeJoinUnder(sourceDir, rel)
		if err != nil {
			return fmt.Errorf("resolve source attachment %q: %w", rel, err)
		}
		dstPath, err := safeJoinUnder(targetDir, rel)
		if err != nil {
			return fmt.Errorf("resolve target attachment %q: %w", rel, err)
		}
		if err := copyAttachmentFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("copy attachment %q: %w", rel, err)
		}
	}
	return nil
}

func safeJoinUnder(rootDir, rel string) (string, error) {
	rootDir = filepath.Clean(strings.TrimSpace(rootDir))
	rel = strings.TrimSpace(rel)
	rel = strings.TrimPrefix(rel, "/")
	if rootDir == "" || rel == "" {
		return "", fmt.Errorf("invalid path")
	}
	full := filepath.Clean(filepath.Join(rootDir, filepath.FromSlash(rel)))
	relative, err := filepath.Rel(rootDir, full)
	if err != nil {
		return "", err
	}
	if relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes root")
	}
	return full, nil
}

func copyAttachmentFile(srcPath, dstPath string) error {
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	if srcInfo.IsDir() {
		return fmt.Errorf("source is directory")
	}
	if filepath.Clean(srcPath) == filepath.Clean(dstPath) {
		return nil
	}

	if dstInfo, err := os.Stat(dstPath); err == nil {
		if dstInfo.IsDir() {
			return fmt.Errorf("target exists as directory")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	tmpFile, err := os.CreateTemp(filepath.Dir(dstPath), ".copy-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := io.Copy(tmpFile, srcFile); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, dstPath)
}

func removeAttachmentDir(dir string) error {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "" {
		return nil
	}
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return os.RemoveAll(dir)
}

func journalDayFromRel(rel string) (time.Time, error) {
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if !sourceJournalFileRe.MatchString(rel) {
		return time.Time{}, fmt.Errorf("invalid source journal path: %s", rel)
	}
	datePart := strings.TrimSuffix(rel, ".md")
	day, err := time.ParseInLocation("2006-01/02", datePart, time.Local)
	if err != nil {
		return time.Time{}, err
	}
	return day, nil
}

func targetFileName(day time.Time, bucket string) string {
	return fmt.Sprintf("%s-%s.md", day.Format("02"), bucket)
}

func buildMigratedNoteContent(dateTitle, body string, now time.Time, noteID string) string {
	body = strings.TrimSpace(normalizeLineEndings(body))
	noteID = strings.TrimSpace(noteID)
	if noteID == "" {
		noteID = uuid.NewString()
	}
	fm := []string{
		"---",
		"id: " + noteID,
		"title: " + dateTitle,
		"created: " + now.Format(time.RFC3339),
		"updated: " + now.Format(time.RFC3339),
		"priority: 10",
		"visibility: inherited",
		"---",
	}
	if body == "" {
		return strings.Join(fm, "\n") + "\n"
	}
	return strings.Join(fm, "\n") + "\n\n" + body + "\n"
}

func splitFrontmatterBlock(content string) (string, string, bool) {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return "", content, false
	}
	end := -1
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end <= 0 {
		return "", content, false
	}
	frontmatter := strings.Join(lines[:end+1], "\n")
	body := strings.Join(lines[end+1:], "\n")
	return frontmatter, body, true
}

func composeFrontmatterBody(frontmatter, body string) string {
	frontmatter = strings.TrimRight(normalizeLineEndings(frontmatter), "\n")
	body = strings.TrimSpace(normalizeLineEndings(body))
	if body == "" {
		return frontmatter + "\n"
	}
	return frontmatter + "\n\n" + body + "\n"
}

func normalizeLineEndings(content string) string {
	return strings.ReplaceAll(content, "\r\n", "\n")
}
