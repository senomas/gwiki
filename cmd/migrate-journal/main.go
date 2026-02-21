package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
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
	day, err := journalDayFromRel(src.Rel)
	if err != nil {
		return out, err
	}
	split := parseDailyJournal(string(contentBytes), day)
	if len(split.Order) == 0 {
		out.Skipped = true
		return out, nil
	}

	dateTitle := day.Format("2 Jan 2006")
	for _, bucket := range split.Order {
		body := strings.TrimSpace(split.Buckets[bucket])
		if body == "" {
			continue
		}
		targetPath := filepath.Join(filepath.Dir(src.Path), targetFileName(day, bucket))
		created, updated, err := writeTargetEntry(targetPath, dateTitle, body, now, dryRun)
		if err != nil {
			return out, err
		}
		if created {
			out.CreatedTargets++
		}
		if updated {
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
	out.DeletedSource = true
	return out, nil
}

func writeTargetEntry(targetPath, dateTitle, body string, now time.Time, dryRun bool) (bool, bool, error) {
	body = strings.TrimSpace(normalizeLineEndings(body))
	if body == "" {
		return false, false, nil
	}
	existingBytes, err := os.ReadFile(targetPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, false, err
	}
	if errors.Is(err, os.ErrNotExist) {
		if dryRun {
			return true, false, nil
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return false, false, err
		}
		return true, false, fsio.WriteFileAtomic(targetPath, []byte(buildMigratedNoteContent(dateTitle, body, now)), 0o644)
	}

	frontmatter, existingBody, hasFrontmatter := splitFrontmatterBlock(normalizeLineEndings(string(existingBytes)))
	mergedBody := mergeBodies(existingBody, body)
	var next string
	if hasFrontmatter {
		next = composeFrontmatterBody(frontmatter, mergedBody)
	} else {
		next = buildMigratedNoteContent(dateTitle, mergedBody, now)
	}
	if dryRun {
		return false, true, nil
	}
	return false, true, fsio.WriteFileAtomic(targetPath, []byte(next), 0o644)
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

func buildMigratedNoteContent(dateTitle, body string, now time.Time) string {
	body = strings.TrimSpace(normalizeLineEndings(body))
	fm := []string{
		"---",
		"id: " + uuid.NewString(),
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
