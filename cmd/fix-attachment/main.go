package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gwiki/internal/index"

	"golang.org/x/term"
)

type runOptions struct {
	RepoRoot string
	Verbose  bool
	Fix      bool
	Yes      bool
	Out      io.Writer
	ErrOut   io.Writer
}

type runStats struct {
	NotesScanned    int
	AttachmentRefs  int
	InvalidRefs     int
	NotesMissingID  int
	UnreadableNotes int
	WalkErrors      int
}

type fixStats struct {
	Candidates int
	FixedRefs  int
	Copied     int
	Notes      int
	Errors     int
}

type noteRecord struct {
	Owner       string
	AbsPath     string
	DisplayPath string
	Title       string
	ID          string
	Content     string
}

type attachmentRef struct {
	start  int
	end    int
	prefix string
	raw    string
	noteID string
	rel    string
	lineNo int
}

type finding struct {
	NotePath  string
	NoteAbs   string
	Owner     string
	NoteID    string
	NoteTitle string
	LineNo    int
	RefRaw    string
	RefNote   string
	RefRel    string
	RefPref   string
	RefStart  int
	RefEnd    int
	RefOwners []string
	SrcOwner  string
	SrcTitle  string
	SrcPath   string
	Reason    string
}

type replaceEntry struct {
	start int
	end   int
	text  string
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("fix-attachment", flag.ContinueOnError)
	fs.SetOutput(errOut)

	opts := runOptions{
		Out:    out,
		ErrOut: errOut,
	}
	fs.StringVar(&opts.RepoRoot, "repo", "", "wiki repository root (defaults to $WIKI_REPO_PATH or current directory)")
	fs.BoolVar(&opts.Verbose, "verbose", false, "print per-note scanning progress")
	fs.BoolVar(&opts.Fix, "fix", false, "copy owner-mismatched attachments into current note owner/id and rewrite links")
	fs.BoolVar(&opts.Yes, "yes", false, "auto-confirm fix operation (use with --fix)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(errOut, "usage: fix-attachment [--repo <path>] [--verbose] [--fix] [--yes]")
		return 2
	}
	if opts.Yes && !opts.Fix {
		_, _ = fmt.Fprintln(errOut, "ERROR: --yes requires --fix")
		return 2
	}

	repoRoot, stats, findings, err := execute(opts)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	var fstats fixStats
	if opts.Fix {
		candidates := buildFixCandidates(findings)
		fstats.Candidates = len(candidates)
		if len(candidates) > 0 {
			fstats, err = applyOwnerFixes(repoRoot, candidates, opts.Yes, out, errOut)
			if err != nil {
				_, _ = fmt.Fprintf(errOut, "ERROR: apply fixes: %v\n", err)
				return 1
			}
			repoRoot, stats, findings, err = execute(runOptions{
				RepoRoot: repoRoot,
				Verbose:  opts.Verbose,
				Out:      out,
				ErrOut:   errOut,
			})
			if err != nil {
				_, _ = fmt.Fprintf(errOut, "ERROR: %v\n", err)
				return 1
			}
		}
	}

	printFindingsReport(out, repoRoot, stats, findings)
	if opts.Fix {
		_, _ = fmt.Fprintf(out, "\nFix summary:\n")
		_, _ = fmt.Fprintf(out, "  candidates : %d\n", fstats.Candidates)
		_, _ = fmt.Fprintf(out, "  fixed refs : %d\n", fstats.FixedRefs)
		_, _ = fmt.Fprintf(out, "  copied     : %d\n", fstats.Copied)
		_, _ = fmt.Fprintf(out, "  notes      : %d\n", fstats.Notes)
		_, _ = fmt.Fprintf(out, "  fix errors : %d\n", fstats.Errors)
		_, _ = fmt.Fprintf(out, "fix candidates=%d fixed=%d copied=%d notes=%d fix_errors=%d\n",
			fstats.Candidates, fstats.FixedRefs, fstats.Copied, fstats.Notes, fstats.Errors)
	}

	if stats.InvalidRefs > 0 || stats.UnreadableNotes > 0 || stats.WalkErrors > 0 || fstats.Errors > 0 {
		return 1
	}
	return 0
}

func execute(opts runOptions) (string, runStats, []finding, error) {
	var stats runStats
	var findings []finding

	out := opts.Out
	errOut := opts.ErrOut
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}

	repoRoot := strings.TrimSpace(opts.RepoRoot)
	if repoRoot == "" {
		repoRoot = strings.TrimSpace(os.Getenv("WIKI_REPO_PATH"))
	}
	if repoRoot == "" {
		repoRoot = "."
	}
	repoAbs, err := filepath.Abs(repoRoot)
	if err != nil {
		return "", stats, nil, fmt.Errorf("resolve repo root: %w", err)
	}
	info, err := os.Stat(repoAbs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return repoAbs, stats, nil, fmt.Errorf("repo root not found: %s", repoAbs)
		}
		return repoAbs, stats, nil, fmt.Errorf("stat repo root %s: %w", repoAbs, err)
	}
	if !info.IsDir() {
		return repoAbs, stats, nil, fmt.Errorf("repo root is not a directory: %s", repoAbs)
	}

	notes, idOwners, scanStats := scanNotes(repoAbs, opts.Verbose, out, errOut)
	stats = scanStats
	noteByOwnerAndID := make(map[string]noteRecord, len(notes))
	for _, note := range notes {
		if note.ID == "" {
			continue
		}
		noteByOwnerAndID[ownerIDKey(note.Owner, note.ID)] = note
	}

	for _, note := range notes {
		refs := scanAttachmentRefs(note.Content)
		stats.AttachmentRefs += len(refs)
		for _, ref := range refs {
			reasons := make([]string, 0, 3)

			if note.ID == "" {
				reasons = append(reasons, "current-note-missing-id")
			} else if ref.noteID != note.ID {
				reasons = append(reasons, fmt.Sprintf("note-id-mismatch(current=%s,ref=%s)", note.ID, ref.noteID))
			}

			owners := idOwners[ref.noteID]
			sourceOwner := ""
			sourceTitle := ""
			sourcePath := ""
			if len(owners) == 1 {
				sourceOwner = owners[0]
				if src, ok := noteByOwnerAndID[ownerIDKey(sourceOwner, ref.noteID)]; ok {
					sourceTitle = src.Title
					sourcePath = src.DisplayPath
				}
			}
			switch len(owners) {
			case 0:
				reasons = append(reasons, fmt.Sprintf("unknown-note-id(%s)", ref.noteID))
			case 1:
				if owners[0] != note.Owner {
					reasons = append(reasons, fmt.Sprintf("owner-mismatch(current=%s,ref=%s)", note.Owner, owners[0]))
				}
			default:
				reasons = append(reasons, fmt.Sprintf("ambiguous-note-id(%s=>%s)", ref.noteID, strings.Join(owners, ",")))
			}

			if len(reasons) == 0 {
				continue
			}
			stats.InvalidRefs++
			ownersCopy := append([]string(nil), owners...)
			findings = append(findings, finding{
				NotePath:  note.DisplayPath,
				NoteAbs:   note.AbsPath,
				Owner:     note.Owner,
				NoteID:    note.ID,
				NoteTitle: note.Title,
				LineNo:    ref.lineNo,
				RefRaw:    ref.raw,
				RefNote:   ref.noteID,
				RefRel:    ref.rel,
				RefPref:   ref.prefix,
				RefStart:  ref.start,
				RefEnd:    ref.end,
				RefOwners: ownersCopy,
				SrcOwner:  sourceOwner,
				SrcTitle:  sourceTitle,
				SrcPath:   sourcePath,
				Reason:    strings.Join(reasons, "; "),
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].NotePath != findings[j].NotePath {
			return findings[i].NotePath < findings[j].NotePath
		}
		if findings[i].LineNo != findings[j].LineNo {
			return findings[i].LineNo < findings[j].LineNo
		}
		if findings[i].RefRaw != findings[j].RefRaw {
			return findings[i].RefRaw < findings[j].RefRaw
		}
		return findings[i].Reason < findings[j].Reason
	})

	return repoAbs, stats, findings, nil
}

func scanNotes(repoRoot string, verbose bool, out io.Writer, errOut io.Writer) ([]noteRecord, map[string][]string, runStats) {
	var stats runStats
	notes := make([]noteRecord, 0, 128)
	idOwnerSet := map[string]map[string]struct{}{}

	ownerEntries, err := os.ReadDir(repoRoot)
	if err != nil {
		stats.WalkErrors++
		_, _ = fmt.Fprintf(errOut, "ERROR: list repo root %s: %v\n", repoRoot, err)
		return notes, map[string][]string{}, stats
	}
	sort.Slice(ownerEntries, func(i, j int) bool {
		return ownerEntries[i].Name() < ownerEntries[j].Name()
	})

	for _, ownerEntry := range ownerEntries {
		if !ownerEntry.IsDir() {
			continue
		}
		owner := strings.TrimSpace(ownerEntry.Name())
		if owner == "" || strings.HasPrefix(owner, ".") {
			continue
		}

		notesRoot := filepath.Join(repoRoot, owner, "notes")
		if info, err := os.Stat(notesRoot); err != nil || !info.IsDir() {
			continue
		}

		walkErr := filepath.WalkDir(notesRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				stats.WalkErrors++
				_, _ = fmt.Fprintf(errOut, "ERROR: walk %s: %v\n", path, walkErr)
				return nil
			}
			if d.IsDir() {
				if d.Name() == "attachments" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.EqualFold(filepath.Ext(d.Name()), ".md") {
				return nil
			}

			contentBytes, err := os.ReadFile(path)
			if err != nil {
				stats.UnreadableNotes++
				_, _ = fmt.Fprintf(errOut, "ERROR: read %s: %v\n", path, err)
				return nil
			}
			content := string(contentBytes)
			attrs := index.FrontmatterAttributes(content)
			meta := index.ParseContent(content)
			noteID := strings.TrimSpace(attrs.ID)
			title := strings.TrimSpace(meta.Title)
			if title == "" {
				base := filepath.Base(path)
				title = strings.TrimSuffix(base, filepath.Ext(base))
			}
			if noteID == "" {
				stats.NotesMissingID++
			}

			rel, relErr := filepath.Rel(repoRoot, path)
			displayPath := path
			if relErr == nil {
				displayPath = filepath.ToSlash(rel)
			}

			if verbose {
				if noteID == "" {
					_, _ = fmt.Fprintf(out, "scan %s (missing id)\n", displayPath)
				} else {
					_, _ = fmt.Fprintf(out, "scan %s (id=%s)\n", displayPath, noteID)
				}
			}

			notes = append(notes, noteRecord{
				Owner:       owner,
				AbsPath:     path,
				DisplayPath: displayPath,
				Title:       title,
				ID:          noteID,
				Content:     content,
			})
			stats.NotesScanned++

			if noteID != "" {
				if _, ok := idOwnerSet[noteID]; !ok {
					idOwnerSet[noteID] = map[string]struct{}{}
				}
				idOwnerSet[noteID][owner] = struct{}{}
			}

			return nil
		})
		if walkErr != nil {
			stats.WalkErrors++
			_, _ = fmt.Fprintf(errOut, "ERROR: walk notes root %s: %v\n", notesRoot, walkErr)
		}
	}

	idOwners := make(map[string][]string, len(idOwnerSet))
	for noteID, ownersSet := range idOwnerSet {
		owners := make([]string, 0, len(ownersSet))
		for owner := range ownersSet {
			owners = append(owners, owner)
		}
		sort.Strings(owners)
		idOwners[noteID] = owners
	}

	sort.Slice(notes, func(i, j int) bool {
		return notes[i].DisplayPath < notes[j].DisplayPath
	})

	return notes, idOwners, stats
}

func scanAttachmentRefs(content string) []attachmentRef {
	refs := make([]attachmentRef, 0, 8)
	seen := map[[2]int]struct{}{}
	prefixes := []string{"/attachments/", "attachments/"}
	delims := func(r byte) bool {
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
			if prefix == "attachments/" && start > 0 && content[start-1] == '/' {
				offset = start + len(prefix)
				continue
			}
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
			for pathEnd < len(content) && !delims(content[pathEnd]) {
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

			key := [2]int{start, pathEnd}
			if _, ok := seen[key]; ok {
				offset = pathEnd
				continue
			}
			seen[key] = struct{}{}

			raw := content[start:pathEnd]
			lineNo := 1 + strings.Count(content[:start], "\n")
			refs = append(refs, attachmentRef{
				start:  start,
				end:    pathEnd,
				prefix: prefix,
				raw:    raw,
				noteID: noteID,
				rel:    rel,
				lineNo: lineNo,
			})
			offset = pathEnd
		}
	}

	return refs
}

func buildFixCandidates(findings []finding) []finding {
	candidates := make([]finding, 0, len(findings))
	for _, f := range findings {
		if f.NoteID == "" || f.RefNote == "" || f.RefRel == "" {
			continue
		}
		if len(f.RefOwners) != 1 {
			continue
		}
		if f.RefOwners[0] == f.Owner {
			continue
		}
		candidates = append(candidates, f)
	}
	return candidates
}

func promptYesNo(prompt string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, fmt.Errorf("stdin is not a terminal (use --yes to auto-confirm)")
	}
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("read response: %w", err)
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes", nil
}

func applyOwnerFixes(repoRoot string, candidates []finding, autoYes bool, out io.Writer, errOut io.Writer) (fixStats, error) {
	stats := fixStats{Candidates: len(candidates)}

	byNote := map[string][]finding{}
	for _, c := range candidates {
		byNote[c.NoteAbs] = append(byNote[c.NoteAbs], c)
	}

	notePaths := make([]string, 0, len(byNote))
	for p := range byNote {
		notePaths = append(notePaths, p)
	}
	sort.Strings(notePaths)

	copiedMap := map[string]string{}
	for _, noteAbs := range notePaths {
		items := byNote[noteAbs]
		raw, err := os.ReadFile(noteAbs)
		if err != nil {
			stats.Errors += len(items)
			_, _ = fmt.Fprintf(errOut, "ERROR: read note %s: %v\n", noteAbs, err)
			continue
		}
		content := string(raw)
		refs := scanAttachmentRefs(content)

		candByKey := map[string][]finding{}
		for _, c := range items {
			key := fmt.Sprintf("%d|%s", c.LineNo, c.RefRaw)
			candByKey[key] = append(candByKey[key], c)
		}

		repls := make([]replaceEntry, 0, len(items))
		for _, ref := range refs {
			key := fmt.Sprintf("%d|%s", ref.lineNo, ref.raw)
			queue := candByKey[key]
			if len(queue) == 0 {
				continue
			}
			c := queue[0]
			candByKey[key] = queue[1:]
			newRawPreview := c.RefPref + c.NoteID + "/" + c.RefRel
			if !autoYes {
				ok, err := promptCopyFix(c, newRawPreview, errOut)
				if err != nil {
					return stats, err
				}
				if !ok {
					_, _ = fmt.Fprintf(out, "skip %s:%d %q\n", c.NotePath, c.LineNo, c.RefRaw)
					continue
				}
			}

			srcOwner := c.RefOwners[0]
			srcPath := filepath.Join(repoRoot, srcOwner, "notes", "attachments", c.RefNote, filepath.FromSlash(c.RefRel))
			dstRoot := filepath.Join(repoRoot, c.Owner, "notes", "attachments", c.NoteID)
			cacheKey := srcPath + "=>" + dstRoot

			if _, statErr := os.Stat(srcPath); statErr != nil {
				if os.IsNotExist(statErr) {
					restored, commitHash, restoreErr := restoreAttachmentFromGit(repoRoot, srcOwner, c.RefNote, c.RefRel)
					if restoreErr != nil {
						stats.Errors++
						_, _ = fmt.Fprintf(errOut, "ERROR: restore %s from git failed: %v\n", c.RefRaw, restoreErr)
						continue
					}
					if !restored {
						stats.Errors++
						_, _ = fmt.Fprintf(errOut, "ERROR: source attachment missing and not found in git history: %s\n", c.RefRaw)
						continue
					}
					_, _ = fmt.Fprintf(out, "restored source from git: [%s] %s (commit %s)\n", srcOwner, c.RefRel, shortHash(commitHash))
				} else {
					stats.Errors++
					_, _ = fmt.Fprintf(errOut, "ERROR: stat source %s: %v\n", c.RefRaw, statErr)
					continue
				}
			}

			dstRel, copied, err := ensureCopiedAttachment(srcPath, dstRoot, c.RefRel, copiedMap, cacheKey)
			if err != nil {
				stats.Errors++
				_, _ = fmt.Fprintf(errOut, "ERROR: copy %s -> owner=%s note=%s: %v\n", c.RefRaw, c.Owner, c.NoteID, err)
				continue
			}
			if copied {
				stats.Copied++
			}

			newRaw := c.RefPref + c.NoteID + "/" + dstRel
			repls = append(repls, replaceEntry{
				start: ref.start,
				end:   ref.end,
				text:  newRaw,
			})
			stats.FixedRefs++
			_, _ = fmt.Fprintf(out, "fixed %s:%d %q -> %q\n", c.NotePath, c.LineNo, c.RefRaw, newRaw)
		}

		if len(repls) == 0 {
			continue
		}
		sort.Slice(repls, func(i, j int) bool {
			return repls[i].start > repls[j].start
		})
		updated := content
		for _, r := range repls {
			updated = updated[:r.start] + r.text + updated[r.end:]
		}
		if updated == content {
			continue
		}
		if err := os.WriteFile(noteAbs, []byte(updated), 0o644); err != nil {
			stats.Errors++
			_, _ = fmt.Fprintf(errOut, "ERROR: write note %s: %v\n", noteAbs, err)
			continue
		}
		stats.Notes++
	}

	return stats, nil
}

func ensureCopiedAttachment(srcPath, dstRoot, rel string, copiedMap map[string]string, cacheKey string) (string, bool, error) {
	if dstRel, ok := copiedMap[cacheKey]; ok {
		return dstRel, false, nil
	}

	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		return "", false, err
	}

	candidate := filepath.ToSlash(strings.TrimPrefix(path.Clean(rel), "/"))
	if candidate == "" || candidate == "." || strings.HasPrefix(candidate, "..") {
		return "", false, fmt.Errorf("invalid relative attachment path: %q", rel)
	}

	copied := false
	for i := 1; i < 1000; i++ {
		dstRel := candidate
		if i > 1 {
			ext := path.Ext(candidate)
			base := strings.TrimSuffix(candidate, ext)
			dstRel = fmt.Sprintf("%s-%d%s", base, i, ext)
		}
		dstPath := filepath.Join(dstRoot, filepath.FromSlash(dstRel))
		existing, readErr := os.ReadFile(dstPath)
		if readErr == nil {
			if bytes.Equal(existing, srcData) {
				copiedMap[cacheKey] = dstRel
				return dstRel, copied, nil
			}
			continue
		}
		if !os.IsNotExist(readErr) {
			return "", copied, readErr
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return "", copied, err
		}
		if err := os.WriteFile(dstPath, srcData, 0o644); err != nil {
			return "", copied, err
		}
		copied = true
		copiedMap[cacheKey] = dstRel
		return dstRel, copied, nil
	}
	return "", copied, fmt.Errorf("unable to place attachment after many attempts")
}

func restoreAttachmentFromGit(repoRoot, owner, noteID, rel string) (bool, string, error) {
	repoDir := filepath.Join(repoRoot, owner)
	gitPath := filepath.ToSlash(filepath.Join("notes", "attachments", noteID, rel))

	revListOut, err := exec.Command("git", "-C", repoDir, "rev-list", "HEAD", "--", gitPath).Output()
	if err != nil {
		return false, "", fmt.Errorf("git rev-list: %w", err)
	}
	commits := strings.Fields(string(revListOut))
	if len(commits) == 0 {
		return false, "", nil
	}

	var commitWithBlob string
	var data []byte
	for _, commit := range commits {
		object := commit + ":" + gitPath
		if err := exec.Command("git", "-C", repoDir, "cat-file", "-e", object).Run(); err != nil {
			continue
		}
		out, err := exec.Command("git", "-C", repoDir, "show", object).Output()
		if err != nil {
			continue
		}
		commitWithBlob = commit
		data = out
		break
	}
	if commitWithBlob == "" {
		return false, "", nil
	}

	dstPath := filepath.Join(repoDir, filepath.FromSlash(gitPath))
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return false, "", err
	}
	if err := os.WriteFile(dstPath, data, 0o644); err != nil {
		return false, "", err
	}
	return true, commitWithBlob, nil
}

func ownerIDKey(owner, noteID string) string {
	return owner + "::" + noteID
}

func displayTitle(title, path string) string {
	title = strings.TrimSpace(title)
	if title != "" {
		return title
	}
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func printFindingsReport(out io.Writer, repoRoot string, stats runStats, findings []finding) {
	_, _ = fmt.Fprintf(out, "Scan report: %s\n", repoRoot)
	_, _ = fmt.Fprintf(out, "  notes scanned      : %d\n", stats.NotesScanned)
	_, _ = fmt.Fprintf(out, "  attachment refs    : %d\n", stats.AttachmentRefs)
	_, _ = fmt.Fprintf(out, "  invalid refs       : %d\n", stats.InvalidRefs)
	_, _ = fmt.Fprintf(out, "  notes missing id   : %d\n", stats.NotesMissingID)
	_, _ = fmt.Fprintf(out, "  unreadable notes   : %d\n", stats.UnreadableNotes)
	_, _ = fmt.Fprintf(out, "  walk errors        : %d\n", stats.WalkErrors)

	if len(findings) == 0 {
		_, _ = fmt.Fprintln(out, "\nNo invalid attachment links found.")
		_, _ = fmt.Fprintf(out, "repo=%s notes=%d refs=%d invalid=%d missing_note_id=%d unreadable=%d walk_errors=%d\n",
			repoRoot, stats.NotesScanned, stats.AttachmentRefs, stats.InvalidRefs, stats.NotesMissingID, stats.UnreadableNotes, stats.WalkErrors)
		return
	}

	_, _ = fmt.Fprintf(out, "\nInvalid attachment links (%d):\n", len(findings))
	for i, f := range findings {
		srcOwner := strings.TrimSpace(f.SrcOwner)
		srcTitle := strings.TrimSpace(f.SrcTitle)
		if srcOwner == "" && len(f.RefOwners) == 1 {
			srcOwner = f.RefOwners[0]
		}
		if srcTitle == "" {
			srcTitle = f.RefNote
		}
		_, _ = fmt.Fprintf(out, "%d) [%s] %s\n", i+1, f.Owner, displayTitle(f.NoteTitle, f.NotePath))
		_, _ = fmt.Fprintf(out, "   note   : %s:%d\n", f.NotePath, f.LineNo)
		_, _ = fmt.Fprintf(out, "   link   : %s\n", f.RefRaw)
		if srcOwner != "" {
			_, _ = fmt.Fprintf(out, "   source : [%s] %s (id=%s)\n", srcOwner, srcTitle, f.RefNote)
		} else {
			_, _ = fmt.Fprintf(out, "   source : id=%s\n", f.RefNote)
		}
		_, _ = fmt.Fprintf(out, "   reason : %s\n", f.Reason)
	}

	_, _ = fmt.Fprintf(out, "repo=%s notes=%d refs=%d invalid=%d missing_note_id=%d unreadable=%d walk_errors=%d\n",
		repoRoot, stats.NotesScanned, stats.AttachmentRefs, stats.InvalidRefs, stats.NotesMissingID, stats.UnreadableNotes, stats.WalkErrors)
}

func promptCopyFix(c finding, newRaw string, errOut io.Writer) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, fmt.Errorf("stdin is not a terminal (use --yes to auto-confirm)")
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	srcOwner := c.SrcOwner
	if srcOwner == "" && len(c.RefOwners) == 1 {
		srcOwner = c.RefOwners[0]
	}
	srcTitle := displayTitle(c.SrcTitle, c.SrcPath)
	dstTitle := displayTitle(c.NoteTitle, c.NotePath)

	_, _ = fmt.Fprintf(errOut, "\nCopy attachment reference?\n")
	_, _ = fmt.Fprintf(errOut, "  from   : [%s] %s (id=%s)\n", srcOwner, srcTitle, c.RefNote)
	if c.SrcPath != "" {
		_, _ = fmt.Fprintf(errOut, "           %s\n", c.SrcPath)
	}
	_, _ = fmt.Fprintf(errOut, "  to     : [%s] %s (id=%s)\n", c.Owner, dstTitle, c.NoteID)
	_, _ = fmt.Fprintf(errOut, "           %s:%d\n", c.NotePath, c.LineNo)
	_, _ = fmt.Fprintf(errOut, "  file   : %s\n", c.RefRel)
	_, _ = fmt.Fprintf(errOut, "  rewrite: %s -> %s\n", c.RefRaw, newRaw)

	return promptYesNo("Proceed? [y/N]: ")
}

func shortHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
