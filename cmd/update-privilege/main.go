package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gwiki/internal/index"
)

type runOptions struct {
	Root    string
	DryRun  bool
	Verbose bool
	Out     io.Writer
	ErrOut  io.Writer
}

type runStats struct {
	Scanned int
	Matched int
	Updated int
	Skipped int
	Errors  int
}

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, out io.Writer, errOut io.Writer) int {
	fs := flag.NewFlagSet("update-privilege", flag.ContinueOnError)
	fs.SetOutput(errOut)

	var opts runOptions
	opts.Out = out
	opts.ErrOut = errOut
	fs.StringVar(&opts.Root, "root", "", "root directory to scan (defaults to $WIKI_REPO_PATH/notes or ./notes)")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "show changes without writing files")
	fs.BoolVar(&opts.Verbose, "verbose", false, "print per-file decisions")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(errOut, "usage: update-privilege [--root <path>] [--dry-run] [--verbose]\n")
		return 2
	}

	root, stats, err := execute(opts)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "ERROR: %v\n", err)
		return 1
	}

	_, _ = fmt.Fprintf(out, "root=%s scanned=%d matched=%d updated=%d skipped=%d errors=%d dry_run=%t\n",
		root, stats.Scanned, stats.Matched, stats.Updated, stats.Skipped, stats.Errors, opts.DryRun)
	if stats.Errors > 0 {
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
		repoPath := strings.TrimSpace(os.Getenv("WIKI_REPO_PATH"))
		if repoPath != "" {
			rootInput = filepath.Join(repoPath, "notes")
		} else {
			rootInput = filepath.Join(".", "notes")
		}
	}
	rootAbs, err := filepath.Abs(rootInput)
	if err != nil {
		return "", stats, fmt.Errorf("resolve root path: %w", err)
	}
	info, err := os.Stat(rootAbs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rootAbs, stats, fmt.Errorf("root path not found: %s", rootAbs)
		}
		return rootAbs, stats, fmt.Errorf("stat root path %s: %w", rootAbs, err)
	}
	if !info.IsDir() {
		return rootAbs, stats, fmt.Errorf("root path is not a directory: %s", rootAbs)
	}

	walkErr := filepath.WalkDir(rootAbs, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			stats.Errors++
			_, _ = fmt.Fprintf(errOut, "ERROR: walk %s: %v\n", path, walkErr)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}

		stats.Scanned++
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			stats.Errors++
			_, _ = fmt.Fprintf(errOut, "ERROR: read %s: %v\n", path, err)
			return nil
		}

		updated, changed, reason, err := rewritePrivateToInherited(string(contentBytes))
		if err != nil {
			stats.Errors++
			_, _ = fmt.Fprintf(errOut, "ERROR: update %s: %v\n", path, err)
			return nil
		}
		if !changed {
			stats.Skipped++
			if opts.Verbose {
				_, _ = fmt.Fprintf(out, "skip %s (%s)\n", displayPath(rootAbs, path), reason)
			}
			return nil
		}

		stats.Matched++
		if opts.DryRun {
			stats.Updated++
			_, _ = fmt.Fprintf(out, "would update %s\n", displayPath(rootAbs, path))
			return nil
		}

		mode := fs.FileMode(0o644)
		if fileInfo, statErr := os.Stat(path); statErr == nil {
			mode = fileInfo.Mode().Perm()
		}
		if err := os.WriteFile(path, []byte(updated), mode); err != nil {
			stats.Errors++
			_, _ = fmt.Fprintf(errOut, "ERROR: write %s: %v\n", path, err)
			return nil
		}
		stats.Updated++
		if opts.Verbose {
			_, _ = fmt.Fprintf(out, "updated %s\n", displayPath(rootAbs, path))
		}
		return nil
	})
	if walkErr != nil {
		return rootAbs, stats, fmt.Errorf("walk root %s: %w", rootAbs, walkErr)
	}

	return rootAbs, stats, nil
}

func rewritePrivateToInherited(content string) (string, bool, string, error) {
	attrs := index.FrontmatterAttributes(content)
	if !attrs.Has {
		return content, false, "no-frontmatter", nil
	}
	if strings.TrimSpace(strings.ToLower(attrs.Visibility)) != index.VisibilityPrivate {
		if strings.TrimSpace(attrs.Visibility) == "" {
			return content, false, "no-visibility", nil
		}
		return content, false, "visibility-" + strings.ToLower(strings.TrimSpace(attrs.Visibility)), nil
	}

	updated, err := index.SetVisibility(content, index.VisibilityInherited)
	if err != nil {
		return "", false, "", err
	}
	if updated == content {
		return content, false, "unchanged", nil
	}
	return updated, true, "", nil
}

func displayPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	if rel == "." {
		return filepath.Base(path)
	}
	return rel
}
