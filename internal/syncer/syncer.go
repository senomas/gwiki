package syncer

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func Run(ctx context.Context, repoPath string) (string, error) {
	repoDir := strings.TrimSpace(os.Getenv("REPO_DIR"))
	if repoDir == "" {
		repoDir = repoPath
	}
	if repoDir == "" {
		repoDir = "/notes"
	}
	logFile := strings.TrimSpace(os.Getenv("LOG_FILE"))
	if logFile == "" {
		logFile = filepath.Join(repoDir, ".git", "auto-sync.log")
	}
	commitMessage := os.Getenv("COMMIT_MESSAGE")
	if commitMessage == "" {
		commitMessage = "auto: notes"
	}
	mainBranch := os.Getenv("MAIN_BRANCH")
	if mainBranch == "" {
		mainBranch = "master"
	}
	pushBranch := os.Getenv("PUSH_BRANCH")
	if pushBranch == "" {
		pushBranch = "gwiki"
	}
	homeDir := os.Getenv("HOME")
	if homeDir == "" {
		homeDir = "/home/gwiki"
	}
	gitConfigGlobal := os.Getenv("GIT_CONFIG_GLOBAL")
	if gitConfigGlobal == "" {
		gitConfigGlobal = filepath.Join(homeDir, ".gitconfig")
	}
	gitCredentialsFile := os.Getenv("GIT_CREDENTIALS_FILE")
	if gitCredentialsFile == "" {
		gitCredentialsFile = filepath.Join(homeDir, ".git-credentials")
	}

	if _, err := os.Stat(filepath.Join(repoDir, ".git")); err != nil {
		return "", fmt.Errorf("auto-sync: no git repo in %s", repoDir)
	}

	if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
		return "", err
	}
	logHandle, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	defer logHandle.Close()

	var output bytes.Buffer
	writer := io.MultiWriter(&output, logHandle)
	writeLine := func(format string, args ...any) {
		_, _ = fmt.Fprintf(writer, format, args...)
		_, _ = fmt.Fprintln(writer)
	}

	env := append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"HOME="+homeDir,
		"GIT_CONFIG_GLOBAL="+gitConfigGlobal,
		"GIT_CREDENTIALS_FILE="+gitCredentialsFile,
	)

	writeLine("auto-sync: start %s", time.Now().Format(time.RFC3339))
	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "config", "--global", "credential.helper", "store --file="+gitCredentialsFile)
	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "checkout", mainBranch)
	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "add", "notes/")

	hasChanges, err := gitHasStagedChanges(ctx, repoDir, env, writer)
	if err != nil {
		return output.String(), err
	}
	if !hasChanges {
		if _, err := runGitCommand(ctx, repoDir, env, writer, "git", "pull", "--rebase", "origin", mainBranch); err != nil {
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "rebase", "--abort")
			writeLine("auto-sync: rebase failed")
			_ = trimLogFile(logFile, 1000)
			return output.String(), nil
		}
		writeLine("auto-sync: no changes")
		_ = trimLogFile(logFile, 1000)
		return output.String(), nil
	}

	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "commit", "-m", commitMessage)
	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "push", "--force-with-lease", "origin", "HEAD:"+pushBranch)

	if _, err := runGitCommand(ctx, repoDir, env, writer, "git", "pull", "--rebase", "origin", mainBranch); err != nil {
		_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "rebase", "--abort")
		writeLine("auto-sync: rebase failed")
		_ = trimLogFile(logFile, 1000)
		return output.String(), nil
	}

	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "push", "origin", mainBranch)
	_ = trimLogFile(logFile, 1000)
	writeLine("auto-sync: done %s", time.Now().Format(time.RFC3339))

	return output.String(), nil
}

func gitHasStagedChanges(ctx context.Context, dir string, env []string, writer io.Writer) (bool, error) {
	writeCommand(writer, "git", "diff", "--cached", "--quiet")
	cmd := exec.CommandContext(ctx, "git", "diff", "--cached", "--quiet")
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		_, _ = writer.Write(output)
	}
	if err == nil {
		_, _ = fmt.Fprintln(writer, "-> ok (no changes)")
		_, _ = fmt.Fprintln(writer)
		return false, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() == 1 {
			_, _ = fmt.Fprintln(writer, "-> changes staged")
			_, _ = fmt.Fprintln(writer)
			return true, nil
		}
	}
	_, _ = fmt.Fprintf(writer, "-> error: %v\n", err)
	_, _ = fmt.Fprintln(writer)
	return false, err
}

func runGitCommand(ctx context.Context, dir string, env []string, writer io.Writer, name string, args ...string) (string, error) {
	writeCommand(writer, name, args...)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		_, _ = writer.Write(output)
	}
	if err != nil {
		_, _ = fmt.Fprintf(writer, "-> error: %v\n", err)
	} else {
		_, _ = fmt.Fprintln(writer, "-> ok")
	}
	_, _ = fmt.Fprintln(writer)
	return string(output), err
}

func writeCommand(writer io.Writer, name string, args ...string) {
	cmd := append([]string{name}, args...)
	_, _ = fmt.Fprintf(writer, "\n$ %s\n", strings.Join(cmd, " "))
}

func trimLogFile(path string, maxLines int) error {
	if maxLines <= 0 {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	type line struct {
		value string
	}
	lines := make([]line, 0, maxLines)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if len(lines) == maxLines {
			copy(lines, lines[1:])
			lines[maxLines-1] = line{value: scanner.Text()}
			continue
		}
		lines = append(lines, line{value: scanner.Text()})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	for _, item := range lines {
		if _, err := fmt.Fprintln(tmp, item.value); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
