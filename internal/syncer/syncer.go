package syncer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var ErrSyncBusy = errors.New("sync already in progress")
var syncLock = make(chan struct{}, 1)

type Options struct {
	RepoDir            string
	LogFile            string
	CommitMessage      string
	MainBranch         string
	PushBranch         string
	HomeDir            string
	GitConfigGlobal    string
	GitCredentialsFile string
	UserName           string
	EmailDomain        string
}

func Acquire(timeout time.Duration) (func(), error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case syncLock <- struct{}{}:
		return func() { <-syncLock }, nil
	case <-timer.C:
		return nil, ErrSyncBusy
	}
}

func Run(ctx context.Context, repoPath string) (string, error) {
	return RunWithOptions(ctx, repoPath, Options{})
}

func RunWithOptions(ctx context.Context, repoPath string, opts Options) (string, error) {
	opts = resolveOptions(repoPath, opts)
	repoDir := opts.RepoDir
	logFile := opts.LogFile
	commitMessage := opts.CommitMessage
	mainBranch := opts.MainBranch
	pushBranch := opts.PushBranch
	homeDir := opts.HomeDir
	gitConfigGlobal := opts.GitConfigGlobal
	gitCredentialsFile := opts.GitCredentialsFile
	userName := strings.TrimSpace(opts.UserName)
	emailDomain := strings.TrimSpace(opts.EmailDomain)

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
	)
	if strings.TrimSpace(homeDir) != "" {
		env = append(env, "HOME="+homeDir)
	}
	if strings.TrimSpace(gitConfigGlobal) != "" {
		env = append(env, "GIT_CONFIG_GLOBAL="+gitConfigGlobal)
	}
	if strings.TrimSpace(gitCredentialsFile) != "" {
		env = append(env, "GIT_CREDENTIALS_FILE="+gitCredentialsFile)
	}

	if strings.TrimSpace(gitConfigGlobal) != "" {
		if err := os.MkdirAll(filepath.Dir(gitConfigGlobal), 0o755); err != nil {
			return "", err
		}
		if _, err := os.Stat(gitConfigGlobal); err != nil && os.IsNotExist(err) {
			file, createErr := os.OpenFile(gitConfigGlobal, os.O_CREATE|os.O_RDWR, 0o644)
			if createErr != nil {
				return "", createErr
			}
			_ = file.Close()
		}
	}
	if strings.TrimSpace(gitCredentialsFile) != "" {
		if err := os.MkdirAll(filepath.Dir(gitCredentialsFile), 0o755); err != nil {
			return "", err
		}
	}

	writeLine("auto-sync: start %s", time.Now().Format(time.RFC3339))
	if strings.TrimSpace(gitCredentialsFile) != "" {
		_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "config", "--local", "credential.helper", "store --file="+gitCredentialsFile)
	}
	if userName != "" {
		if emailDomain == "" {
			emailDomain = "gwiki.org"
		}
		if ok, _ := gitConfigLocalDefined(ctx, repoDir, env, writer, "user.name"); !ok {
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "config", "--local", "user.name", userName)
		}
		if ok, _ := gitConfigLocalDefined(ctx, repoDir, env, writer, "user.email"); !ok {
			email := fmt.Sprintf("%s@%s", userName, emailDomain)
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "config", "--local", "user.email", email)
		}
	}
	hasOrigin := gitHasOriginRemote(ctx, repoDir, env, writer)
	hasCommits := gitHasCommits(ctx, repoDir, env, writer)
	remoteMain := ""
	if hasOrigin {
		remoteMain = resolveRemoteMainBranch(ctx, repoDir, env, writer)
	}
	effectiveMain := resolveLocalMainBranch(ctx, repoDir, env, writer)
	if effectiveMain == "" {
		if remoteMain != "" {
			effectiveMain = remoteMain
		} else {
			effectiveMain = mainBranch
		}
	}
	if hasOrigin {
		if hasCommits {
			if remoteMain != "" {
				writeLine("auto-sync: fetch %s", remoteMain)
				_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "fetch", "origin", remoteMain)
			} else {
				writeLine("auto-sync: remote HEAD missing; skip fetch %s", effectiveMain)
			}
		} else {
			writeLine("auto-sync: no commits yet; skip fetch %s", effectiveMain)
		}
	}
	if hasCommits {
		_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "checkout", effectiveMain)
	} else {
		_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "checkout", "-b", effectiveMain)
	}
	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "add", "notes/")

	hasChanges, err := gitHasStagedChanges(ctx, repoDir, env, writer)
	if err != nil {
		return output.String(), err
	}
	if !hasChanges {
		if !hasCommits {
			writeLine("auto-sync: no commits yet")
		} else if hasOrigin {
			if !remoteBranchExists(ctx, repoDir, env, writer, effectiveMain) {
				writeLine("auto-sync: push %s", effectiveMain)
				_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "push", "-u", "origin", effectiveMain)
				_ = trimLogFile(logFile, 1000)
				writeLine("auto-sync: done %s", time.Now().Format(time.RFC3339))
				return output.String(), nil
			}
		}
		if hasOrigin && remoteMain != "" {
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "fetch", "origin", pushBranch)
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "push", "--force-with-lease", "origin", "HEAD:"+pushBranch)
			if _, err := runGitCommand(ctx, repoDir, env, writer, "git", "pull", "--rebase", "origin", remoteMain); err != nil {
				_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "rebase", "--abort")
				writeLine("auto-sync: rebase failed")
				_ = trimLogFile(logFile, 1000)
				return output.String(), nil
			}
			writeLine("auto-sync: push %s", remoteMain)
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "push", "origin", remoteMain)
		} else if hasOrigin && remoteMain == "" {
			writeLine("auto-sync: remote HEAD missing; skip rebase")
		} else {
			writeLine("auto-sync: no remote origin")
		}
		writeLine("auto-sync: no changes")
		_ = trimLogFile(logFile, 1000)
		return output.String(), nil
	}

	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "commit", "-m", commitMessage)
	if hasOrigin {
		if hasCommits && remoteMain != "" {
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "fetch", "origin", pushBranch)
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "push", "--force-with-lease", "origin", "HEAD:"+pushBranch)
		}

		if hasCommits && remoteMain != "" {
			if _, err := runGitCommand(ctx, repoDir, env, writer, "git", "pull", "--rebase", "origin", remoteMain); err != nil {
				_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "rebase", "--abort")
				writeLine("auto-sync: rebase failed")
				_ = trimLogFile(logFile, 1000)
				return output.String(), nil
			}
		}

		if !hasCommits {
			writeLine("auto-sync: push %s", effectiveMain)
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "push", "-u", "origin", effectiveMain)
			_ = trimLogFile(logFile, 1000)
			writeLine("auto-sync: done %s", time.Now().Format(time.RFC3339))
			return output.String(), nil
		}

		if remoteMain != "" {
			if _, err := runGitCommand(ctx, repoDir, env, writer, "git", "pull", "--rebase", "origin", remoteMain); err != nil {
				_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "rebase", "--abort")
				writeLine("auto-sync: rebase failed")
				_ = trimLogFile(logFile, 1000)
				return output.String(), nil
			}
		} else {
			writeLine("auto-sync: remote HEAD missing; skip rebase")
		}

		writeLine("auto-sync: push %s", effectiveMain)
		_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "push", "origin", effectiveMain)
	} else {
		writeLine("auto-sync: no remote origin")
	}
	_ = trimLogFile(logFile, 1000)
	writeLine("auto-sync: done %s", time.Now().Format(time.RFC3339))

	return output.String(), nil
}

func CommitOnly(ctx context.Context, repoPath string) (string, error) {
	return CommitOnlyWithOptions(ctx, repoPath, Options{})
}

func CommitOnlyWithOptions(ctx context.Context, repoPath string, opts Options) (string, error) {
	opts = resolveOptions(repoPath, opts)
	repoDir := opts.RepoDir
	logFile := opts.LogFile
	commitMessage := opts.CommitMessage
	mainBranch := opts.MainBranch
	homeDir := opts.HomeDir
	gitConfigGlobal := opts.GitConfigGlobal
	gitCredentialsFile := opts.GitCredentialsFile
	userName := strings.TrimSpace(opts.UserName)
	emailDomain := strings.TrimSpace(opts.EmailDomain)

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
	)
	if strings.TrimSpace(homeDir) != "" {
		env = append(env, "HOME="+homeDir)
	}
	if strings.TrimSpace(gitConfigGlobal) != "" {
		env = append(env, "GIT_CONFIG_GLOBAL="+gitConfigGlobal)
	}
	if strings.TrimSpace(gitCredentialsFile) != "" {
		env = append(env, "GIT_CREDENTIALS_FILE="+gitCredentialsFile)
	}

	if strings.TrimSpace(gitConfigGlobal) != "" {
		if err := os.MkdirAll(filepath.Dir(gitConfigGlobal), 0o755); err != nil {
			return "", err
		}
		if _, err := os.Stat(gitConfigGlobal); err != nil && os.IsNotExist(err) {
			file, createErr := os.OpenFile(gitConfigGlobal, os.O_CREATE|os.O_RDWR, 0o644)
			if createErr != nil {
				return "", createErr
			}
			_ = file.Close()
		}
	}
	if strings.TrimSpace(gitCredentialsFile) != "" {
		if err := os.MkdirAll(filepath.Dir(gitCredentialsFile), 0o755); err != nil {
			return "", err
		}
	}

	writeLine("auto-sync: commit-only start %s", time.Now().Format(time.RFC3339))
	if strings.TrimSpace(gitCredentialsFile) != "" {
		_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "config", "--local", "credential.helper", "store --file="+gitCredentialsFile)
	}
	if userName != "" {
		if emailDomain == "" {
			emailDomain = "gwiki.org"
		}
		if ok, _ := gitConfigLocalDefined(ctx, repoDir, env, writer, "user.name"); !ok {
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "config", "--local", "user.name", userName)
		}
		if ok, _ := gitConfigLocalDefined(ctx, repoDir, env, writer, "user.email"); !ok {
			email := fmt.Sprintf("%s@%s", userName, emailDomain)
			_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "config", "--local", "user.email", email)
		}
	}
	if strings.TrimSpace(mainBranch) != "" {
		_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "checkout", mainBranch)
	}
	_, _ = runGitCommand(ctx, repoDir, env, writer, "git", "add", "notes/")
	hasChanges, err := gitHasStagedChanges(ctx, repoDir, env, writer)
	if err != nil {
		return output.String(), err
	}
	if !hasChanges {
		writeLine("auto-sync: no changes")
		_ = trimLogFile(logFile, 1000)
		return output.String(), nil
	}
	if _, err := runGitCommand(ctx, repoDir, env, writer, "git", "commit", "-m", commitMessage); err != nil {
		_ = trimLogFile(logFile, 1000)
		return output.String(), err
	}
	_ = trimLogFile(logFile, 1000)
	writeLine("auto-sync: commit-only done %s", time.Now().Format(time.RFC3339))
	return output.String(), nil
}

func LogGraph(ctx context.Context, repoPath string, limit int) (string, error) {
	return LogGraphWithOptions(ctx, repoPath, limit, Options{})
}

func LogGraphWithOptions(ctx context.Context, repoPath string, limit int, opts Options) (string, error) {
	opts = resolveOptions(repoPath, opts)
	repoDir := opts.RepoDir
	homeDir := opts.HomeDir
	gitConfigGlobal := opts.GitConfigGlobal
	gitCredentialsFile := opts.GitCredentialsFile
	env := append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"HOME="+homeDir,
		"GIT_CONFIG_GLOBAL="+gitConfigGlobal,
		"GIT_CREDENTIALS_FILE="+gitCredentialsFile,
	)
	var output bytes.Buffer
	_, err := runGitCommand(ctx, repoDir, env, &output, "git", "log", "--graph", "--decorate", "--all", "-n", strconv.Itoa(limit))
	return output.String(), err
}

func resolveOptions(repoPath string, opts Options) Options {
	if strings.TrimSpace(opts.RepoDir) == "" {
		opts.RepoDir = strings.TrimSpace(os.Getenv("REPO_DIR"))
	}
	if strings.TrimSpace(opts.RepoDir) == "" {
		opts.RepoDir = repoPath
	}
	if strings.TrimSpace(opts.RepoDir) == "" {
		opts.RepoDir = "/notes"
	}
	if strings.TrimSpace(opts.LogFile) == "" {
		opts.LogFile = strings.TrimSpace(os.Getenv("LOG_FILE"))
	}
	if strings.TrimSpace(opts.LogFile) == "" {
		opts.LogFile = filepath.Join(opts.RepoDir, ".git", "auto-sync.log")
	}
	if strings.TrimSpace(opts.CommitMessage) == "" {
		opts.CommitMessage = strings.TrimSpace(os.Getenv("COMMIT_MESSAGE"))
	}
	if strings.TrimSpace(opts.CommitMessage) == "" {
		opts.CommitMessage = "auto: notes"
	}
	if strings.TrimSpace(opts.MainBranch) == "" {
		opts.MainBranch = strings.TrimSpace(os.Getenv("MAIN_BRANCH"))
	}
	if strings.TrimSpace(opts.MainBranch) == "" {
		opts.MainBranch = "master"
	}
	if strings.TrimSpace(opts.PushBranch) == "" {
		opts.PushBranch = strings.TrimSpace(os.Getenv("PUSH_BRANCH"))
	}
	if strings.TrimSpace(opts.PushBranch) == "" {
		opts.PushBranch = "gwiki"
	}
	if strings.TrimSpace(opts.HomeDir) == "" {
		opts.HomeDir = strings.TrimSpace(os.Getenv("HOME"))
	}
	if strings.TrimSpace(opts.HomeDir) == "" {
		opts.HomeDir = "/home/gwiki"
	}
	if strings.TrimSpace(opts.GitConfigGlobal) == "" {
		opts.GitConfigGlobal = strings.TrimSpace(os.Getenv("GIT_CONFIG_GLOBAL"))
	}
	if strings.TrimSpace(opts.GitConfigGlobal) == "" {
		opts.GitConfigGlobal = filepath.Join(opts.HomeDir, ".gitconfig")
	}
	if strings.TrimSpace(opts.GitCredentialsFile) == "" {
		opts.GitCredentialsFile = strings.TrimSpace(os.Getenv("GIT_CREDENTIALS_FILE"))
	}
	if strings.TrimSpace(opts.GitCredentialsFile) == "" {
		opts.GitCredentialsFile = filepath.Join(opts.HomeDir, ".git-credentials")
	}
	if strings.TrimSpace(opts.EmailDomain) == "" {
		opts.EmailDomain = strings.TrimSpace(os.Getenv("WIKI_EMAIL_DOMAIN"))
	}
	if strings.TrimSpace(opts.EmailDomain) == "" {
		opts.EmailDomain = strings.TrimSpace(os.Getenv("WIKI_DOMAIN"))
	}
	if strings.TrimSpace(opts.EmailDomain) == "" {
		opts.EmailDomain = "gwiki.org"
	}
	return opts
}

func gitConfigLocalDefined(ctx context.Context, dir string, env []string, writer io.Writer, key string) (bool, error) {
	writeCommand(writer, "git", "config", "--local", "--get", key)
	cmd := exec.CommandContext(ctx, "git", "config", "--local", "--get", key)
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		_, _ = writer.Write(output)
	}
	if err == nil {
		_, _ = fmt.Fprintln(writer, "-> ok")
		_, _ = fmt.Fprintln(writer)
		return strings.TrimSpace(string(output)) != "", nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		_, _ = fmt.Fprintln(writer, "-> not set")
		_, _ = fmt.Fprintln(writer)
		return false, nil
	}
	_, _ = fmt.Fprintf(writer, "-> error: %v\n", err)
	_, _ = fmt.Fprintln(writer)
	return false, err
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

func gitHasOriginRemote(ctx context.Context, dir string, env []string, writer io.Writer) bool {
	writeCommand(writer, "git", "remote", "get-url", "origin")
	cmd := exec.CommandContext(ctx, "git", "remote", "get-url", "origin")
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		_, _ = writer.Write(output)
	}
	if err != nil {
		_, _ = fmt.Fprintf(writer, "-> error: %v\n", err)
		_, _ = fmt.Fprintln(writer)
		return false
	}
	_, _ = fmt.Fprintln(writer, "-> ok")
	_, _ = fmt.Fprintln(writer)
	return true
}

func gitHasCommits(ctx context.Context, dir string, env []string, writer io.Writer) bool {
	writeCommand(writer, "git", "rev-parse", "--verify", "HEAD")
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--verify", "HEAD")
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		_, _ = writer.Write(output)
	}
	if err != nil {
		_, _ = fmt.Fprintln(writer, "-> no commits")
		_, _ = fmt.Fprintln(writer)
		return false
	}
	_, _ = fmt.Fprintln(writer, "-> ok")
	_, _ = fmt.Fprintln(writer)
	return true
}

func resolveRemoteMainBranch(ctx context.Context, dir string, env []string, writer io.Writer) string {
	writeCommand(writer, "git", "ls-remote", "--symref", "origin", "HEAD")
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--symref", "origin", "HEAD")
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		_, _ = writer.Write(output)
	}
	if err != nil {
		_, _ = fmt.Fprintf(writer, "-> error: %v\n", err)
		_, _ = fmt.Fprintln(writer)
		return ""
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ref:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ref := strings.TrimSpace(fields[1])
		if strings.HasPrefix(ref, "refs/heads/") {
			branch := strings.TrimPrefix(ref, "refs/heads/")
			if branch != "" {
				_, _ = fmt.Fprintf(writer, "-> ok (%s)\n\n", branch)
				return branch
			}
		}
	}
	_, _ = fmt.Fprintln(writer, "-> ok (no HEAD)")
	_, _ = fmt.Fprintln(writer)
	return ""
}

func resolveLocalMainBranch(ctx context.Context, dir string, env []string, writer io.Writer) string {
	if gitLocalBranchExists(ctx, dir, env, writer, "master") {
		return "master"
	}
	if gitLocalBranchExists(ctx, dir, env, writer, "main") {
		return "main"
	}
	return gitCurrentBranch(ctx, dir, env, writer)
}

func gitLocalBranchExists(ctx context.Context, dir string, env []string, writer io.Writer, branch string) bool {
	writeCommand(writer, "git", "show-ref", "--verify", "refs/heads/"+branch)
	cmd := exec.CommandContext(ctx, "git", "show-ref", "--verify", "refs/heads/"+branch)
	cmd.Dir = dir
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintln(writer, "-> missing")
		_, _ = fmt.Fprintln(writer)
		return false
	}
	_, _ = fmt.Fprintln(writer, "-> ok")
	_, _ = fmt.Fprintln(writer)
	return true
}

func gitCurrentBranch(ctx context.Context, dir string, env []string, writer io.Writer) string {
	writeCommand(writer, "git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		_, _ = writer.Write(output)
	}
	if err != nil {
		_, _ = fmt.Fprintf(writer, "-> error: %v\n", err)
		_, _ = fmt.Fprintln(writer)
		return ""
	}
	branch := strings.TrimSpace(string(output))
	if branch == "HEAD" || branch == "" {
		_, _ = fmt.Fprintln(writer, "-> detached")
		_, _ = fmt.Fprintln(writer)
		return ""
	}
	_, _ = fmt.Fprintf(writer, "-> ok (%s)\n\n", branch)
	return branch
}

func remoteBranchExists(ctx context.Context, dir string, env []string, writer io.Writer, branch string) bool {
	if strings.TrimSpace(branch) == "" {
		return false
	}
	writeCommand(writer, "git", "ls-remote", "--heads", "origin", branch)
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--heads", "origin", branch)
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		_, _ = writer.Write(output)
	}
	if err != nil {
		_, _ = fmt.Fprintf(writer, "-> error: %v\n", err)
		_, _ = fmt.Fprintln(writer)
		return false
	}
	if strings.TrimSpace(string(output)) == "" {
		_, _ = fmt.Fprintln(writer, "-> missing")
		_, _ = fmt.Fprintln(writer)
		return false
	}
	_, _ = fmt.Fprintln(writer, "-> ok")
	_, _ = fmt.Fprintln(writer)
	return true
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
