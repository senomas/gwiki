package web

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gwiki/internal/storage/fs"
)

type UserConfig struct {
	CompactNoteList     *bool  `json:"compact-note-list"`
	EditCommandTrigger  string `json:"edit-command-trigger"`
	EditCommandTodo     string `json:"edit-command-todo"`
	EditCommandToday    string `json:"edit-command-today"`
	EditCommandTime     string `json:"edit-command-time"`
	EditCommandDateBase string `json:"edit-command-date-base"`
}

func defaultUserConfig() UserConfig {
	val := true
	return UserConfig{
		CompactNoteList:     &val,
		EditCommandTrigger:  "!",
		EditCommandTodo:     "!",
		EditCommandToday:    "d",
		EditCommandTime:     "t",
		EditCommandDateBase: "d",
	}
}

func (c UserConfig) CompactNoteListValue() bool {
	if c.CompactNoteList == nil {
		return true
	}
	return *c.CompactNoteList
}

func (c UserConfig) EditCommandTriggerValue() string {
	if strings.TrimSpace(c.EditCommandTrigger) == "" {
		return "!"
	}
	return c.EditCommandTrigger
}

func (c UserConfig) EditCommandTodoValue() string {
	if strings.TrimSpace(c.EditCommandTodo) == "" {
		return "!"
	}
	return c.EditCommandTodo
}

func (c UserConfig) EditCommandTodayValue() string {
	if strings.TrimSpace(c.EditCommandToday) == "" {
		return "d"
	}
	return c.EditCommandToday
}

func (c UserConfig) EditCommandTimeValue() string {
	if strings.TrimSpace(c.EditCommandTime) == "" {
		return "t"
	}
	return c.EditCommandTime
}

func (c UserConfig) EditCommandDateBaseValue() string {
	if strings.TrimSpace(c.EditCommandDateBase) == "" {
		return "d"
	}
	return c.EditCommandDateBase
}

func (s *Server) userConfigPath(owner string) string {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return ""
	}
	if s.cfg.RepoPath == "" {
		return ""
	}
	notesRoot := filepath.Join(s.cfg.RepoPath, "notes")
	if info, err := os.Stat(notesRoot); err == nil && info.IsDir() {
		return filepath.Join(s.cfg.RepoPath, "config.json")
	}
	return filepath.Join(s.cfg.RepoPath, owner, "config.json")
}

func (s *Server) loadUserConfig(ctx context.Context) (UserConfig, error) {
	owner := currentUserName(ctx)
	if owner == "" {
		return defaultUserConfig(), nil
	}
	path := s.userConfigPath(owner)
	if path == "" {
		return defaultUserConfig(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return defaultUserConfig(), nil
		}
		return defaultUserConfig(), err
	}
	var cfg UserConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return defaultUserConfig(), err
	}
	return cfg, nil
}

func (s *Server) saveUserConfig(ctx context.Context, owner string, cfg UserConfig) error {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return errors.New("owner required")
	}
	path := s.userConfigPath(owner)
	if path == "" {
		return errors.New("config path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return fs.WriteFileAtomic(path, payload, 0o644)
}
