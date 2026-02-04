package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/storage/fs"
)

type signalState struct {
	Groups map[string]int64 `json:"groups"`
}

type signalGroupEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type signalEnvelope struct {
	Envelope struct {
		Source    string `json:"source"`
		Timestamp int64  `json:"timestamp"`
		Data      struct {
			Message   string `json:"message"`
			GroupInfo struct {
				GroupID string `json:"groupId"`
				Name    string `json:"name"`
			} `json:"groupInfo"`
			Previews []struct {
				URL         string `json:"url"`
				Title       string `json:"title"`
				Description string `json:"description"`
			} `json:"previews"`
		} `json:"dataMessage"`
	} `json:"envelope"`
}

type signalMessage struct {
	Sender   string
	Text     string
	GroupID  string
	Group    string
	TSMillis int64
	Previews []signalPreview
}

type signalPreview struct {
	URL         string
	Title       string
	Description string
}

func (s *Server) StartSignalPoller() {
	cfg := s.cfg
	if strings.TrimSpace(cfg.SignalURL) == "" || strings.TrimSpace(cfg.SignalNumber) == "" || strings.TrimSpace(cfg.SignalOwner) == "" {
		slog.Info("signal poller disabled")
		return
	}
	interval := cfg.SignalPoll
	if interval <= 0 {
		interval = 30 * time.Second
	}
	poller := &signalPoller{
		cfg:       cfg,
		server:    s,
		client:    &http.Client{Timeout: signalHTTPTimeout(cfg)},
		state:     signalState{Groups: map[string]int64{}},
		stateMu:   &sync.Mutex{},
		statePath: filepath.Join(cfg.DataPath, "signal-state.json"),
	}
	if err := poller.loadState(); err != nil {
		slog.Warn("signal state load failed", "err", err)
	}
	ticker := time.NewTicker(interval)
	slog.Info("signal poller enabled", "interval", interval.String(), "http_timeout", signalHTTPTimeout(cfg).String())
	go func() {
		defer ticker.Stop()
		for {
			poller.tick()
			<-ticker.C
		}
	}()
}

type signalPoller struct {
	cfg       config.Config
	server    *Server
	client    *http.Client
	state     signalState
	stateMu   *sync.Mutex
	statePath string
	groupID   string
}

func (p *signalPoller) tick() {
	timeout := signalHTTPTimeout(p.cfg) + 50*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	groupID := p.groupID
	if groupID == "" {
		var err error
		groupID, err = p.resolveGroupID(ctx)
		if err != nil {
			slog.Warn("signal resolve group", "err", err)
			return
		}
		p.groupID = groupID
	}
	messages, err := p.receiveMessages(ctx)
	if err != nil {
		slog.Warn("signal receive", "err", err)
		return
	}
	if len(messages) == 0 {
		return
	}
	p.stateMu.Lock()
	lastTS := p.state.Groups[groupID]
	p.stateMu.Unlock()

	maxTS := lastTS
	for _, msg := range messages {
		if msg.GroupID != groupID {
			continue
		}
		if msg.Text == "" {
			continue
		}
		if msg.TSMillis <= lastTS {
			continue
		}
		notePath := p.notePathForTimestamp(msg.TSMillis)
		if err := p.appendMessage(ctx, notePath, msg); err != nil {
			slog.Warn("signal append message failed", "err", err)
			continue
		}
		if msg.TSMillis > maxTS {
			maxTS = msg.TSMillis
		}
	}
	if maxTS > lastTS {
		p.stateMu.Lock()
		p.state.Groups[groupID] = maxTS
		p.stateMu.Unlock()
		if err := p.saveState(); err != nil {
			slog.Warn("signal state save failed", "err", err)
		}
	}
}

func (p *signalPoller) resolveGroupID(ctx context.Context) (string, error) {
	groupName := strings.TrimSpace(p.cfg.SignalGroup)
	if groupName == "" {
		groupName = "gwiki"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/groups/%s", strings.TrimRight(p.cfg.SignalURL, "/"), p.cfg.SignalNumber), nil)
	if err != nil {
		return "", err
	}
	resp, err := p.doRequest(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("group list failed: %s", strings.TrimSpace(string(body)))
	}
	var groups []signalGroupEntry
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return "", err
	}
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g.Name), groupName) {
			if g.ID != "" {
				return g.ID, nil
			}
		}
	}
	return "", fmt.Errorf("group %q not found", groupName)
}

func (p *signalPoller) receiveMessages(ctx context.Context) ([]signalMessage, error) {
	url := fmt.Sprintf("%s/v1/receive/%s?timeout=1&ignore_stories=true&max_messages=50", strings.TrimRight(p.cfg.SignalURL, "/"), p.cfg.SignalNumber)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("receive failed: %s", strings.TrimSpace(string(body)))
	}
	var rawItems []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&rawItems); err != nil {
		return nil, err
	}
	out := make([]signalMessage, 0, len(rawItems))
	for _, raw := range rawItems {
		msg, ok := decodeSignalMessage(raw)
		if ok {
			out = append(out, msg)
		}
	}
	return out, nil
}

func (p *signalPoller) doRequest(req *http.Request) (*http.Response, error) {
	start := time.Now()
	deadline, hasDeadline := req.Context().Deadline()
	resp, err := p.client.Do(req)
	duration := time.Since(start)
	deadlineInfo := "none"
	if hasDeadline {
		deadlineInfo = deadline.Format(time.RFC3339Nano)
	}
	timeoutInfo := "none"
	if p.client != nil {
		timeoutInfo = p.client.Timeout.String()
	}
	if err != nil {
		slog.Debug("signal http error", "method", req.Method, "url", req.URL.String(), "duration", duration.String(), "timeout", timeoutInfo, "deadline", deadlineInfo, "err", err)
		return nil, err
	}
	bodyPreview := ""
	if resp.Body != nil {
		const maxPreview = 2048
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxPreview))
		if readErr == nil {
			bodyPreview = strings.TrimSpace(string(bodyBytes))
			rest, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(append(bodyBytes, rest...)))
		}
	}
	slog.Debug("signal http", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "duration", duration.String(), "timeout", timeoutInfo, "deadline", deadlineInfo, "body", bodyPreview)
	return resp, nil
}

func decodeSignalMessage(raw json.RawMessage) (signalMessage, bool) {
	if len(raw) == 0 {
		return signalMessage{}, false
	}
	if raw[0] == '"' {
		var embedded string
		if err := json.Unmarshal(raw, &embedded); err == nil {
			if embedded == "" {
				return signalMessage{}, false
			}
			raw = []byte(embedded)
		}
	}
	var env signalEnvelope
	if err := json.Unmarshal(raw, &env); err == nil {
		previews := make([]signalPreview, 0, len(env.Envelope.Data.Previews))
		for _, preview := range env.Envelope.Data.Previews {
			url := strings.TrimSpace(preview.URL)
			title := strings.TrimSpace(preview.Title)
			desc := strings.TrimSpace(preview.Description)
			if url == "" {
				continue
			}
			previews = append(previews, signalPreview{
				URL:         url,
				Title:       title,
				Description: desc,
			})
		}
		msg := signalMessage{
			Sender:   strings.TrimSpace(env.Envelope.Source),
			Text:     strings.TrimSpace(env.Envelope.Data.Message),
			GroupID:  strings.TrimSpace(env.Envelope.Data.GroupInfo.GroupID),
			Group:    strings.TrimSpace(env.Envelope.Data.GroupInfo.Name),
			Previews: previews,
		}
		ts := env.Envelope.Timestamp
		if ts > 0 {
			msg.TSMillis = normalizeSignalTimestamp(ts)
		}
		if msg.Text != "" || msg.GroupID != "" || len(msg.Previews) > 0 {
			return msg, true
		}
	}
	return signalMessage{}, false
}

func normalizeSignalTimestamp(ts int64) int64 {
	if ts > 1_000_000_000_000 {
		return ts
	}
	return ts * 1000
}

func (p *signalPoller) notePathForTimestamp(tsMillis int64) string {
	when := time.Unix(0, tsMillis*int64(time.Millisecond))
	date := when.In(time.Local).Format("2006-01-02")
	return filepath.ToSlash(filepath.Join(p.cfg.SignalOwner, "inbox", "signal-"+date+".md"))
}

func (p *signalPoller) appendMessage(ctx context.Context, notePath string, msg signalMessage) error {
	content := ""
	if fullPath, err := fs.NoteFilePath(p.cfg.RepoPath, notePath); err == nil {
		if raw, err := os.ReadFile(fullPath); err == nil {
			content = normalizeLineEndings(string(raw))
		}
	}
	lines := buildSignalNoteLines(msg)
	if len(lines) == 0 {
		return nil
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += strings.Join(lines, "\n") + "\n"

	noteCtx := WithUser(ctx, User{Name: p.cfg.SignalOwner, Authenticated: true})
	_, apiErr := p.server.saveNoteCommon(noteCtx, saveNoteInput{
		NotePath:    notePath,
		TargetOwner: p.cfg.SignalOwner,
		Content:     content,
	})
	if apiErr != nil {
		return fmt.Errorf(apiErr.message)
	}
	return nil
}

func buildSignalNoteLines(msg signalMessage) []string {
	lines := []string{}
	if len(msg.Previews) > 0 {
		for idx, preview := range msg.Previews {
			title := preview.Title
			if title == "" {
				title = preview.URL
			}
			lines = append(lines, fmt.Sprintf("- [ ] [%s](%s)", title, preview.URL))
			if preview.Description != "" {
				lines = append(lines, "", "  "+preview.Description)
			}
			if idx < len(msg.Previews)-1 {
				lines = append(lines, "")
			}
		}
		return lines
	}
	text := strings.TrimSpace(msg.Text)
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\t", " ")
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	return []string{fmt.Sprintf("- [ ] %s", text)}
}

func (p *signalPoller) loadState() error {
	data, err := os.ReadFile(p.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var state signalState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.Groups == nil {
		state.Groups = map[string]int64{}
	}
	p.stateMu.Lock()
	p.state = state
	p.stateMu.Unlock()
	return nil
}

func (p *signalPoller) saveState() error {
	p.stateMu.Lock()
	payload, err := json.MarshalIndent(p.state, "", "  ")
	p.stateMu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.statePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p.statePath, payload, 0o644)
}

func signalHTTPTimeout(cfg config.Config) time.Duration {
	if cfg.SignalHTTPTimeout > 0 {
		return cfg.SignalHTTPTimeout
	}
	return 60 * time.Second
}
