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
	"gwiki/internal/index"
	"gwiki/internal/storage/fs"
)

type signalState struct {
	Groups map[string]int64 `json:"groups"`
}

type signalGroupEntry struct {
	ID         string `json:"id"`
	InternalID string `json:"internal_id"`
	Name       string `json:"name"`
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
				Image       struct {
					ContentType string `json:"contentType"`
					Filename    string `json:"filename"`
					ID          string `json:"id"`
				} `json:"image"`
			} `json:"previews"`
		} `json:"dataMessage"`
		TypingMessage struct {
			GroupID string `json:"groupId"`
		} `json:"typingMessage"`
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
	ImageID     string
	ContentType string
	Filename    string
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
	cfg             config.Config
	server          *Server
	client          *http.Client
	state           signalState
	stateMu         *sync.Mutex
	statePath       string
	groupID         string
	groupInternalID string
}

func (p *signalPoller) tick() {
	timeout := signalHTTPTimeout(p.cfg) + 50*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	groupID := p.groupID
	if groupID == "" {
		var err error
		groupID, p.groupInternalID, err = p.resolveGroupID(ctx)
		if err != nil {
			slog.Warn("signal resolve group", "err", err)
			return
		}
		p.groupID = groupID
	}
	slog.Debug("signal poll tick", "group_id", groupID, "group_internal_id", p.groupInternalID, "owner", p.cfg.SignalOwner)
	messages, err := p.receiveMessages(ctx)
	if err != nil {
		slog.Warn("signal receive", "err", err)
		return
	}
	if len(messages) == 0 {
		slog.Debug("signal receive empty")
		return
	}
	p.stateMu.Lock()
	lastTS := p.state.Groups[groupID]
	p.stateMu.Unlock()

	slog.Debug("signal receive batch", "count", len(messages), "last_ts", lastTS)
	maxTS := lastTS
	for _, msg := range messages {
		if msg.GroupID != groupID && (p.groupInternalID == "" || msg.GroupID != p.groupInternalID) {
			slog.Debug("signal skip message", "reason", "group_mismatch", "msg_group", msg.GroupID)
			continue
		}
		if msg.Text == "" && len(msg.Previews) == 0 {
			slog.Debug("signal skip message", "reason", "empty_text")
			continue
		}
		if msg.TSMillis <= lastTS {
			slog.Debug("signal skip message", "reason", "old_timestamp", "ts", msg.TSMillis)
			continue
		}
		notePath := p.notePathForTimestamp(msg.TSMillis)
		slog.Debug("signal append", "note_path", notePath, "sender", msg.Sender, "ts", msg.TSMillis, "previews", len(msg.Previews))
		if err := p.appendMessage(ctx, notePath, msg); err != nil {
			slog.Warn("signal append message failed", "err", err)
			continue
		}
		if msg.TSMillis > maxTS {
			maxTS = msg.TSMillis
		}
	}
	if maxTS > lastTS {
		slog.Debug("signal update state", "group_id", groupID, "last_ts", maxTS)
		p.stateMu.Lock()
		p.state.Groups[groupID] = maxTS
		p.stateMu.Unlock()
		if err := p.saveState(); err != nil {
			slog.Warn("signal state save failed", "err", err)
		}
	}
}

func (p *signalPoller) resolveGroupID(ctx context.Context) (string, string, error) {
	groupName := strings.TrimSpace(p.cfg.SignalGroup)
	if groupName == "" {
		groupName = "gwiki"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/v1/groups/%s", strings.TrimRight(p.cfg.SignalURL, "/"), p.cfg.SignalNumber), nil)
	if err != nil {
		return "", "", err
	}
	resp, err := p.doRequest(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", "", fmt.Errorf("group list failed: %s", strings.TrimSpace(string(body)))
	}
	var groups []signalGroupEntry
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return "", "", err
	}
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g.Name), groupName) {
			if g.ID != "" {
				return g.ID, g.InternalID, nil
			}
		}
	}
	return "", "", fmt.Errorf("group %q not found", groupName)
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
				ImageID:     strings.TrimSpace(preview.Image.ID),
				ContentType: strings.TrimSpace(preview.Image.ContentType),
				Filename:    strings.TrimSpace(preview.Image.Filename),
			})
		}
		msg := signalMessage{
			Sender:   strings.TrimSpace(env.Envelope.Source),
			Text:     strings.TrimSpace(env.Envelope.Data.Message),
			GroupID:  strings.TrimSpace(env.Envelope.Data.GroupInfo.GroupID),
			Group:    strings.TrimSpace(env.Envelope.Data.GroupInfo.Name),
			Previews: previews,
		}
		if msg.GroupID == "" {
			msg.GroupID = strings.TrimSpace(env.Envelope.TypingMessage.GroupID)
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
	fullPath, err := fs.NoteFilePath(p.cfg.RepoPath, notePath)
	if err == nil {
		if raw, err := os.ReadFile(fullPath); err == nil {
			content = normalizeLineEndings(string(raw))
		}
	}
	frontmatter, body, noteID, err := ensureSignalFrontmatter(content, time.Now(), historyUser(ctx))
	if err != nil {
		return err
	}
	lines, err := p.buildSignalNoteLines(ctx, msg, noteID)
	if err != nil {
		return err
	}
	if len(lines) == 0 {
		return nil
	}
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	body += strings.Join(lines, "\n") + "\n"

	noteCtx := WithUser(ctx, User{Name: p.cfg.SignalOwner, Authenticated: true})
	_, apiErr := p.server.saveNoteCommon(noteCtx, saveNoteInput{
		NotePath:    notePath,
		TargetOwner: p.cfg.SignalOwner,
		Content:     body,
		Frontmatter: frontmatter,
	})
	if apiErr != nil {
		return fmt.Errorf(apiErr.message)
	}
	return nil
}

func ensureSignalFrontmatter(content string, now time.Time, user string) (string, string, string, error) {
	normalized := normalizeLineEndings(content)
	if index.HasFrontmatter(normalized) {
		fm := index.FrontmatterBlock(normalized)
		body := strings.TrimPrefix(normalized, fm)
		body = strings.TrimPrefix(body, "\n")
		meta := index.FrontmatterAttributes(normalized)
		return fm, body, meta.ID, nil
	}
	updated, err := index.EnsureFrontmatterWithTitleAndUser(normalized, now, 0, "", user)
	if err != nil {
		return "", "", "", err
	}
	fm := index.FrontmatterBlock(updated)
	body := strings.TrimPrefix(updated, fm)
	body = strings.TrimPrefix(body, "\n")
	meta := index.FrontmatterAttributes(updated)
	return fm, body, meta.ID, nil
}

func (p *signalPoller) buildSignalNoteLines(ctx context.Context, msg signalMessage, noteID string) ([]string, error) {
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
			if preview.ImageID != "" && noteID != "" {
				attachmentName, ok, err := p.ensureSignalPreviewImage(ctx, noteID, preview)
				if err != nil {
					slog.Warn("signal preview image", "err", err)
				}
				if ok {
					lines = append(lines, "", "  ![](/attachments/"+noteID+"/"+attachmentName+")")
				}
			}
			if idx < len(msg.Previews)-1 {
				lines = append(lines, "")
			}
		}
		return lines, nil
	}
	text := strings.TrimSpace(msg.Text)
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\t", " ")
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	return []string{fmt.Sprintf("- [ ] %s", text)}, nil
}

func (p *signalPoller) ensureSignalPreviewImage(ctx context.Context, noteID string, preview signalPreview) (string, bool, error) {
	attachmentID := strings.TrimSpace(preview.ImageID)
	if attachmentID == "" {
		return "", false, nil
	}
	name := sanitizeAttachmentName(preview.Filename)
	if name == "" {
		name = sanitizeAttachmentName(attachmentID)
	}
	if name == "" {
		return "", false, nil
	}
	if ext := extensionFromContentType(preview.ContentType); ext != "" && !strings.HasSuffix(strings.ToLower(name), ext) {
		name += ext
	}
	attachmentsDir := p.server.noteAttachmentsDir(p.cfg.SignalOwner, noteID)
	if err := os.MkdirAll(attachmentsDir, 0o755); err != nil {
		return "", false, err
	}
	targetPath := filepath.Join(attachmentsDir, name)
	if _, err := os.Stat(targetPath); err == nil {
		return name, true, nil
	}
	url := fmt.Sprintf("%s/v1/attachments/%s", strings.TrimRight(p.cfg.SignalURL, "/"), attachmentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	resp, err := p.doRequest(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", false, fmt.Errorf("attachment fetch failed: %s", strings.TrimSpace(string(body)))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}
	if err := os.WriteFile(targetPath, data, 0o644); err != nil {
		return "", false, err
	}
	return name, true, nil
}

func sanitizeAttachmentName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, "\\", "-")
	name = strings.ReplaceAll(name, "/", "-")
	return name
}

func extensionFromContentType(contentType string) string {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	switch contentType {
	case "image/jpeg", "image/jpg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	default:
		return ""
	}
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
