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
			Attachments []struct {
				ContentType string `json:"contentType"`
				Filename    string `json:"filename"`
				ID          string `json:"id"`
			} `json:"attachments"`
		} `json:"dataMessage"`
		TypingMessage struct {
			GroupID string `json:"groupId"`
		} `json:"typingMessage"`
	} `json:"envelope"`
}

type signalMessage struct {
	Sender      string
	Text        string
	GroupID     string
	Group       string
	TSMillis    int64
	Previews    []signalPreview
	Attachments []signalAttachment
	RawJSON     string
}

type signalPreview struct {
	URL         string
	Title       string
	Description string
	ImageID     string
	ContentType string
	Filename    string
}

type signalAttachment struct {
	ID          string
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
		if msg.Text == "" && len(msg.Previews) == 0 && len(msg.Attachments) == 0 {
			slog.Debug("signal skip message", "reason", "empty_text")
			continue
		}
		if msg.TSMillis <= lastTS {
			slog.Debug("signal skip message", "reason", "old_timestamp", "ts", msg.TSMillis)
			continue
		}
		p.writeSignalDebugMessage(msg)
		if signalDebugEnabled() && msg.RawJSON != "" {
			slog.Debug("signal message raw", "ts", msg.TSMillis, "raw_json", msg.RawJSON)
		}
		notePath := p.notePathForTimestamp(msg.TSMillis)
		slog.Debug("signal append", "note_path", notePath, "sender", msg.Sender, "ts", msg.TSMillis, "previews", len(msg.Previews), "attachments", len(msg.Attachments))
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

func signalDebugLogDir() string {
	logPath := strings.TrimSpace(os.Getenv("WIKI_DEV_LOG_FILE"))
	if logPath == "" {
		logPath = "dev.log"
	}
	dir := filepath.Dir(logPath)
	if strings.TrimSpace(dir) == "" {
		return "."
	}
	return dir
}

func signalDebugEnabled() bool {
	return strings.TrimSpace(os.Getenv("DEV")) != ""
}

func (p *signalPoller) writeSignalDebugMessage(msg signalMessage) {
	if !signalDebugEnabled() {
		return
	}
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}
	dir := signalDebugLogDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		slog.Warn("signal debug create dir failed", "dir", dir, "err", err)
		return
	}

	timestamp := time.Now()
	if msg.TSMillis > 0 {
		timestamp = time.UnixMilli(msg.TSMillis)
	}
	baseName := fmt.Sprintf("signal-%s", timestamp.Format("060102150405"))
	var (
		file *os.File
		path string
	)
	for i := 0; i < 1000; i++ {
		name := baseName + ".json"
		if i > 0 {
			name = fmt.Sprintf("%s-%d.json", baseName, i+1)
		}
		candidate := filepath.Join(dir, name)
		created, err := os.OpenFile(candidate, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			slog.Warn("signal debug open failed", "path", candidate, "err", err)
			return
		}
		file = created
		path = candidate
		break
	}
	if file == nil {
		slog.Warn("signal debug file create failed", "base", baseName)
		return
	}
	defer file.Close()

	dump := map[string]any{
		"timestamp": timestamp.Format(time.RFC3339Nano),
	}
	if msg.Group != "" {
		dump["group"] = msg.Group
	}
	if msg.GroupID != "" {
		dump["group_id"] = msg.GroupID
	}
	if msg.Sender != "" {
		dump["sender"] = msg.Sender
	}
	if len(msg.Previews) > 0 {
		dump["previews"] = len(msg.Previews)
	}
	if len(msg.Attachments) > 0 {
		dump["attachments"] = len(msg.Attachments)
	}
	dump["text"] = text
	if msg.RawJSON != "" {
		var raw any
		if err := json.Unmarshal([]byte(msg.RawJSON), &raw); err == nil {
			dump["raw"] = raw
		} else {
			dump["raw_text"] = msg.RawJSON
		}
	}
	pretty, err := json.MarshalIndent(dump, "", "  ")
	if err != nil {
		slog.Warn("signal debug marshal failed", "path", path, "err", err)
		return
	}
	pretty = append(pretty, '\n')

	if _, err := file.Write(pretty); err != nil {
		slog.Warn("signal debug write failed", "path", path, "err", err)
		return
	}
	displayPath := path
	if absPath, err := filepath.Abs(path); err == nil {
		displayPath = absPath
	}
	slog.Debug("signal debug dump written", "path", displayPath, "bytes", len(pretty))
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
	if signalDebugEnabled() && resp.Body != nil {
		const maxPreview = 2048
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxPreview))
		if readErr == nil {
			bodyPreview = strings.TrimSpace(string(bodyBytes))
			rest, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(append(bodyBytes, rest...)))
		}
	}
	if signalDebugEnabled() {
		slog.Debug("signal http", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "duration", duration.String(), "timeout", timeoutInfo, "deadline", deadlineInfo, "body", bodyPreview)
	} else {
		slog.Debug("signal http", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "duration", duration.String(), "timeout", timeoutInfo, "deadline", deadlineInfo)
	}
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
			imageID := strings.TrimSpace(preview.Image.ID)
			if url == "" && imageID == "" {
				continue
			}
			previews = append(previews, signalPreview{
				URL:         url,
				Title:       title,
				Description: desc,
				ImageID:     imageID,
				ContentType: strings.TrimSpace(preview.Image.ContentType),
				Filename:    strings.TrimSpace(preview.Image.Filename),
			})
		}
		attachments := make([]signalAttachment, 0, len(env.Envelope.Data.Attachments))
		for _, attachment := range env.Envelope.Data.Attachments {
			attachmentID := strings.TrimSpace(attachment.ID)
			if attachmentID == "" {
				continue
			}
			attachments = append(attachments, signalAttachment{
				ID:          attachmentID,
				ContentType: strings.TrimSpace(attachment.ContentType),
				Filename:    strings.TrimSpace(attachment.Filename),
			})
		}
		msg := signalMessage{
			Sender:      strings.TrimSpace(env.Envelope.Source),
			Text:        strings.TrimSpace(env.Envelope.Data.Message),
			GroupID:     strings.TrimSpace(env.Envelope.Data.GroupInfo.GroupID),
			Group:       strings.TrimSpace(env.Envelope.Data.GroupInfo.Name),
			Previews:    previews,
			Attachments: attachments,
			RawJSON:     string(raw),
		}
		if msg.GroupID == "" {
			msg.GroupID = strings.TrimSpace(env.Envelope.TypingMessage.GroupID)
		}
		ts := env.Envelope.Timestamp
		if ts > 0 {
			msg.TSMillis = normalizeSignalTimestamp(ts)
		}
		if msg.Text != "" || msg.GroupID != "" || len(msg.Previews) > 0 || len(msg.Attachments) > 0 {
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
	now := time.Now()
	month := now.Format("2006-01")
	day := now.Format("02")
	return filepath.ToSlash(filepath.Join(p.cfg.SignalOwner, month, day+".md"))
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
	entry := strings.Join(lines, "\n")
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}
	journalEntry := "## " + time.Now().Format("15:04") + "\n\n" + entry + "\n"
	if body == "" {
		journalDate := time.Now().Format("2 Jan 2006")
		body = "# " + journalDate + "\n\n" + journalEntry
	} else {
		body = strings.TrimRight(body, "\n") + "\n\n" + journalEntry
	}

	noteCtx := WithUser(ctx, User{Name: p.cfg.SignalOwner, Authenticated: true})
	_, apiErr := p.server.saveNoteCommon(noteCtx, saveNoteInput{
		NotePath:    notePath,
		TargetOwner: p.cfg.SignalOwner,
		Content:     body,
		Frontmatter: frontmatter,
	})
	if apiErr != nil {
		return fmt.Errorf("%s", apiErr.message)
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
	suffixTags := " #inbox #signal"
	text := normalizeSignalText(msg.Text)
	hasLinkPreview := false
	hasImagePreview := false
	for _, preview := range msg.Previews {
		if strings.TrimSpace(preview.URL) != "" {
			hasLinkPreview = true
		}
		if strings.TrimSpace(preview.ImageID) != "" {
			hasImagePreview = true
		}
	}
	hasAttachments := len(msg.Attachments) > 0

	// For captioned image messages, render as a regular inbox task then image(s).
	if text != "" && (hasImagePreview || hasAttachments) && !hasLinkPreview {
		lines := []string{fmt.Sprintf("- [ ] %s%s", text, suffixTags)}
		if noteID == "" {
			return lines, nil
		}
		for _, preview := range msg.Previews {
			if strings.TrimSpace(preview.ImageID) == "" {
				continue
			}
			attachmentName, ok, err := p.ensureSignalPreviewImage(ctx, noteID, preview)
			if err != nil {
				slog.Warn("signal preview image", "err", err)
				continue
			}
			if ok {
				lines = append(lines, "  ![](/attachments/"+noteID+"/"+attachmentName+")")
			}
		}
		for _, attachment := range msg.Attachments {
			attachmentName, ok, err := p.ensureSignalMessageAttachment(ctx, noteID, attachment)
			if err != nil {
				slog.Warn("signal attachment image", "err", err)
				continue
			}
			if ok {
				lines = append(lines, "  ![](/attachments/"+noteID+"/"+attachmentName+")")
			}
		}
		return lines, nil
	}

	lines := []string{}
	if len(msg.Previews) > 0 {
		for idx, preview := range msg.Previews {
			if strings.TrimSpace(preview.URL) == "" {
				continue
			}
			title := preview.Title
			if title == "" {
				title = preview.URL
			}
			lines = append(lines, fmt.Sprintf("- [ ] [%s](%s)%s", title, preview.URL, suffixTags))
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
		if len(lines) > 0 {
			if text != "" {
				lines = append(lines, "", fmt.Sprintf("- [ ] %s%s", text, suffixTags))
			}
			if noteID != "" {
				for _, attachment := range msg.Attachments {
					attachmentName, ok, err := p.ensureSignalMessageAttachment(ctx, noteID, attachment)
					if err != nil {
						slog.Warn("signal attachment image", "err", err)
						continue
					}
					if ok {
						lines = append(lines, "", "  ![](/attachments/"+noteID+"/"+attachmentName+")")
					}
				}
			}
			return lines, nil
		}
	}
	if text == "" {
		return nil, nil
	}
	lines = []string{fmt.Sprintf("- [ ] %s%s", text, suffixTags)}
	if noteID == "" {
		return lines, nil
	}
	for _, attachment := range msg.Attachments {
		attachmentName, ok, err := p.ensureSignalMessageAttachment(ctx, noteID, attachment)
		if err != nil {
			slog.Warn("signal attachment image", "err", err)
			continue
		}
		if ok {
			lines = append(lines, "  ![](/attachments/"+noteID+"/"+attachmentName+")")
		}
	}
	return lines, nil
}

func normalizeSignalText(text string) string {
	text = strings.TrimSpace(text)
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\t", " ")
	return strings.TrimSpace(text)
}

func (p *signalPoller) ensureSignalPreviewImage(ctx context.Context, noteID string, preview signalPreview) (string, bool, error) {
	return p.ensureSignalAttachment(ctx, noteID, preview.ImageID, preview.Filename, preview.ContentType)
}

func (p *signalPoller) ensureSignalMessageAttachment(ctx context.Context, noteID string, attachment signalAttachment) (string, bool, error) {
	return p.ensureSignalAttachment(ctx, noteID, attachment.ID, attachment.Filename, attachment.ContentType)
}

func (p *signalPoller) ensureSignalAttachment(ctx context.Context, noteID string, attachmentID string, filename string, contentType string) (string, bool, error) {
	attachmentID = strings.TrimSpace(attachmentID)
	if attachmentID == "" {
		return "", false, nil
	}
	name := sanitizeAttachmentName(filename)
	if name == "" {
		name = sanitizeAttachmentName(attachmentID)
	}
	if name == "" {
		return "", false, nil
	}
	if ext := extensionFromContentType(contentType); ext != "" && !strings.HasSuffix(strings.ToLower(name), ext) {
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
