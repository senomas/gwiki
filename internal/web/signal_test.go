package web

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gwiki/internal/config"
)

func TestSignalDebugLogDir_Default(t *testing.T) {
	t.Setenv("WIKI_DEV_LOG_FILE", "")

	got := signalDebugLogDir()
	if got != "." {
		t.Fatalf("expected default log dir '.', got %q", got)
	}
}

func TestSignalDebugLogDir_FromLogPath(t *testing.T) {
	path := filepath.Join("log", "dev.log")
	t.Setenv("WIKI_DEV_LOG_FILE", path)

	got := signalDebugLogDir()
	if filepath.Clean(got) != filepath.Clean("log") {
		t.Fatalf("expected log dir %q, got %q", "log", got)
	}
}

func TestSignalPollerWriteSignalDebugMessage(t *testing.T) {
	t.Setenv("DEV", "1")
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "log", "dev.log")
	t.Setenv("WIKI_DEV_LOG_FILE", logPath)

	ts := time.Date(2026, 2, 11, 10, 13, 14, 0, time.UTC)
	msg := signalMessage{
		Sender:   "+628123456789",
		Text:     "test inbox from signal",
		GroupID:  "group-id",
		Group:    "gwiki",
		TSMillis: ts.UnixMilli(),
		RawJSON:  `{"envelope":{"source":"+628123456789","dataMessage":{"message":"test inbox from signal"}}}`,
	}

	var poller signalPoller
	poller.writeSignalDebugMessage(msg)

	expectedName := "signal-" + time.UnixMilli(msg.TSMillis).Format("060102150405") + ".json"
	expectedPath := filepath.Join(tmpDir, "log", expectedName)
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read debug file: %v", err)
	}
	var dump map[string]any
	if err := json.Unmarshal(data, &dump); err != nil {
		t.Fatalf("unmarshal debug json: %v; data=%s", err, string(data))
	}
	if got, _ := dump["sender"].(string); got != "+628123456789" {
		t.Fatalf("expected sender in debug file, got: %v", dump["sender"])
	}
	if got, _ := dump["text"].(string); got != "test inbox from signal" {
		t.Fatalf("expected message text in debug file, got: %v", dump["text"])
	}
	raw, ok := dump["raw"].(map[string]any)
	if !ok {
		t.Fatalf("expected raw object in debug file, got: %#v", dump["raw"])
	}
	env, ok := raw["envelope"].(map[string]any)
	if !ok {
		t.Fatalf("expected envelope in raw object, got: %#v", raw["envelope"])
	}
	dataMsg, ok := env["dataMessage"].(map[string]any)
	if !ok {
		t.Fatalf("expected dataMessage in raw envelope, got: %#v", env["dataMessage"])
	}
	if got, _ := dataMsg["message"].(string); got != "test inbox from signal" {
		t.Fatalf("expected raw message text, got: %v", dataMsg["message"])
	}
}

func TestSignalPollerWriteSignalDebugMessage_DisabledWithoutDev(t *testing.T) {
	t.Setenv("DEV", "")
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "log", "dev.log")
	t.Setenv("WIKI_DEV_LOG_FILE", logPath)

	msg := signalMessage{
		Text:     "should not be dumped",
		TSMillis: time.Now().UnixMilli(),
	}
	var poller signalPoller
	poller.writeSignalDebugMessage(msg)

	matches, err := filepath.Glob(filepath.Join(tmpDir, "log", "signal-*.json"))
	if err != nil {
		t.Fatalf("glob signal debug files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no signal debug files, got: %v", matches)
	}
}

func TestDecodeSignalMessage_ImageOnlyPreviewWithText(t *testing.T) {
	raw := []byte(`{
		"envelope": {
			"source": "+628111111111",
			"timestamp": 1770206552814,
			"dataMessage": {
				"message": "caption from signal",
				"groupInfo": {"groupId": "group-a", "name": "gwiki"},
				"previews": [{
					"url": "",
					"title": "",
					"description": "",
					"image": {
						"contentType": "image/jpeg",
						"filename": "photo.jpg",
						"id": "image-123"
					}
				}]
			}
		}
	}`)

	msg, ok := decodeSignalMessage(raw)
	if !ok {
		t.Fatalf("expected message to decode")
	}
	if msg.Text != "caption from signal" {
		t.Fatalf("unexpected text: %q", msg.Text)
	}
	if len(msg.Previews) != 1 {
		t.Fatalf("expected one preview, got %d", len(msg.Previews))
	}
	if msg.Previews[0].ImageID != "image-123" {
		t.Fatalf("unexpected image id: %q", msg.Previews[0].ImageID)
	}
	if !strings.Contains(msg.RawJSON, `"message": "caption from signal"`) {
		t.Fatalf("expected raw json to include message, got: %q", msg.RawJSON)
	}
}

func TestDecodeSignalMessage_DataMessageAttachmentsWithText(t *testing.T) {
	raw := []byte(`{
		"envelope": {
			"source": "+628129555265",
			"timestamp": 1770876198291,
			"dataMessage": {
				"message": "Sate klathal",
				"groupInfo": {"groupId": "group-a", "name": "gwiki"},
				"attachments": [{
					"contentType": "image/jpeg",
					"filename": null,
					"id": "eOvZWIZP8IRLCoKX8ABn.jpg"
				}]
			}
		}
	}`)

	msg, ok := decodeSignalMessage(raw)
	if !ok {
		t.Fatalf("expected message to decode")
	}
	if msg.Text != "Sate klathal" {
		t.Fatalf("unexpected text: %q", msg.Text)
	}
	if len(msg.Attachments) != 1 {
		t.Fatalf("expected one attachment, got %d", len(msg.Attachments))
	}
	if msg.Attachments[0].ID != "eOvZWIZP8IRLCoKX8ABn.jpg" {
		t.Fatalf("unexpected attachment id: %q", msg.Attachments[0].ID)
	}
	if msg.Attachments[0].ContentType != "image/jpeg" {
		t.Fatalf("unexpected attachment content type: %q", msg.Attachments[0].ContentType)
	}
	if !strings.Contains(msg.RawJSON, `"attachments"`) {
		t.Fatalf("expected raw json to include attachments, got: %q", msg.RawJSON)
	}
}

func TestBuildSignalNoteLines_ImageWithTextTemplate(t *testing.T) {
	tmpDir := t.TempDir()
	owner := "seno"
	noteID := "note-123"
	attachmentsDir := filepath.Join(tmpDir, owner, "notes", "attachments", noteID)
	if err := os.MkdirAll(attachmentsDir, 0o755); err != nil {
		t.Fatalf("mkdir attachments: %v", err)
	}
	if err := os.WriteFile(filepath.Join(attachmentsDir, "photo.jpg"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write attachment: %v", err)
	}

	cfg := config.Config{
		RepoPath:    tmpDir,
		SignalOwner: owner,
	}
	poller := signalPoller{
		cfg:    cfg,
		server: &Server{cfg: cfg},
	}

	lines, err := poller.buildSignalNoteLines(context.Background(), signalMessage{
		Text: "my caption",
		Previews: []signalPreview{{
			ImageID:  "image-123",
			Filename: "photo.jpg",
		}},
	}, noteID)
	if err != nil {
		t.Fatalf("build lines: %v", err)
	}

	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %#v", len(lines), lines)
	}
	if lines[0] != "- [ ] my caption #inbox #signal" {
		t.Fatalf("unexpected first line: %q", lines[0])
	}
	if lines[1] != "  ![](/attachments/note-123/photo.jpg)" {
		t.Fatalf("unexpected image line: %q", lines[1])
	}
}

func TestBuildSignalNoteLines_DataMessageAttachmentsWithText(t *testing.T) {
	tmpDir := t.TempDir()
	owner := "seno"
	noteID := "note-123"
	attachmentsDir := filepath.Join(tmpDir, owner, "notes", "attachments", noteID)
	if err := os.MkdirAll(attachmentsDir, 0o755); err != nil {
		t.Fatalf("mkdir attachments: %v", err)
	}
	attachmentFile := "image-attachment-123.jpg"
	if err := os.WriteFile(filepath.Join(attachmentsDir, attachmentFile), []byte("x"), 0o644); err != nil {
		t.Fatalf("write attachment: %v", err)
	}

	cfg := config.Config{
		RepoPath:    tmpDir,
		SignalOwner: owner,
	}
	poller := signalPoller{
		cfg:    cfg,
		server: &Server{cfg: cfg},
	}

	lines, err := poller.buildSignalNoteLines(context.Background(), signalMessage{
		Text: "my caption",
		Attachments: []signalAttachment{{
			ID:          "image-attachment-123",
			ContentType: "image/jpeg",
		}},
	}, noteID)
	if err != nil {
		t.Fatalf("build lines: %v", err)
	}

	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %#v", len(lines), lines)
	}
	if lines[0] != "- [ ] my caption #inbox #signal" {
		t.Fatalf("unexpected first line: %q", lines[0])
	}
	if lines[1] != "  ![](/attachments/note-123/"+attachmentFile+")" {
		t.Fatalf("unexpected image line: %q", lines[1])
	}
}

func TestBuildSignalNoteLines_LinkPreviewIncludesOriginalMessage(t *testing.T) {
	poller := signalPoller{}
	lines, err := poller.buildSignalNoteLines(context.Background(), signalMessage{
		Text: "https://vt.tiktok.com/ZSmkQSUcW/\n\nDamar Valley Glamping Wonosobo",
		Previews: []signalPreview{{
			URL:         "https://vt.tiktok.com/ZSmkQSUcW",
			Title:       "TikTok",
			Description: "Preview description",
		}},
	}, "")
	if err != nil {
		t.Fatalf("build lines: %v", err)
	}
	if len(lines) == 0 {
		t.Fatalf("expected non-empty lines")
	}
	if lines[0] != "- [ ] [TikTok](https://vt.tiktok.com/ZSmkQSUcW) #inbox #signal" {
		t.Fatalf("unexpected preview line: %q", lines[0])
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "Preview description") {
		t.Fatalf("expected preview description in output: %#v", lines)
	}
	if !strings.Contains(joined, "- [ ] https://vt.tiktok.com/ZSmkQSUcW/") {
		t.Fatalf("expected original message URL in output, got: %#v", lines)
	}
	if !strings.Contains(joined, "Damar Valley Glamping Wonosobo #inbox #signal") {
		t.Fatalf("expected original message line in output, got: %#v", lines)
	}
}
