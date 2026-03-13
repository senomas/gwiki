package web

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	attachmentImageMobileWidth  = 768
	attachmentImageDesktopWidth = 1600
)

func attachmentFileFromURL(raw string) (string, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", false
	}
	pathValue := parsed.Path
	if pathValue == "" {
		return "", "", false
	}
	clean := path.Clean(pathValue)
	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimPrefix(clean, "../")
	if !strings.HasPrefix(clean, "/attachments/") && !strings.HasPrefix(clean, "attachments/") {
		return "", "", false
	}
	rel := strings.TrimPrefix(clean, "/attachments/")
	rel = strings.TrimPrefix(rel, "attachments/")
	parts := strings.Split(rel, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	noteID := strings.TrimSpace(parts[0])
	if noteID == "" {
		return "", "", false
	}
	relPath := path.Clean(strings.Join(parts[1:], "/"))
	if relPath == "." || strings.HasPrefix(relPath, "..") || strings.Contains(relPath, "\\") {
		return "", "", false
	}
	return noteID, relPath, true
}

func normalizeAttachmentURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	if parsed.Path == "" {
		return strings.TrimSpace(raw)
	}
	clean := path.Clean(parsed.Path)
	if strings.HasPrefix(clean, "attachments/") {
		parsed.Path = "/" + strings.TrimPrefix(clean, "/")
		return parsed.String()
	}
	if strings.HasPrefix(clean, "/attachments/") {
		parsed.Path = clean
		return parsed.String()
	}
	return strings.TrimSpace(raw)
}

func attachmentImageOriginalURL(raw string) string {
	return normalizeAttachmentURL(raw)
}

func attachmentImageVariantURL(raw string, width int) string {
	normalized := attachmentImageOriginalURL(raw)
	if normalized == "" || !supportedAttachmentImageWidth(width) {
		return normalized
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return normalized
	}
	query := parsed.Query()
	query.Set("w", strconv.Itoa(width))
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func supportedAttachmentImageWidth(width int) bool {
	switch width {
	case attachmentImageMobileWidth, attachmentImageDesktopWidth:
		return true
	default:
		return false
	}
}

func requestedAttachmentImageWidth(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	width, err := strconv.Atoi(raw)
	if err != nil || !supportedAttachmentImageWidth(width) {
		return 0, false
	}
	return width, true
}

func isResizableAttachmentImage(relPath string) bool {
	switch strings.ToLower(path.Ext(relPath)) {
	case ".jpg", ".jpeg", ".png", ".webp":
		return true
	default:
		return false
	}
}

func attachmentImageVariantOutputExt(relPath string) string {
	switch strings.ToLower(path.Ext(relPath)) {
	case ".jpg", ".jpeg":
		return ".jpg"
	default:
		return ".png"
	}
}

func attachmentImageVariantAssetRelativePath(relPath string, width int) string {
	base := sanitizeAttachmentName(strings.TrimSuffix(path.Base(relPath), path.Ext(relPath)))
	if base == "" {
		base = "attachment-image"
	}
	sum := sha1.Sum([]byte(relPath))
	shortHash := hex.EncodeToString(sum[:])[:12]
	return path.Join(
		"image-cache",
		fmt.Sprintf("%s-%s-w%d%s", base, shortHash, width, attachmentImageVariantOutputExt(relPath)),
	)
}

func (s *Server) ensureAttachmentImageVariant(ownerName, noteID, relPath string, width int) (string, bool) {
	if !supportedAttachmentImageWidth(width) || !isResizableAttachmentImage(relPath) {
		return "", false
	}
	assetsRoot := strings.TrimSpace(s.assetsRoot())
	if assetsRoot == "" {
		return "", false
	}
	sourcePath := filepath.Join(s.noteAttachmentsDir(ownerName, noteID), filepath.FromSlash(relPath))
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil || sourceInfo.IsDir() {
		return "", false
	}

	variantRel := attachmentImageVariantAssetRelativePath(relPath, width)
	variantPath := filepath.Join(assetsRoot, noteID, filepath.FromSlash(variantRel))
	if info, err := os.Stat(variantPath); err == nil && !info.IsDir() && info.Size() > 0 && !info.ModTime().Before(sourceInfo.ModTime()) {
		return variantPath, true
	}
	if err := os.MkdirAll(filepath.Dir(variantPath), 0o755); err != nil {
		slog.Warn("attachment image cache mkdir failed", "owner", ownerName, "note_id", noteID, "rel_path", relPath, "width", width, "err", err)
		return "", false
	}
	if err := generateAttachmentImageVariant(sourcePath, variantPath, width, attachmentImageVariantOutputExt(relPath)); err != nil {
		slog.Warn("attachment image cache generation failed", "owner", ownerName, "note_id", noteID, "rel_path", relPath, "width", width, "err", err)
		return "", false
	}
	return variantPath, true
}

func generateAttachmentImageVariant(sourcePath, variantPath string, width int, outputExt string) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(variantPath), ".attachment-image-*"+outputExt)
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	filter := fmt.Sprintf("scale=w=%d:h=%d:force_original_aspect_ratio=decrease:flags=lanczos", width, width)
	args := []string{
		"-hide_banner",
		"-loglevel", "error",
		"-y",
		"-i", sourcePath,
		"-vf", filter,
		"-frames:v", "1",
	}
	switch strings.ToLower(outputExt) {
	case ".jpg", ".jpeg":
		args = append(args, "-q:v", "3")
	case ".png":
		args = append(args, "-compression_level", "6")
	}
	args = append(args, tmpPath)

	cmd := exec.Command("ffmpeg", args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	info, err := os.Stat(tmpPath)
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if info.Size() <= 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("attachment image variant output empty")
	}
	if err := os.Rename(tmpPath, variantPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
