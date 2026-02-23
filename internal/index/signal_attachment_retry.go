package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	signalAttachmentRetryInitialDelay = 5 * time.Second
	signalAttachmentRetryMaxDelay     = time.Hour
)

type SignalAttachmentRetry struct {
	OwnerName    string
	NoteID       string
	AttachmentID string
	Filename     string
	ContentType  string
	Attempt      int
	NextRetryAt  time.Time
	LastError    string
	UpdatedAt    time.Time
}

func (i *Index) ScheduleSignalAttachmentRetry(
	ctx context.Context,
	ownerName string,
	noteID string,
	attachmentID string,
	filename string,
	contentType string,
	lastError string,
) (SignalAttachmentRetry, error) {
	ownerName = strings.TrimSpace(ownerName)
	noteID = strings.TrimSpace(noteID)
	attachmentID = strings.TrimSpace(attachmentID)
	filename = strings.TrimSpace(filename)
	contentType = strings.TrimSpace(contentType)
	lastError = strings.TrimSpace(lastError)
	if ownerName == "" || noteID == "" || attachmentID == "" {
		return SignalAttachmentRetry{}, fmt.Errorf("invalid signal attachment retry key")
	}

	tx, txStart, err := i.beginTx(ctx, "signal-attachment-retry-schedule")
	if err != nil {
		return SignalAttachmentRetry{}, err
	}
	defer i.rollbackTx(tx, "signal-attachment-retry-schedule", txStart)

	var attempt int
	err = i.queryRowContextTx(
		ctx,
		tx,
		`SELECT attempt
		FROM signal_attachment_retries
		WHERE owner_name=? AND note_id=? AND attachment_id=?`,
		ownerName,
		noteID,
		attachmentID,
	).Scan(&attempt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return SignalAttachmentRetry{}, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		attempt = 1
	} else {
		attempt++
	}

	now := time.Now()
	nextRetry := now.Add(signalAttachmentRetryDelay(attempt))
	if _, err := i.execContextTx(
		ctx,
		tx,
		`INSERT INTO signal_attachment_retries(
			owner_name,
			note_id,
			attachment_id,
			filename,
			content_type,
			attempt,
			next_retry_unix,
			last_error,
			updated_at
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(owner_name, note_id, attachment_id)
		DO UPDATE SET
			filename=excluded.filename,
			content_type=excluded.content_type,
			attempt=excluded.attempt,
			next_retry_unix=excluded.next_retry_unix,
			last_error=excluded.last_error,
			updated_at=excluded.updated_at`,
		ownerName,
		noteID,
		attachmentID,
		filename,
		contentType,
		attempt,
		nextRetry.Unix(),
		lastError,
		now.Unix(),
	); err != nil {
		return SignalAttachmentRetry{}, err
	}
	if err := i.commitTx(tx, "signal-attachment-retry-schedule", txStart); err != nil {
		return SignalAttachmentRetry{}, err
	}

	return SignalAttachmentRetry{
		OwnerName:    ownerName,
		NoteID:       noteID,
		AttachmentID: attachmentID,
		Filename:     filename,
		ContentType:  contentType,
		Attempt:      attempt,
		NextRetryAt:  nextRetry,
		LastError:    lastError,
		UpdatedAt:    now,
	}, nil
}

func (i *Index) ListDueSignalAttachmentRetries(
	ctx context.Context,
	ownerName string,
	now time.Time,
	limit int,
) ([]SignalAttachmentRetry, error) {
	ownerName = strings.TrimSpace(ownerName)
	if ownerName == "" {
		return nil, fmt.Errorf("owner is required")
	}
	if limit <= 0 {
		limit = 20
	}

	rows, err := i.queryContext(
		ctx,
		`SELECT
			owner_name,
			note_id,
			attachment_id,
			filename,
			content_type,
			attempt,
			next_retry_unix,
			last_error,
			updated_at
		FROM signal_attachment_retries
		WHERE owner_name=? AND next_retry_unix<=?
		ORDER BY next_retry_unix ASC
		LIMIT ?`,
		ownerName,
		now.Unix(),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]SignalAttachmentRetry, 0, limit)
	for rows.Next() {
		var (
			item      SignalAttachmentRetry
			nextUnix  int64
			updatedAt int64
		)
		if err := rows.Scan(
			&item.OwnerName,
			&item.NoteID,
			&item.AttachmentID,
			&item.Filename,
			&item.ContentType,
			&item.Attempt,
			&nextUnix,
			&item.LastError,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.NextRetryAt = time.Unix(nextUnix, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (i *Index) DeleteSignalAttachmentRetry(ctx context.Context, ownerName string, noteID string, attachmentID string) error {
	ownerName = strings.TrimSpace(ownerName)
	noteID = strings.TrimSpace(noteID)
	attachmentID = strings.TrimSpace(attachmentID)
	if ownerName == "" || noteID == "" || attachmentID == "" {
		return nil
	}
	_, err := i.execContext(
		ctx,
		`DELETE FROM signal_attachment_retries
		WHERE owner_name=? AND note_id=? AND attachment_id=?`,
		ownerName,
		noteID,
		attachmentID,
	)
	return err
}

func signalAttachmentRetryDelay(attempt int) time.Duration {
	if attempt <= 1 {
		return signalAttachmentRetryInitialDelay
	}
	delay := signalAttachmentRetryInitialDelay
	for i := 1; i < attempt; i++ {
		if delay >= signalAttachmentRetryMaxDelay {
			return signalAttachmentRetryMaxDelay
		}
		delay *= 2
		if delay >= signalAttachmentRetryMaxDelay {
			return signalAttachmentRetryMaxDelay
		}
	}
	if delay <= 0 {
		return signalAttachmentRetryMaxDelay
	}
	return delay
}
