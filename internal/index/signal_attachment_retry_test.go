package index

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignalAttachmentRetryDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 1, want: 5 * time.Second},
		{attempt: 2, want: 10 * time.Second},
		{attempt: 3, want: 20 * time.Second},
		{attempt: 4, want: 40 * time.Second},
		{attempt: 5, want: 80 * time.Second},
		{attempt: 20, want: time.Hour},
	}
	for _, tc := range tests {
		got := signalAttachmentRetryDelay(tc.attempt)
		if got != tc.want {
			t.Fatalf("attempt=%d delay=%s want=%s", tc.attempt, got, tc.want)
		}
	}
}

func TestSignalAttachmentRetryScheduleAndList(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "seno", "notes"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}
	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()
	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	first, err := idx.ScheduleSignalAttachmentRetry(
		ctx,
		"seno",
		"2026-02/23-08-05.md",
		"att-1",
		"photo.jpg",
		"image/jpeg",
		"http 500",
	)
	if err != nil {
		t.Fatalf("schedule first retry: %v", err)
	}
	if first.Attempt != 1 {
		t.Fatalf("first attempt=%d want=1", first.Attempt)
	}

	second, err := idx.ScheduleSignalAttachmentRetry(
		ctx,
		"seno",
		"2026-02/23-08-05.md",
		"att-1",
		"photo.jpg",
		"image/jpeg",
		"timeout",
	)
	if err != nil {
		t.Fatalf("schedule second retry: %v", err)
	}
	if second.Attempt != 2 {
		t.Fatalf("second attempt=%d want=2", second.Attempt)
	}
	if !second.NextRetryAt.After(first.NextRetryAt) {
		t.Fatalf("second next retry should be after first, first=%s second=%s", first.NextRetryAt, second.NextRetryAt)
	}

	dueNow, err := idx.ListDueSignalAttachmentRetries(ctx, "seno", time.Now(), 20)
	if err != nil {
		t.Fatalf("list due now: %v", err)
	}
	if len(dueNow) != 0 {
		t.Fatalf("expected no due retries now, got %d", len(dueNow))
	}

	dueLater, err := idx.ListDueSignalAttachmentRetries(ctx, "seno", second.NextRetryAt.Add(time.Second), 20)
	if err != nil {
		t.Fatalf("list due later: %v", err)
	}
	if len(dueLater) != 1 {
		t.Fatalf("expected one due retry, got %d", len(dueLater))
	}
	if dueLater[0].Attempt != 2 {
		t.Fatalf("due retry attempt=%d want=2", dueLater[0].Attempt)
	}

	if err := idx.DeleteSignalAttachmentRetry(ctx, "seno", "2026-02/23-08-05.md", "att-1"); err != nil {
		t.Fatalf("delete retry: %v", err)
	}
	dueAfterDelete, err := idx.ListDueSignalAttachmentRetries(ctx, "seno", time.Now().Add(24*time.Hour), 20)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(dueAfterDelete) != 0 {
		t.Fatalf("expected no retries after delete, got %d", len(dueAfterDelete))
	}
}
