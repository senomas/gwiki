package web

import (
	"net/http"
	"testing"
	"time"
)

func TestLoginRateLimiterIPBlock(t *testing.T) {
	limiter := newLoginRateLimiterWithConfig(loginRateLimiterConfig{
		ipWindow:        time.Minute,
		ipBlock:         2 * time.Minute,
		ipMaxAttempts:   2,
		userWindow:      10 * time.Minute,
		userBlock:       10 * time.Minute,
		userBlockAfter:  99,
		delayStartAfter: 3,
		delayMax:        30 * time.Second,
		sweepInterval:   time.Minute,
		retention:       10 * time.Minute,
	})
	now := time.Date(2026, 2, 22, 12, 0, 0, 0, time.UTC)

	if ok, _, _ := limiter.Allow("127.0.0.1", "alice", now); !ok {
		t.Fatalf("expected first attempt allowed")
	}
	limiter.OnFailure("127.0.0.1", "alice", now)
	if ok, _, _ := limiter.Allow("127.0.0.1", "alice", now.Add(1*time.Second)); !ok {
		t.Fatalf("expected second attempt allowed")
	}
	limiter.OnFailure("127.0.0.1", "alice", now.Add(1*time.Second))

	ok, retryAfter, reason := limiter.Allow("127.0.0.1", "alice", now.Add(2*time.Second))
	if ok {
		t.Fatalf("expected third attempt to be blocked by ip limit")
	}
	if reason != "ip_blocked" {
		t.Fatalf("expected ip_blocked reason, got %q", reason)
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retry after, got %s", retryAfter)
	}
}

func TestLoginRateLimiterDelayAndResetOnSuccess(t *testing.T) {
	limiter := newLoginRateLimiterWithConfig(loginRateLimiterConfig{
		ipWindow:        10 * time.Minute,
		ipBlock:         time.Minute,
		ipMaxAttempts:   100,
		userWindow:      10 * time.Minute,
		userBlock:       10 * time.Minute,
		userBlockAfter:  50,
		delayStartAfter: 2,
		delayMax:        30 * time.Second,
		sweepInterval:   time.Minute,
		retention:       10 * time.Minute,
	})
	now := time.Date(2026, 2, 22, 13, 0, 0, 0, time.UTC)

	if ok, _, _ := limiter.Allow("10.0.0.1", "alice", now); !ok {
		t.Fatalf("expected first attempt allowed")
	}
	limiter.OnFailure("10.0.0.1", "alice", now)

	if ok, _, _ := limiter.Allow("10.0.0.1", "alice", now.Add(100*time.Millisecond)); !ok {
		t.Fatalf("expected second attempt allowed")
	}
	limiter.OnFailure("10.0.0.1", "alice", now.Add(100*time.Millisecond))

	ok, retryAfter, reason := limiter.Allow("10.0.0.1", "alice", now.Add(500*time.Millisecond))
	if ok {
		t.Fatalf("expected attempt during cooldown to be throttled")
	}
	if reason != "throttled" {
		t.Fatalf("expected throttled reason, got %q", reason)
	}
	if retryAfter <= 0 || retryAfter > 2*time.Second {
		t.Fatalf("unexpected retry after %s", retryAfter)
	}

	if ok, _, _ := limiter.Allow("10.0.0.1", "alice", now.Add(1200*time.Millisecond)); !ok {
		t.Fatalf("expected attempt after cooldown to be allowed")
	}

	limiter.OnSuccess("10.0.0.1", "alice")
	if ok, _, _ := limiter.Allow("10.0.0.1", "alice", now.Add(1300*time.Millisecond)); !ok {
		t.Fatalf("expected immediate allow after success reset")
	}
}

func TestLoginRateLimiterUserBlock(t *testing.T) {
	limiter := newLoginRateLimiterWithConfig(loginRateLimiterConfig{
		ipWindow:        10 * time.Minute,
		ipBlock:         time.Minute,
		ipMaxAttempts:   100,
		userWindow:      10 * time.Minute,
		userBlock:       5 * time.Minute,
		userBlockAfter:  3,
		delayStartAfter: 10,
		delayMax:        30 * time.Second,
		sweepInterval:   time.Minute,
		retention:       10 * time.Minute,
	})
	now := time.Date(2026, 2, 22, 14, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		if ok, _, _ := limiter.Allow("10.0.0.2", "alice", at); !ok {
			t.Fatalf("expected allow before user lock at iteration %d", i)
		}
		limiter.OnFailure("10.0.0.2", "alice", at)
	}

	ok, retryAfter, reason := limiter.Allow("10.0.0.2", "alice", now.Add(4*time.Second))
	if ok {
		t.Fatalf("expected user lock")
	}
	if reason != "user_blocked" {
		t.Fatalf("expected user_blocked reason, got %q", reason)
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retry after during user lock")
	}
}

func TestLoginRemoteIP(t *testing.T) {
	req := &http.Request{RemoteAddr: "127.0.0.1:43210"}
	if got := loginRemoteIP(req); got != "127.0.0.1" {
		t.Fatalf("expected parsed ip, got %q", got)
	}
	req = &http.Request{RemoteAddr: "bad-addr"}
	if got := loginRemoteIP(req); got != "bad-addr" {
		t.Fatalf("expected fallback raw remote addr, got %q", got)
	}
	req = &http.Request{RemoteAddr: ""}
	if got := loginRemoteIP(req); got != "unknown" {
		t.Fatalf("expected unknown, got %q", got)
	}
}
