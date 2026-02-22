package web

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"gwiki/internal/config"
)

const (
	defaultLoginRLIPMaxAttempts   = 60
	defaultLoginRLUserBlockAfter  = 12
	defaultLoginRLDelayStartAfter = 3
)

type loginRateLimiter struct {
	mu        sync.Mutex
	cfg       loginRateLimiterConfig
	ipStates  map[string]*loginIPState
	userState map[string]*loginUserState
	lastSweep time.Time
}

type loginRateLimiterConfig struct {
	ipWindow        time.Duration
	ipBlock         time.Duration
	ipMaxAttempts   int
	userWindow      time.Duration
	userBlock       time.Duration
	userBlockAfter  int
	delayStartAfter int
	delayMax        time.Duration
	sweepInterval   time.Duration
	retention       time.Duration
}

type loginIPState struct {
	attempts     []time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

type loginUserState struct {
	failures            []time.Time
	consecutiveFailures int
	nextAllowed         time.Time
	blockedUntil        time.Time
	lastSeen            time.Time
}

func newLoginRateLimiter(cfg config.Config) *loginRateLimiter {
	rlCfg := loginRateLimiterConfig{
		ipWindow:        positiveDurationOr(cfg.LoginRateLimitIPWindow, 5*time.Minute),
		ipBlock:         positiveDurationOr(cfg.LoginRateLimitIPBlock, 5*time.Minute),
		ipMaxAttempts:   positiveIntOr(cfg.LoginRateLimitIPMaxAttempts, defaultLoginRLIPMaxAttempts),
		userWindow:      positiveDurationOr(cfg.LoginRateLimitUserWindow, 10*time.Minute),
		userBlock:       positiveDurationOr(cfg.LoginRateLimitUserBlock, 10*time.Minute),
		userBlockAfter:  positiveIntOr(cfg.LoginRateLimitUserBlockAfter, defaultLoginRLUserBlockAfter),
		delayStartAfter: positiveIntOr(cfg.LoginRateLimitDelayStartAfter, defaultLoginRLDelayStartAfter),
		delayMax:        positiveDurationOr(cfg.LoginRateLimitDelayMax, 30*time.Second),
		sweepInterval:   positiveDurationOr(cfg.LoginRateLimitSweep, 10*time.Minute),
	}
	rlCfg.retention = maxDuration(
		rlCfg.ipWindow,
		rlCfg.ipBlock,
		rlCfg.userWindow,
		rlCfg.userBlock,
		rlCfg.delayMax,
	) * 2
	if rlCfg.retention <= 0 {
		rlCfg.retention = 20 * time.Minute
	}
	return newLoginRateLimiterWithConfig(rlCfg)
}

func newLoginRateLimiterWithConfig(cfg loginRateLimiterConfig) *loginRateLimiter {
	if cfg.ipWindow <= 0 {
		cfg.ipWindow = 5 * time.Minute
	}
	if cfg.ipBlock <= 0 {
		cfg.ipBlock = 5 * time.Minute
	}
	if cfg.ipMaxAttempts <= 0 {
		cfg.ipMaxAttempts = defaultLoginRLIPMaxAttempts
	}
	if cfg.userWindow <= 0 {
		cfg.userWindow = 10 * time.Minute
	}
	if cfg.userBlock <= 0 {
		cfg.userBlock = 10 * time.Minute
	}
	if cfg.userBlockAfter <= 0 {
		cfg.userBlockAfter = defaultLoginRLUserBlockAfter
	}
	if cfg.delayStartAfter <= 0 {
		cfg.delayStartAfter = defaultLoginRLDelayStartAfter
	}
	if cfg.delayMax <= 0 {
		cfg.delayMax = 30 * time.Second
	}
	if cfg.sweepInterval <= 0 {
		cfg.sweepInterval = 10 * time.Minute
	}
	if cfg.retention <= 0 {
		cfg.retention = maxDuration(cfg.userWindow, cfg.userBlock, cfg.ipWindow, cfg.ipBlock, cfg.delayMax) * 2
	}
	if cfg.retention <= 0 {
		cfg.retention = 20 * time.Minute
	}
	return &loginRateLimiter{
		cfg:       cfg,
		ipStates:  make(map[string]*loginIPState),
		userState: make(map[string]*loginUserState),
	}
}

func (l *loginRateLimiter) Allow(ip, username string, now time.Time) (bool, time.Duration, string) {
	if l == nil {
		return true, 0, ""
	}
	if now.IsZero() {
		now = time.Now()
	}
	ip = normalizeLoginIP(ip)
	userKey := loginUserKey(ip, username)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeSweepLocked(now)

	ipState := l.ipStates[ip]
	if ipState == nil {
		ipState = &loginIPState{}
		l.ipStates[ip] = ipState
	}
	ipState.lastSeen = now
	pruneTimeSlice(&ipState.attempts, now.Add(-l.cfg.ipWindow))
	if now.Before(ipState.blockedUntil) {
		return false, ipState.blockedUntil.Sub(now), "ip_blocked"
	}
	ipState.attempts = append(ipState.attempts, now)
	if len(ipState.attempts) > l.cfg.ipMaxAttempts {
		ipState.blockedUntil = now.Add(l.cfg.ipBlock)
		return false, ipState.blockedUntil.Sub(now), "ip_blocked"
	}

	userState := l.userState[userKey]
	if userState == nil {
		userState = &loginUserState{}
		l.userState[userKey] = userState
	}
	userState.lastSeen = now
	pruneTimeSlice(&userState.failures, now.Add(-l.cfg.userWindow))
	if now.Before(userState.blockedUntil) {
		return false, userState.blockedUntil.Sub(now), "user_blocked"
	}
	if now.Before(userState.nextAllowed) {
		return false, userState.nextAllowed.Sub(now), "throttled"
	}
	return true, 0, ""
}

func (l *loginRateLimiter) OnFailure(ip, username string, now time.Time) {
	if l == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	userKey := loginUserKey(ip, username)

	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeSweepLocked(now)

	userState := l.userState[userKey]
	if userState == nil {
		userState = &loginUserState{}
		l.userState[userKey] = userState
	}
	userState.lastSeen = now
	pruneTimeSlice(&userState.failures, now.Add(-l.cfg.userWindow))
	userState.failures = append(userState.failures, now)
	userState.consecutiveFailures++

	if len(userState.failures) >= l.cfg.userBlockAfter {
		userState.blockedUntil = now.Add(l.cfg.userBlock)
		userState.nextAllowed = userState.blockedUntil
		return
	}

	delay := l.delayForFailures(userState.consecutiveFailures)
	if delay > 0 {
		userState.nextAllowed = now.Add(delay)
	}
}

func (l *loginRateLimiter) OnSuccess(ip, username string) {
	if l == nil {
		return
	}
	userKey := loginUserKey(ip, username)

	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.userState, userKey)
}

func (l *loginRateLimiter) delayForFailures(consecutiveFailures int) time.Duration {
	if consecutiveFailures < l.cfg.delayStartAfter {
		return 0
	}
	shift := consecutiveFailures - l.cfg.delayStartAfter
	if shift < 0 {
		shift = 0
	}
	if shift > 20 {
		shift = 20
	}
	delay := time.Second * time.Duration(1<<shift)
	if delay > l.cfg.delayMax {
		return l.cfg.delayMax
	}
	return delay
}

func (l *loginRateLimiter) maybeSweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < l.cfg.sweepInterval {
		return
	}
	expireBefore := now.Add(-l.cfg.retention)
	for key, state := range l.ipStates {
		pruneTimeSlice(&state.attempts, now.Add(-l.cfg.ipWindow))
		if len(state.attempts) == 0 && now.After(state.blockedUntil) && state.lastSeen.Before(expireBefore) {
			delete(l.ipStates, key)
		}
	}
	for key, state := range l.userState {
		pruneTimeSlice(&state.failures, now.Add(-l.cfg.userWindow))
		if len(state.failures) == 0 && now.After(state.nextAllowed) && now.After(state.blockedUntil) && state.lastSeen.Before(expireBefore) {
			delete(l.userState, key)
		}
	}
	l.lastSweep = now
}

func pruneTimeSlice(items *[]time.Time, after time.Time) {
	list := *items
	if len(list) == 0 {
		return
	}
	keep := 0
	for keep < len(list) && list[keep].Before(after) {
		keep++
	}
	if keep == 0 {
		return
	}
	if keep >= len(list) {
		*items = (*items)[:0]
		return
	}
	next := make([]time.Time, len(list)-keep)
	copy(next, list[keep:])
	*items = next
}

func loginRemoteIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	raw := strings.TrimSpace(r.RemoteAddr)
	if raw == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil {
		host = strings.TrimSpace(host)
		if host != "" {
			return host
		}
	}
	return raw
}

func loginUserKey(ip, username string) string {
	return normalizeLoginIP(ip) + "\n" + normalizeLoginUsername(username)
}

func normalizeLoginUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func normalizeLoginIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "unknown"
	}
	return ip
}

func loginUsernameHash(username string) string {
	username = normalizeLoginUsername(username)
	if username == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(username))
	return hex.EncodeToString(sum[:8])
}

func positiveDurationOr(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

func positiveIntOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func maxDuration(values ...time.Duration) time.Duration {
	var max time.Duration
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}
