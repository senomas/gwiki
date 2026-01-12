package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	"gwiki/internal/auth"
	"gwiki/internal/config"
	"gwiki/internal/index"
)

type authEntry struct {
	plain string
	hash  *auth.Argon2idHash
}

type Auth struct {
	users    map[string]authEntry
	sessions map[string]sessionEntry
	mu       sync.Mutex
}

type sessionEntry struct {
	user    string
	expires time.Time
}

func newAuth(cfg config.Config) (*Auth, error) {
	users := make(map[string]authEntry)

	if cfg.AuthFile != "" {
		fileUsers, err := auth.LoadFile(cfg.AuthFile)
		if err != nil {
			return nil, err
		}
		for user, hash := range fileUsers {
			users[user] = authEntry{hash: hash}
		}
	}

	if cfg.AuthUser != "" || cfg.AuthPass != "" {
		if cfg.AuthUser == "" || cfg.AuthPass == "" {
			return nil, errors.New("WIKI_AUTH_USER and WIKI_AUTH_PASS must be set together")
		}
		users[cfg.AuthUser] = authEntry{plain: cfg.AuthPass}
	}

	if len(users) == 0 {
		return nil, nil
	}

	return &Auth{
		users:    users,
		sessions: make(map[string]sessionEntry),
	}, nil
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, ok := a.sessionUser(r); ok {
			ctx := WithUser(r.Context(), User{Name: user, Authenticated: true})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		user, pass, ok := r.BasicAuth()
		if ok {
			if !a.verify(user, pass) {
				w.Header().Set("WWW-Authenticate", `Basic realm="gwiki"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := WithUser(r.Context(), User{Name: user, Authenticated: true})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		ctx := index.WithPublicVisibility(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Auth) verify(user, pass string) bool {
	entry, ok := a.users[user]
	if !ok {
		return false
	}
	if entry.hash != nil {
		return entry.hash.Verify(pass)
	}
	return subtle.ConstantTimeCompare([]byte(entry.plain), []byte(pass)) == 1
}

func (a *Auth) Authenticate(user, pass string) bool {
	return a.verify(user, pass)
}

func (a *Auth) CreateSession(user string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	a.mu.Lock()
	a.sessions[token] = sessionEntry{
		user:    user,
		expires: time.Now().Add(24 * time.Hour),
	}
	a.mu.Unlock()
	return token, nil
}

func (a *Auth) sessionUser(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("gwiki_session")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.sessions[cookie.Value]
	if !ok {
		return "", false
	}
	if time.Now().After(entry.expires) {
		delete(a.sessions, cookie.Value)
		return "", false
	}
	return entry.user, true
}

func (a *Auth) ClearSession(token string) {
	if token == "" {
		return
	}
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}
