package web

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"gwiki/internal/auth"
	"gwiki/internal/config"
	"gwiki/internal/index"
)

type authEntry struct {
	plain string
	hash  *auth.Argon2idHash
}

type Auth struct {
	users map[string]authEntry
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

	return &Auth{users: users}, nil
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
