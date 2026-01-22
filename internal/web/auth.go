package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gwiki/internal/auth"
	"gwiki/internal/config"
	"gwiki/internal/index"
)

type authEntry struct {
	plain string
	hash  *auth.Argon2idHash
	roles []string
}

type Auth struct {
	users  map[string]authEntry
	secret []byte
}

func newAuth(cfg config.Config) (*Auth, error) {
	users := make(map[string]authEntry)

	if cfg.AuthFile != "" {
		fileUsers, err := auth.LoadFile(cfg.AuthFile)
		if err != nil {
			return nil, err
		}
		for user, entry := range fileUsers {
			users[user] = authEntry{hash: entry.Hash, roles: entry.Roles}
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

	secret, err := authSecret(cfg)
	if err != nil {
		return nil, err
	}
	return &Auth{
		users:  users,
		secret: secret,
	}, nil
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, ok := a.tokenUser(r); ok {
			ctx := WithUser(r.Context(), User{Name: user, Authenticated: true, Roles: a.rolesForUser(user)})
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

func (a *Auth) rolesForUser(user string) []string {
	entry, ok := a.users[user]
	if !ok || len(entry.roles) == 0 {
		return nil
	}
	out := make([]string, len(entry.roles))
	copy(out, entry.roles)
	return out
}

func (a *Auth) CreateToken(user string) (string, error) {
	claims := jwtClaims{
		Sub: user,
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(24 * time.Hour).Unix(),
	}
	return signJWT(claims, a.secret)
}

func (a *Auth) tokenUser(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("gwiki_session")
	if err != nil || cookie.Value == "" {
		return "", false
	}
	claims, err := parseJWT(cookie.Value, a.secret)
	if err != nil {
		return "", false
	}
	if claims.Exp <= time.Now().Unix() {
		return "", false
	}
	if strings.TrimSpace(claims.Sub) == "" {
		return "", false
	}
	return claims.Sub, true
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func authSecret(cfg config.Config) ([]byte, error) {
	if v := os.Getenv("WIKI_AUTH_SECRET"); v != "" {
		return []byte(v), nil
	}
	if cfg.AuthFile == "" {
		return nil, errors.New("WIKI_AUTH_SECRET or WIKI_AUTH_FILE required for JWT auth")
	}
	data, err := os.ReadFile(cfg.AuthFile)
	if err != nil {
		return nil, fmt.Errorf("read auth file for jwt secret: %w", err)
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

func signJWT(claims jwtClaims, secret []byte) (string, error) {
	header := `{"alg":"HS256","typ":"JWT"}`
	headerEnc := base64.RawURLEncoding.EncodeToString([]byte(header))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payloadEnc := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := headerEnc + "." + payloadEnc
	sig := hmacSHA256([]byte(signingInput), secret)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigEnc, nil
}

func parseJWT(token string, secret []byte) (jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return jwtClaims{}, errors.New("invalid token format")
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return jwtClaims{}, errors.New("invalid token signature")
	}
	expected := hmacSHA256([]byte(signingInput), secret)
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return jwtClaims{}, errors.New("invalid token signature")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, errors.New("invalid token payload")
	}
	var claims jwtClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return jwtClaims{}, errors.New("invalid token payload")
	}
	return claims, nil
}

func hmacSHA256(input, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(input)
	return mac.Sum(nil)
}
