package web

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/index"
	"gwiki/internal/storage/fs"
)

type Server struct {
	cfg     config.Config
	idx     *index.Index
	mux     *http.ServeMux
	locker  *fs.Locker
	views   *Templates
	auth    *Auth
	toasts  *toastStore
	events  *sseHub
	apiKeys map[string]apiKeyEntry
}

func NewServer(cfg config.Config, idx *index.Index) (*Server, error) {
	auth, err := newAuth(cfg)
	if err != nil {
		return nil, err
	}
	apiKeys, err := loadAPIKeys(cfg.DataPath)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		idx:     idx,
		mux:     http.NewServeMux(),
		locker:  fs.NewLocker(),
		views:   MustParseTemplates(),
		auth:    auth,
		toasts:  newToastStore(),
		events:  newSSEHub(),
		apiKeys: apiKeys,
	}
	embedCacheStore = idx

	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	var base http.Handler = s.mux
	base = s.apiAuthMiddleware(base)
	base = s.accessContextMiddleware(base)
	var handler http.Handler
	if s.auth != nil {
		handler = s.auth.Middleware(base)
	} else {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithUser(r.Context(), User{Name: "local", Authenticated: true})
			base.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	return s.debugLogMiddleware(handler)
}

func (s *Server) accessContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if IsAuthenticated(ctx) {
			user, ok := CurrentUser(ctx)
			if ok && strings.TrimSpace(user.Name) != "" {
				userID, err := s.idx.AccessFilterForUser(ctx, user.Name)
				if err != nil {
					if _, ensureErr := s.idx.EnsureUser(ctx, user.Name); ensureErr == nil {
						userID, err = s.idx.AccessFilterForUser(ctx, user.Name)
					}
				}
				if err == nil && userID > 0 {
					ctx = index.WithAccessFilter(ctx, userID)
				}
			}
		} else {
			ctx = index.WithPublicVisibility(ctx)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) apiAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		user, err := s.apiUserForRequest(r)
		if err != nil {
			writeAPIError(w, err.status, err.message)
			return
		}
		if user.Name == "" {
			writeAPIError(w, http.StatusUnauthorized, "missing api key")
			return
		}
		ctx := WithUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type apiAuthError struct {
	status  int
	message string
}

func (s *Server) apiUserForRequest(r *http.Request) (User, *apiAuthError) {
	if len(s.apiKeys) == 0 {
		return User{}, &apiAuthError{status: http.StatusUnauthorized, message: "api keys not configured"}
	}
	key := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if key == "" {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			key = strings.TrimSpace(authHeader[7:])
		}
	}
	if key == "" {
		return User{}, &apiAuthError{status: http.StatusUnauthorized, message: "missing api key"}
	}
	entry, ok := s.apiKeys[key]
	if !ok {
		return User{}, &apiAuthError{status: http.StatusUnauthorized, message: "invalid api key"}
	}
	if apiKeyExpired(entry, time.Now()) {
		return User{}, &apiAuthError{status: http.StatusUnauthorized, message: "api key expired"}
	}
	if _, err := s.idx.EnsureUser(r.Context(), entry.Alias); err != nil {
		return User{}, &apiAuthError{status: http.StatusInternalServerError, message: err.Error()}
	}
	return User{
		Name:          entry.Alias,
		Authenticated: true,
	}, nil
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"`+jsonEscape(message)+`"}`)
}

func writeAPIJSON(w http.ResponseWriter, status int, payload interface{}) {
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func jsonEscape(input string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return replacer.Replace(input)
}

func (s *Server) debugLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const maxBodySize = 1024
		start := time.Now()
		slog.Debug(
			"http request start",
			"method", r.Method,
			"url", r.URL.String(),
			"headers", r.Header,
		)
		var bodyPreview []byte
		if r.Body != nil && r.Body != http.NoBody {
			limited := io.LimitReader(r.Body, maxBodySize)
			bodyPreview, _ = io.ReadAll(limited)
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyPreview), r.Body))
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		elapsed := time.Since(start)

		level := slog.LevelDebug
		if rec.status >= http.StatusBadRequest {
			level = slog.LevelWarn
		}
		slog.Log(
			r.Context(),
			level,
			"http request",
			"method", r.Method,
			"url", r.URL.String(),
			"status", rec.status,
			"duration_ms", elapsed.Milliseconds(),
			"headers", r.Header,
			"body", string(bodyPreview),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(p)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/password/change", s.handlePasswordChange)
	s.mux.HandleFunc("/logout", s.handleLogout)
	s.mux.HandleFunc("/events", s.handleEvents)
	s.mux.HandleFunc("/toast", s.handleToastList)
	s.mux.HandleFunc("/toast/", s.handleToastDismiss)
	s.mux.HandleFunc("/settings", s.handleSettings)
	s.mux.HandleFunc("/settings/save", s.handleSettingsSave)
	s.mux.HandleFunc("/settings/remotes/add", s.handleSettingsRemoteAdd)
	s.mux.HandleFunc("/settings/remotes/remove", s.handleSettingsRemoteRemove)
	s.mux.HandleFunc("/settings/users/create", s.handleSettingsUserCreate)
	s.mux.HandleFunc("/settings/users/delete", s.handleSettingsUserDelete)
	s.mux.HandleFunc("/sidebar", s.handleSidebar)
	s.mux.HandleFunc("/calendar", s.handleCalendar)
	s.mux.HandleFunc("/calendar-skeleton", s.handleCalendarSkeleton)
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/search", s.handleSearch)
	s.mux.HandleFunc("/notes/new", s.handleNewNote)
	s.mux.HandleFunc("/notes/page", s.handleHomeNotesPage)
	s.mux.HandleFunc("/notes/section", s.handleHomeNotesSection)
	s.mux.HandleFunc("/notes/", s.handleNotes)
	s.mux.HandleFunc("/daily/", s.handleDaily)
	s.mux.HandleFunc("/journal/year/", s.handleJournalYear)
	s.mux.HandleFunc("/journal/month/", s.handleJournalMonth)
	s.mux.HandleFunc("/sync/run", s.handleSyncRun)
	s.mux.HandleFunc("/sync/", s.handleSyncUser)
	s.mux.HandleFunc("/favicon.ico", s.handleFavicon)
	s.mux.HandleFunc("/static/", s.handleStaticFile)
	s.mux.HandleFunc("/attachments/", s.handleAttachmentFile)
	s.mux.HandleFunc("/assets/", s.handleAssetFile)
	s.mux.HandleFunc("/tags/suggest", s.handleTagSuggest)
	s.mux.HandleFunc("/users/suggest", s.handleUserSuggest)
	s.mux.HandleFunc("/tasks", s.handleTasks)
	s.mux.HandleFunc("/todo/page", s.handleTodoPage)
	s.mux.HandleFunc("/todo", s.handleTodo)
	s.mux.HandleFunc("/broken", s.handleBroken)
	s.mux.HandleFunc("/quick/notes", s.handleQuickNotes)
	s.mux.HandleFunc("/quick/launcher", s.handleQuickLauncher)
	s.mux.HandleFunc("/quick/edit-actions", s.handleQuickEditActions)
	s.mux.HandleFunc("/api/notes", s.handleAPINotes)
	s.mux.HandleFunc("/sync", s.handleSync)
	s.mux.HandleFunc("/tasks/toggle", s.handleToggleTask)
	s.mux.HandleFunc("/rebuild", s.handleRebuild)
}
