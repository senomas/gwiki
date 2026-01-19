package web

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"time"

	"gwiki/internal/config"
	"gwiki/internal/index"
	"gwiki/internal/storage/fs"
)

type Server struct {
	cfg    config.Config
	idx    *index.Index
	mux    *http.ServeMux
	locker *fs.Locker
	views  *Templates
	auth   *Auth
}

func NewServer(cfg config.Config, idx *index.Index) (*Server, error) {
	auth, err := newAuth(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		idx:    idx,
		mux:    http.NewServeMux(),
		locker: fs.NewLocker(),
		views:  MustParseTemplates(),
		auth:   auth,
	}
	embedCacheStore = idx

	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	var handler http.Handler
	if s.auth != nil {
		handler = s.auth.Middleware(s.mux)
	} else {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithUser(r.Context(), User{Name: "local", Authenticated: true})
			s.mux.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	return s.debugLogMiddleware(handler)
}

func (s *Server) debugLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const maxBodySize = 1024
		start := time.Now()
		var bodyPreview []byte
		if r.Body != nil && r.Body != http.NoBody {
			limited := io.LimitReader(r.Body, maxBodySize)
			bodyPreview, _ = io.ReadAll(limited)
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyPreview), r.Body))
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		elapsed := time.Since(start)

		slog.Debug(
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

func (s *Server) routes() {
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/logout", s.handleLogout)
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/search", s.handleSearch)
	s.mux.HandleFunc("/notes/new", s.handleNewNote)
	s.mux.HandleFunc("/notes/page", s.handleHomeNotesPage)
	s.mux.HandleFunc("/notes/", s.handleNotes)
	s.mux.HandleFunc("/daily/", s.handleDaily)
	s.mux.HandleFunc("/journal/year/", s.handleJournalYear)
	s.mux.HandleFunc("/journal/month/", s.handleJournalMonth)
	s.mux.HandleFunc("/attachments/", s.handleAttachmentFile)
	s.mux.HandleFunc("/assets/", s.handleAssetFile)
	s.mux.HandleFunc("/tags/suggest", s.handleTagSuggest)
	s.mux.HandleFunc("/tasks", s.handleTasks)
	s.mux.HandleFunc("/tasks/toggle", s.handleToggleTask)
}
