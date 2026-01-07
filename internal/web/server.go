package web

import (
	"net/http"

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
	if s.auth != nil {
		return s.auth.Middleware(s.mux)
	}
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/search", s.handleSearch)
	s.mux.HandleFunc("/notes/new", s.handleNewNote)
	s.mux.HandleFunc("/notes/page", s.handleHomeNotesPage)
	s.mux.HandleFunc("/notes/", s.handleNotes)
	s.mux.HandleFunc("/tasks", s.handleTasks)
}
