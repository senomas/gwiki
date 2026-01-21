package web

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type Toast struct {
	ID              string
	Message         string
	Kind            string
	DurationSeconds int
	CreatedAt       time.Time
}

type toastStore struct {
	mu     sync.Mutex
	byUser map[string][]Toast
}

func newToastStore() *toastStore {
	return &toastStore{byUser: make(map[string][]Toast)}
}

func (s *toastStore) Add(key string, toast Toast) {
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byUser[key] = append(s.byUser[key], toast)
}

func (s *toastStore) List(key string) []Toast {
	if key == "" {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	toasts := s.byUser[key]
	if len(toasts) == 0 {
		return nil
	}
	active := toasts[:0]
	for _, toast := range toasts {
		if toast.DurationSeconds > 0 {
			exp := toast.CreatedAt.Add(time.Duration(toast.DurationSeconds) * time.Second)
			if now.After(exp) {
				continue
			}
		}
		active = append(active, toast)
	}
	if len(active) == 0 {
		delete(s.byUser, key)
		return nil
	}
	out := make([]Toast, len(active))
	copy(out, active)
	s.byUser[key] = active
	return out
}

func (s *toastStore) Remove(key, id string) {
	if key == "" || id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	toasts := s.byUser[key]
	if len(toasts) == 0 {
		return
	}
	next := toasts[:0]
	for _, toast := range toasts {
		if toast.ID == id {
			continue
		}
		next = append(next, toast)
	}
	if len(next) == 0 {
		delete(s.byUser, key)
		return
	}
	s.byUser[key] = next
}

func toastKey(r *http.Request) string {
	if user, ok := CurrentUser(r.Context()); ok && strings.TrimSpace(user.Name) != "" {
		return "user:" + strings.TrimSpace(user.Name)
	}
	if cookie, err := r.Cookie("gwiki_session"); err == nil && cookie.Value != "" {
		return "session:" + cookie.Value
	}
	return ""
}

func (s *Server) addToast(r *http.Request, toast Toast) {
	s.toasts.Add(toastKey(r), toast)
}
