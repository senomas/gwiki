package web

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

type sseHub struct {
	mu      sync.Mutex
	clients map[string]map[chan []byte]struct{}
}

func newSSEHub() *sseHub {
	return &sseHub{clients: make(map[string]map[chan []byte]struct{})}
}

func (h *sseHub) add(key string) chan []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan []byte, 8)
	if _, ok := h.clients[key]; !ok {
		h.clients[key] = make(map[chan []byte]struct{})
	}
	h.clients[key][ch] = struct{}{}
	return ch
}

func (h *sseHub) remove(key string, ch chan []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if chans, ok := h.clients[key]; ok {
		delete(chans, ch)
		if len(chans) == 0 {
			delete(h.clients, key)
		}
	}
	close(ch)
}

func (h *sseHub) broadcast(key string, data []byte) {
	h.mu.Lock()
	chans := h.clients[key]
	h.mu.Unlock()
	if len(chans) == 0 {
		return
	}
	for ch := range chans {
		select {
		case ch <- data:
		default:
		}
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	key := toastKey(r)
	if key == "" {
		key = "session:anonymous"
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.events.add(key)
	defer s.events.remove(key, ch)

	fmt.Fprint(w, "event: ready\ndata: ok\n\n")
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "event: toast\ndata: %s\n\n", msg)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}
