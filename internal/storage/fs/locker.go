package fs

import "sync"

type Locker struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func NewLocker() *Locker {
	return &Locker{locks: make(map[string]*sync.Mutex)}
}

func (l *Locker) Lock(path string) func() {
	l.mu.Lock()
	m, ok := l.locks[path]
	if !ok {
		m = &sync.Mutex{}
		l.locks[path] = m
	}
	l.mu.Unlock()

	m.Lock()
	return func() {
		m.Unlock()
	}
}
