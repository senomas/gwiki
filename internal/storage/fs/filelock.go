package fs

import (
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type FileLock struct {
	path string
	file *os.File
}

func AcquireFileLock(path string) (*FileLock, error) {
	return AcquireFileLockWithTimeout(path, 0)
}

func AcquireFileLockWithTimeout(path string, timeout time.Duration) (*FileLock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
			_ = file.Close()
			return nil, err
		}
		return &FileLock{path: path, file: file}, nil
	}
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			_ = file.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, os.ErrDeadlineExceeded
		}
		time.Sleep(50 * time.Millisecond)
	}
	return &FileLock{path: path, file: file}, nil
}

func (l *FileLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	if err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN); err != nil {
		_ = l.file.Close()
		return err
	}
	return l.file.Close()
}
