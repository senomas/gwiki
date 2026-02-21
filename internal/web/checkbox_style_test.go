package web

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheckboxStylesScopedToDirectChildren(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve test path")
	}
	basePath := filepath.Join(filepath.Dir(file), "..", "..", "templates", "base.html")
	content, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("read base template: %v", err)
	}
	source := string(content)
	if !strings.Contains(source, "li:has(> input[type=\"checkbox\"])") {
		t.Fatalf("expected scoped checkbox selector for direct input")
	}
	if !strings.Contains(source, "li:has(> p > input[type=\"checkbox\"])") {
		t.Fatalf("expected scoped checkbox selector for paragraph input")
	}
}

func TestQuickLauncherTouchDoubleTapSupport(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve test path")
	}
	basePath := filepath.Join(filepath.Dir(file), "..", "..", "templates", "base.html")
	content, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("read base template: %v", err)
	}
	source := string(content)
	if !strings.Contains(source, `document.addEventListener("pointerup"`) {
		t.Fatalf("expected pointerup touch double-tap listener in base template")
	}
	if !strings.Contains(source, `document.addEventListener("touchend"`) {
		t.Fatalf("expected touchend fallback listener in base template")
	}
	if strings.Contains(source, `if (closestEventTarget(target, "[data-note-list]"))`) {
		t.Fatalf("expected note-list safe-area block to be removed from double-click guard")
	}
}
