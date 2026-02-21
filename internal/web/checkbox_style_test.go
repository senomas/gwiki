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

func TestCtrlSpaceShortcutSupportsBraveKeyVariants(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve test path")
	}
	basePath := filepath.Join(filepath.Dir(file), "..", "..", "templates", "base.html")
	baseContent, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("read base template: %v", err)
	}
	baseSource := string(baseContent)
	if !strings.Contains(baseSource, `key === "Unidentified" && code === "Space"`) {
		t.Fatalf("expected Brave ctrl+space key fallback in base template")
	}
	if !strings.Contains(baseSource, `code === "Space"`) {
		t.Fatalf("expected Space code fallback in base template")
	}

	editPath := filepath.Join(filepath.Dir(file), "..", "..", "templates", "note-edit-basic.html")
	editContent, err := os.ReadFile(editPath)
	if err != nil {
		t.Fatalf("read note-edit-basic template: %v", err)
	}
	editSource := string(editContent)
	if !strings.Contains(editSource, `key === "Unidentified" && code === "Space"`) {
		t.Fatalf("expected Brave ctrl+space key fallback in note-edit-basic template")
	}
	if !strings.Contains(editSource, `code === "Space"`) {
		t.Fatalf("expected Space code fallback in note-edit-basic template")
	}
}

func TestFloatingQuickLauncherButtonExists(t *testing.T) {
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
	if !strings.Contains(source, `id="floating-quick-launcher"`) {
		t.Fatalf("expected floating quick launcher button in base template")
	}
	if !strings.Contains(source, `data-quick-launcher="true"`) {
		t.Fatalf("expected floating quick launcher trigger attribute in base template")
	}
}
