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
