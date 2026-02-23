package web

import "testing"

func TestNoteTagBasePathForRequestPath(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		want  string
		match bool
	}{
		{name: "note detail local shorthand", path: "/notes/demo.md", want: "/", match: true},
		{name: "note detail local detail fragment", path: "/notes/demo.md/detail", want: "/", match: true},
		{name: "note detail owner scoped", path: "/notes/@alice/dev/demo.md", want: "/@alice", match: true},
		{name: "note detail owner scoped detail fragment", path: "/notes/@alice/dev/demo.md/detail", want: "/@alice", match: true},
		{name: "todo list", path: "/todo", want: "", match: false},
		{name: "completed list", path: "/completed", want: "", match: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := noteTagBasePathForRequestPath(tt.path)
			if got != tt.want || ok != tt.match {
				t.Fatalf("noteTagBasePathForRequestPath(%q)=(%q,%v) want (%q,%v)", tt.path, got, ok, tt.want, tt.match)
			}
		})
	}
}

func TestSidebarBasePathKeepsListPagesAndMapsNotes(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "/todo", want: "/todo"},
		{path: "/completed", want: "/completed"},
		{path: "/archived", want: "/archived"},
		{path: "/archived/@local/tasks.md", want: "/archived"},
		{path: "/daily", want: "/daily"},
		{path: "/daily/2026-02-21", want: "/daily/2026-02-21"},
		{path: "/notes/demo.md", want: "/"},
		{path: "/notes/@local/demo.md", want: "/@local"},
	}
	for _, tt := range tests {
		if got := sidebarBasePath(tt.path); got != tt.want {
			t.Fatalf("sidebarBasePath(%q)=%q want %q", tt.path, got, tt.want)
		}
	}
}
