package web

import "testing"

func TestNormalizeNoteRef(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "seno/notes/a.md", want: "seno/notes/a.md"},
		{in: "@seno/notes/a.md", want: "seno/notes/a.md"},
		{in: "/@seno/notes/a.md", want: "seno/notes/a.md"},
		{in: "notes/@seno/notes/a.md", want: "seno/notes/a.md"},
		{in: "  @seno/notes/a.md  ", want: "seno/notes/a.md"},
		{in: "6f17a6cb-5307-4af8-accd-f734dc3f3f44", want: "6f17a6cb-5307-4af8-accd-f734dc3f3f44"},
		{in: "@invalid", want: "@invalid"},
	}
	for _, tt := range tests {
		if got := normalizeNoteRef(tt.in); got != tt.want {
			t.Fatalf("normalizeNoteRef(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestNoteHref(t *testing.T) {
	if got := noteHref("seno/notes/a.md"); got != "/notes/@seno/notes/a.md" {
		t.Fatalf("noteHref()=%q", got)
	}
	if got := noteHrefWithSuffix("seno/notes/a.md", "edit"); got != "/notes/@seno/notes/a.md/edit" {
		t.Fatalf("noteHrefWithSuffix()=%q", got)
	}
	if got := noteHrefWithSuffix("seno/notes/a.md", "/edit"); got != "/notes/@seno/notes/a.md/edit" {
		t.Fatalf("noteHrefWithSuffix() with slash=%q", got)
	}
}

func TestParseUserScopedNoteRef(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "@seno/notes/a.md", want: "seno/notes/a.md", ok: true},
		{in: "/@seno/notes/a.md", want: "seno/notes/a.md", ok: true},
		{in: "notes/@seno/notes/a.md", want: "seno/notes/a.md", ok: true},
		{in: "seno/notes/a.md", ok: false},
		{in: "6f17a6cb-5307-4af8-accd-f734dc3f3f44", ok: false},
	}
	for _, tt := range tests {
		got, ok := parseUserScopedNoteRef(tt.in)
		if ok != tt.ok || got != tt.want {
			t.Fatalf("parseUserScopedNoteRef(%q)=(%q,%v) want (%q,%v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
