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
	if got := noteHref("seno/notes/a.md", "seno"); got != "/notes/notes/a.md" {
		t.Fatalf("noteHref() current user=%q", got)
	}
	if got := noteHrefWithSuffix("seno/notes/a.md", "edit"); got != "/notes/@seno/notes/a.md/edit" {
		t.Fatalf("noteHrefWithSuffix()=%q", got)
	}
	if got := noteHrefWithSuffix("seno/notes/a.md", "edit", "seno"); got != "/notes/@seno/notes/a.md/edit" {
		t.Fatalf("noteHrefWithSuffix() current user=%q", got)
	}
	if got := noteHrefWithSuffix("seno/notes/a.md", "/edit"); got != "/notes/@seno/notes/a.md/edit" {
		t.Fatalf("noteHrefWithSuffix() with slash=%q", got)
	}
	if got := noteHrefWithSuffix("seno/notes/a.md", "delete", "seno"); got != "/notes/@seno/notes/a.md/delete" {
		t.Fatalf("noteHrefWithSuffix() delete current user=%q", got)
	}
	if got := noteHrefWithSuffix("seno/notes/a.md", "save", "seno"); got != "/notes/notes/a.md/save" {
		t.Fatalf("noteHrefWithSuffix() save current user=%q", got)
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

func TestParseNoteRefForUser(t *testing.T) {
	tests := []struct {
		in          string
		currentUser string
		want        string
		ok          bool
	}{
		{in: "@seno/notes/a.md", currentUser: "healing", want: "seno/notes/a.md", ok: true},
		{in: "notes/a.md", currentUser: "seno", want: "seno/notes/a.md", ok: true},
		{in: "/notes/a.md", currentUser: "seno", want: "seno/notes/a.md", ok: true},
		{in: "6f17a6cb-5307-4af8-accd-f734dc3f3f44", currentUser: "seno", want: "6f17a6cb-5307-4af8-accd-f734dc3f3f44", ok: true},
		{in: "notes/a.md", currentUser: "", ok: false},
	}
	for _, tt := range tests {
		got, ok := parseNoteRefForUser(tt.in, tt.currentUser)
		if ok != tt.ok || got != tt.want {
			t.Fatalf("parseNoteRefForUser(%q,%q)=(%q,%v) want (%q,%v)", tt.in, tt.currentUser, got, ok, tt.want, tt.ok)
		}
	}
}

func TestWikiLinkRefForTarget(t *testing.T) {
	tests := []struct {
		name        string
		sourceOwner string
		targetPath  string
		wantPath    string
		wantRef     string
		wantErr     bool
	}{
		{
			name:        "same owner uses local ref",
			sourceOwner: "seno",
			targetPath:  "seno/notes/a.md",
			wantPath:    "seno/notes/a.md",
			wantRef:     "notes/a.md",
		},
		{
			name:        "other owner uses explicit ref",
			sourceOwner: "seno",
			targetPath:  "healing/notes/a.md",
			wantPath:    "healing/notes/a.md",
			wantRef:     "@healing/notes/a.md",
		},
		{
			name:        "invalid path rejected",
			sourceOwner: "seno",
			targetPath:  "../etc/passwd",
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotRef, err := wikiLinkRefForTarget(tt.sourceOwner, tt.targetPath)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("wikiLinkRefForTarget error: %v", err)
			}
			if gotPath != tt.wantPath {
				t.Fatalf("wikiLinkRefForTarget path=%q want %q", gotPath, tt.wantPath)
			}
			if gotRef != tt.wantRef {
				t.Fatalf("wikiLinkRefForTarget ref=%q want %q", gotRef, tt.wantRef)
			}
		})
	}
}
