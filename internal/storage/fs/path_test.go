package fs

import "testing"

func TestNormalizeNotePath(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		clean string
	}{
		{"note.md", true, "note.md"},
		{"dir/note.md", true, "dir/note.md"},
		{"../note.md", false, ""},
		{"/abs.md", false, ""},
		{"dir/../note.md", true, "note.md"},
		{"..", false, ""},
	}

	for _, c := range cases {
		got, err := NormalizeNotePath(c.in)
		if c.ok && err != nil {
			t.Fatalf("expected ok for %q, got %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("expected err for %q", c.in)
		}
		if c.ok && got != c.clean {
			t.Fatalf("expected %q -> %q, got %q", c.in, c.clean, got)
		}
	}
}
