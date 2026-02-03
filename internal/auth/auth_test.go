package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("secret-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	parsed, err := ParseArgon2idHash(hash)
	if err != nil {
		t.Fatalf("ParseArgon2idHash: %v", err)
	}
	if !parsed.Verify("secret-password") {
		t.Fatal("expected password to verify")
	}
	if parsed.Verify("wrong-password") {
		t.Fatal("expected password to fail verification")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.txt")

	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	content := "# comment\n\nalice:" + hash + ":1900-01-01:admin, staff\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	users, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	entry, ok := users["alice"]
	if !ok {
		t.Fatal("expected user alice")
	}
	if !entry.Hash.Verify("secret") {
		t.Fatal("expected password to verify for alice")
	}
	if len(entry.Roles) != 2 || entry.Roles[0] != "admin" || entry.Roles[1] != "staff" {
		t.Fatalf("expected roles [admin staff], got %v", entry.Roles)
	}
}

func TestLoadFileDuplicateUser(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.txt")

	hash1, err := HashPassword("secret1")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	hash2, err := HashPassword("secret2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	content := "alice:" + hash1 + ":1900-01-01\nalice:" + hash2 + ":1900-01-01\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}

	if _, err := LoadFile(path); err == nil {
		t.Fatal("expected duplicate user error")
	}
}
