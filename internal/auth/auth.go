package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	defaultMemory     = 64 * 1024
	defaultIterations = 3
	defaultThreads    = 1
	defaultSaltLength = 16
	defaultKeyLength  = 32
)

type Argon2idHash struct {
	m    uint32
	t    uint32
	p    uint8
	salt []byte
	sum  []byte
}

func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password must not be empty")
	}
	salt := make([]byte, defaultSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	sum := argon2.IDKey([]byte(password), salt, defaultIterations, defaultMemory, defaultThreads, defaultKeyLength)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		defaultMemory,
		defaultIterations,
		defaultThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

func ParseArgon2idHash(phc string) (*Argon2idHash, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, errors.New("invalid argon2id hash format")
	}
	if parts[2] != "v=19" {
		return nil, fmt.Errorf("unsupported argon2id version: %s", parts[2])
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return nil, errors.New("invalid argon2id params")
	}
	var m uint64
	var t uint64
	var p uint64
	for _, param := range params {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			return nil, errors.New("invalid argon2id params")
		}
		switch kv[0] {
		case "m":
			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return nil, errors.New("invalid argon2id memory")
			}
			m = val
		case "t":
			val, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return nil, errors.New("invalid argon2id iterations")
			}
			t = val
		case "p":
			val, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil {
				return nil, errors.New("invalid argon2id parallelism")
			}
			p = val
		default:
			return nil, errors.New("invalid argon2id params")
		}
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, errors.New("invalid argon2id salt")
	}
	sum, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, errors.New("invalid argon2id hash")
	}
	return &Argon2idHash{
		m:    uint32(m),
		t:    uint32(t),
		p:    uint8(p),
		salt: salt,
		sum:  sum,
	}, nil
}

func (h *Argon2idHash) Verify(password string) bool {
	sum := argon2.IDKey([]byte(password), h.salt, h.t, h.m, h.p, uint32(len(h.sum)))
	return subtle.ConstantTimeCompare(sum, h.sum) == 1
}

func LoadFile(path string) (map[string]*Argon2idHash, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open auth file: %w", err)
	}
	defer f.Close()

	users := make(map[string]*Argon2idHash)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid auth line %d: expected user:hash", lineNum)
		}
		user := strings.TrimSpace(parts[0])
		hash := strings.TrimSpace(parts[1])
		if user == "" || hash == "" {
			return nil, fmt.Errorf("invalid auth line %d: empty user or hash", lineNum)
		}
		if _, exists := users[user]; exists {
			return nil, fmt.Errorf("duplicate user %q in auth file", user)
		}
		if !strings.HasPrefix(hash, "$argon2id$") {
			return nil, fmt.Errorf("invalid auth line %d: expected argon2id hash", lineNum)
		}
		parsed, err := ParseArgon2idHash(hash)
		if err != nil {
			return nil, fmt.Errorf("invalid auth line %d: %w", lineNum, err)
		}
		users[user] = parsed
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read auth file: %w", err)
	}

	return users, nil
}
