package index

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

var buildVersion string

func SetBuildVersion(version string) {
	buildVersion = strings.TrimSpace(version)
}

func ContentHash(content []byte) string {
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	if buildVersion == "" {
		return hash
	}
	return "v=" + buildVersion + ";" + hash
}

func hashMatchesBuildVersion(hash string) bool {
	if buildVersion == "" {
		return true
	}
	if !strings.HasPrefix(hash, "v=") {
		return false
	}
	trimmed := strings.TrimPrefix(hash, "v=")
	parts := strings.SplitN(trimmed, ";", 2)
	if len(parts) != 2 {
		return false
	}
	return parts[0] == buildVersion
}
