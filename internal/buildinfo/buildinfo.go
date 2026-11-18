// Package buildinfo identifies the running binary for journals and certificates.
package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

var hashOnce = sync.OnceValues(func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
})

// ExecutableHash is the SHA-256 of the running executable. Shunya's builds are
// reproducible (make repro), so the hash names the exact source and build flags:
// anyone can rebuild the tagged release and compare.
func ExecutableHash() (string, error) { return hashOnce() }
