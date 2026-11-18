package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

// keyFileHeader marks a station key file. Whether the key is trusted is not a property
// of the file: a station key is trusted once the organisation's root certifies it
// (shunya keys issue-station, Milestone 7). Files written by Milestones 3–6 carry
// legacyKeyFileHeader and still load.
const (
	keyFileHeader       = "shunya-station-key-v1"
	legacyKeyFileHeader = "shunya-dev-station-key-v1"
)

// GenerateKeyFile creates a new Ed25519 station key at path (mode 0600, never
// overwriting) and returns its public key.
func GenerateKeyFile(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	line := keyFileHeader + " " + base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	return pub, f.Close()
}

// LoadKeyFile reads a station key. On Unix it refuses a key readable by group or others.
func LoadKeyFile(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key %s: permissions %v are too open (want 0600)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	head, enc, ok := strings.Cut(string(bytes.TrimSpace(b)), " ")
	if !ok || (head != keyFileHeader && head != legacyKeyFileHeader) {
		return nil, fmt.Errorf("key %s: not a %s file", path, keyFileHeader)
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(enc)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("key " + path + ": malformed seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
