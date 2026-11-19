package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/note"
	"shunya/internal/tilestore"
)

func runV(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String() + errb.String()
}

func TestLogKey(t *testing.T) {
	dir := t.TempDir()
	if code, out := runV(t, "log-key", "--origin", "example.org/log", "--out", dir); code != 0 || !strings.Contains(out, "example.org/log+") {
		t.Fatalf("%d %s", code, out)
	}
	st, err := os.Stat(filepath.Join(dir, "log.key"))
	if err != nil || (st.Mode().Perm() != 0o600 && os.PathSeparator == '/') {
		t.Fatalf("key file: %v %v", err, st)
	}
	if _, err := readSigner(filepath.Join(dir, "log.key")); err != nil {
		t.Fatal(err)
	}
	vk, _ := os.ReadFile(filepath.Join(dir, "log.vkey"))
	if _, err := note.ParseVerifierKey(string(vk)); err != nil {
		t.Fatal(err)
	}
	if code, out := runV(t, "log-key", "--origin", "example.org/log", "--out", dir); code != 1 {
		t.Fatalf("overwrote the key: %d %s", code, out)
	}
	if code, _ := runV(t, "log-key", "--origin", "bad name", "--out", t.TempDir()); code != 2 {
		t.Fatal("bad origin")
	}
}

func TestServeRefusesPublicAndCorruptLogs(t *testing.T) {
	if code, out := runV(t, "serve", "--dir", "d", "--log-key", "k", "--root", "r", "--revocations", "c", "--listen", "0.0.0.0:8080"); code != 2 || !strings.Contains(out, "not a loopback address") {
		t.Fatalf("%d %s", code, out)
	}
	for addr, ok := range map[string]bool{"127.0.0.1:1": true, "[::1]:1": true, "localhost:1": true, "10.0.0.1:1": false, ":8080": false} {
		if isLoopback(addr) != ok {
			t.Errorf("%s", addr)
		}
	}
}

// audit: first run saves the checkpoint; a later run proves consistency with it; a
// rewritten and re-signed log fails.
func TestAuditCommand(t *testing.T) {
	dir := t.TempDir()
	runV(t, "log-key", "--origin", "example.org/log", "--out", dir)
	s, _ := readSigner(filepath.Join(dir, "log.key"))
	vkey := filepath.Join(dir, "log.vkey")
	logDir := filepath.Join(dir, "log")
	l, err := tilestore.Create(logDir, s)
	if err != nil {
		t.Fatal(err)
	}
	l.Append([]byte{3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	state := filepath.Join(dir, "state")
	if code, out := runV(t, "audit", "--log", logDir, "--log-key", vkey, "--state", state); code != 0 || !strings.Contains(out, "first audit") {
		t.Fatalf("%d %s", code, out)
	}
	beacon := func(b byte) []byte { e := make([]byte, 33); e[0], e[1] = 3, b; return e }
	l.Append(beacon(7), beacon(8))
	if code, out := runV(t, "audit", "--log", logDir, "--log-key", vkey, "--state", state); code != 0 || !strings.Contains(out, "consistent with the checkpoint saved before (size 1)") {
		t.Fatalf("%d %s", code, out)
	}
	// The operator rewrites history with the same key.
	other := filepath.Join(dir, "rewritten")
	l2, _ := tilestore.Create(other, s)
	l2.Append(beacon(9), beacon(7), beacon(8))
	if code, out := runV(t, "audit", "--log", other, "--log-key", vkey, "--state", state); code != 1 || !strings.Contains(out, "AUDIT FAILED") || !strings.Contains(out, "not consistent") {
		t.Fatalf("%d %s", code, out)
	}
	// The failed audit leaves the saved state alone.
	if code, _ := runV(t, "audit", "--log", logDir, "--log-key", vkey, "--state", state, "--json"); code != 0 {
		t.Fatal("state was replaced by the failing audit")
	}
}
