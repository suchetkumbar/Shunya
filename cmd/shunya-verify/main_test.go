package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The verification itself is internal/certcheck (tested end to end through "shunya
// cert show" in cmd/shunya, and with this binary in the lab); here: the command line.
func TestUsageAndFailures(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "usage: shunya-verify") {
		t.Errorf("no args: %d %s", code, errb.String())
	}
	dir := t.TempDir()
	junk := filepath.Join(dir, "c.json")
	os.WriteFile(junk, []byte("{}\n"), 0o644)
	out.Reset()
	if code := run([]string{"--root", strings.Repeat("ab", 32), "--no-revocation-check", junk}, &out, &errb); code != 1 || !strings.HasPrefix(out.String(), "INVALID:") {
		t.Errorf("junk: %d %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"--json", "--root", strings.Repeat("ab", 32), "--no-revocation-check", junk}, &out, &errb); code != 1 {
		t.Errorf("json: %d", code)
	}
	var m map[string]any
	if err := json.Unmarshal(out.Bytes(), &m); err != nil || m["valid"] != false || m["error"] == "" {
		t.Errorf("json output %s", out.String())
	}
	out.Reset()
	if code := run([]string{"--no-revocation-check", junk}, &out, &errb); code != 1 || !strings.Contains(out.String(), "--root is required") {
		t.Errorf("no root: %d %s", code, out.String())
	}
}
