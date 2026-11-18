package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shunya/internal/journal"
	"shunya/internal/keys"
)

type rootFixture struct {
	dir, pass, key, pub, crl, stationCert string
}

// newRoot runs init-root and certifies f's station key.
func newRoot(t *testing.T, f fixture) rootFixture {
	t.Helper()
	r := rootFixture{dir: filepath.Join(f.dir, "root"), pass: filepath.Join(f.dir, "pass")}
	r.key, r.pub, r.crl = filepath.Join(r.dir, "root.key"), filepath.Join(r.dir, "root.pub"), filepath.Join(r.dir, "revocations.json")
	r.stationCert = filepath.Join(f.dir, "station.cert.json")
	os.WriteFile(r.pass, []byte("a long enough passphrase\n"), 0o600)
	if code, out, errs := runCLI(t, "keys", "init-root", "--passphrase-file", r.pass, r.dir); code != 0 || !strings.Contains(out, "root key id: ed25519:") {
		t.Fatalf("init-root: %d %s %s", code, out, errs)
	}
	if code, _, errs := runCLI(t, "keys", "init-root", "--passphrase-file", r.pass, r.dir); code != 1 || !strings.Contains(errs, "refusing to replace") {
		t.Fatalf("second init-root: %d %s", code, errs)
	}
	if code, out, errs := runCLI(t, "keys", "issue-station", "--root", r.key, "--station-key", f.key, "--name", "bay-1",
		"--out", r.stationCert, "--passphrase-file", r.pass); code != 0 || !strings.Contains(out, `certified station "bay-1"`) {
		t.Fatalf("issue-station: %d %s %s", code, out, errs)
	}
	return r
}

func (r rootFixture) verify(t *testing.T, extra ...string) (int, string) {
	t.Helper()
	args := append([]string{"cert", "show", "--root", r.pub, "--revocations", r.crl}, extra...)
	code, out, errs := runCLI(t, args...)
	return code, out + errs
}

func TestCertificateEndToEnd(t *testing.T) {
	f := newFixture(t, 1<<20+3*512)
	r := newRoot(t, f)
	if code, out, _ := runCLI(t, "keys", "show", "--root", r.pub, r.stationCert); code != 0 || !strings.Contains(out, "verified against root") {
		t.Fatalf("keys show: %s", out)
	}
	code, out, errs := runCLI(t, "wipe", "--execute", "--verify", "--image", f.img, "--journal", f.journal, "--key", f.key, "--station-cert", r.stationCert)
	if code != 0 || !strings.Contains(out, "CERTIFICATE ") {
		t.Fatalf("wipe: %d\n%s\n%s", code, out, errs)
	}
	cj, cp := f.journal+".cert.json", f.journal+".cert.pdf"
	code, out = r.verify(t, "--pdf", cp, cj)
	for _, want := range []string{"VALID certificate", "overwrite, NIST SP 800-88 CLEAR", "station bay-1", "not revoked in list 1", "is exactly this certificate's rendering"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("verify lacks %q: %d\n%s", want, code, out)
		}
	}
	// The JSON names the binary that wiped.
	raw, _ := os.ReadFile(cj)
	if !strings.Contains(string(raw), `"wipe_build_hash":"`) || strings.Contains(string(raw), `"wipe_build_hash":""`) {
		t.Error("wipe build hash missing")
	}
	// An edited PDF, an edited certificate, the wrong root: refused.
	pdf, _ := os.ReadFile(cp)
	edited := filepath.Join(f.dir, "edited.pdf")
	os.WriteFile(edited, bytes.Replace(pdf, []byte("CLEAR"), []byte("PURGE"), 1), 0o644)
	if code, out := r.verify(t, "--pdf", edited, cj); code != 1 || !strings.Contains(out, "not this certificate's rendering") {
		t.Errorf("edited PDF: %d %s", code, out)
	}
	bad := filepath.Join(f.dir, "bad.json")
	os.WriteFile(bad, bytes.Replace(raw, []byte(`"nist_level":"clear"`), []byte(`"nist_level":"purge"`), 1), 0o644)
	if code, out := r.verify(t, bad); code != 1 || !strings.Contains(out, "INVALID") {
		t.Errorf("edited certificate: %d %s", code, out)
	}
	if code, out, _ := runCLI(t, "cert", "show", "--root", strings.Repeat("ab", 32), "--revocations", r.crl, cj); code != 1 {
		t.Errorf("wrong root: %d %s", code, out)
	}
	if code, out, _ := runCLI(t, "cert", "show", "--root", r.pub, cj); code != 1 || !strings.Contains(out, "no revocation list") {
		t.Errorf("no revocation list: %d %s", code, out)
	}
	// cert pdf re-renders the identical PDF from the JSON.
	again := filepath.Join(f.dir, "again.pdf")
	if code, _, errs := runCLI(t, "cert", "pdf", "--root", r.pub, "--revocations", r.crl, "--out", again, cj); code != 0 {
		t.Fatal(errs)
	}
	if b, _ := os.ReadFile(again); !bytes.Equal(b, pdf) {
		t.Error("re-rendered PDF differs")
	}

	// Revocation. Retire the station an hour from now: this certificate stands.
	stationID := keyID(t, f.key)
	at := keys.FormatTime(time.Now().Add(time.Hour))
	if code, _, errs := runCLI(t, "keys", "revoke", "--root", r.key, "--revocations", r.crl, "--key-id", stationID,
		"--reason", "retired", "--at", at, "--note", "bay closed", "--passphrase-file", r.pass); code != 0 {
		t.Fatal(errs)
	}
	if code, out := r.verify(t, cj); code != 0 || !strings.Contains(out, "list 2") {
		t.Errorf("issued before retirement: %d %s", code, out)
	}
	// A certificate the station issues after the retirement time fails.
	defer func(n func() time.Time) { now = n }(now)
	now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	late := filepath.Join(f.dir, "late.json")
	if code, _, errs := runCLI(t, "cert", "issue", "--journal", f.journal, "--key", f.key, "--station-cert", r.stationCert,
		"--out", late, "--pdf", late+".pdf"); code != 0 {
		t.Fatal(errs)
	}
	if code, out := r.verify(t, late); code != 1 || !strings.Contains(out, "retired") {
		t.Errorf("issued after retirement: %d %s", code, out)
	}
	// Compromised: every certificate of the station fails, whatever its date.
	if code, _, errs := runCLI(t, "keys", "revoke", "--root", r.key, "--revocations", r.crl, "--key-id", stationID,
		"--reason", "compromised", "--passphrase-file", r.pass); code != 0 {
		t.Fatal(errs)
	}
	if code, out := r.verify(t, cj); code != 1 || !strings.Contains(out, "compromised") {
		t.Errorf("compromised: %d %s", code, out)
	}
	if code, out, _ := runCLI(t, "keys", "show", "--root", r.pub, r.crl); code != 0 || !strings.Contains(out, "revocation list 3") || !strings.Contains(out, "compromised") {
		t.Errorf("keys show list: %s", out)
	}
	// Wrong passphrase.
	wrong := filepath.Join(f.dir, "wrong")
	os.WriteFile(wrong, []byte("not the passphrase"), 0o600)
	if code, _, errs := runCLI(t, "keys", "revoke", "--root", r.key, "--revocations", r.crl, "--key-id", "ed25519:0000000000000000",
		"--reason", "retired", "--passphrase-file", wrong); code != 1 || !strings.Contains(errs, "wrong passphrase") {
		t.Errorf("wrong passphrase: %d %s", code, errs)
	}
}

func keyID(t *testing.T, path string) string {
	k, err := journal.LoadKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return journal.KeyID(k.Public().(ed25519.PublicKey))
}

func TestCertificateDevKeyAndRefusals(t *testing.T) {
	f := newFixture(t, 1<<20)
	// Without --verify there is nothing to certify: the wipe still succeeds and says so.
	r := newRoot(t, f)
	code, out, errs := runCLI(t, "wipe", "--execute", "--image", f.img, "--journal", f.journal, "--key", f.key, "--station-cert", r.stationCert)
	if code != 0 || !strings.Contains(out, "No certificate") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	if code, _, errs := runCLI(t, "cert", "issue", "--journal", f.journal, "--key", f.key); code != 4 || !strings.Contains(errs, "no verification") {
		t.Fatalf("unverified: %d %s", code, errs)
	}
	if code, _, errs := runCLI(t, "verify", "--journal", f.journal, "--key", f.key); code != 0 {
		t.Fatal(errs)
	}
	// Dev-key certificate (no --station-cert): issued, marked, refused unless allowed.
	code, out, errs = runCLI(t, "cert", "issue", "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(out, "uncertified station key") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	cj := f.journal + ".cert.json"
	if code, out := r.verify(t, cj); code != 1 || !strings.Contains(out, "uncertified development key") {
		t.Errorf("dev key accepted: %d %s", code, out)
	}
	if code, out := r.verify(t, "--allow-dev-key", "--pdf", f.journal+".cert.pdf", cj); code != 0 || !strings.Contains(out, "WARNING") || !strings.Contains(out, "UNCERTIFIED") {
		t.Errorf("--allow-dev-key: %d %s", code, out)
	}
	// Existing certificate files are not overwritten.
	if code, _, errs := runCLI(t, "cert", "issue", "--journal", f.journal, "--key", f.key); code != 1 || !strings.Contains(errs, "exists") {
		t.Errorf("overwrite: %d %s", code, errs)
	}
	// A short passphrase is refused at init.
	short := filepath.Join(f.dir, "short")
	os.WriteFile(short, []byte("short"), 0o600)
	if code, _, errs := runCLI(t, "keys", "init-root", "--passphrase-file", short, filepath.Join(f.dir, "r2")); code != 1 || !strings.Contains(errs, "12 characters") {
		t.Errorf("short passphrase: %d %s", code, errs)
	}
}
