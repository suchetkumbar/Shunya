package main

import (
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/cert"
	"shunya/internal/keys"
	"shunya/internal/logserver"
	"shunya/internal/note"
	"shunya/internal/tilestore"
)

type testLog struct {
	srv       *httptest.Server
	vkey, dir string
	signer    *note.Signer
	root      rootFixture
}

func startLog(t *testing.T, r rootFixture, dir string, s *note.Signer) *testLog {
	t.Helper()
	var l *tilestore.Log
	var err error
	if _, e := os.Stat(filepath.Join(dir, "checkpoint")); e == nil {
		l, err = tilestore.Load(dir, s, nil)
	} else {
		l, err = tilestore.Create(dir, s)
	}
	if err != nil {
		t.Fatal(err)
	}
	pubText, _ := os.ReadFile(r.pub)
	root, err := keys.ParsePublic(string(pubText))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(r.crl)
	crl, err := keys.ParseRevocationList(raw, ed25519.PublicKey(root))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := logserver.New(logserver.Config{Log: l, Dir: dir, LogKey: &s.Verifier, Policy: cert.Policy{Root: root, Revocations: &crl},
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), Rate: 1000})
	if err != nil {
		t.Fatal(err)
	}
	tl := &testLog{srv: httptest.NewServer(srv.Handler()), dir: dir, signer: s, root: r, vkey: filepath.Join(filepath.Dir(dir), "log.vkey")}
	os.WriteFile(tl.vkey, []byte(s.VerifierKey()+"\n"), 0o644)
	t.Cleanup(tl.srv.Close)
	return tl
}

func TestLogSeededWipeEndToEnd(t *testing.T) {
	f := newFixture(t, 1<<20+3*512)
	r := newRoot(t, f)
	skey, _, _ := note.GenerateKey("127.0.0.1/log")
	s, _ := note.ParseSignerKey(skey)
	lg := startLog(t, r, filepath.Join(f.dir, "log"), s)

	code, out, errs := runCLI(t, "wipe", "--execute", "--sample", "64", "--log", lg.srv.URL, "--log-key", lg.vkey,
		"--image", f.img, "--journal", f.journal, "--key", f.key, "--station-cert", r.stationCert)
	for _, want := range []string{"VERIFIED (sampled) 64 sectors from a seed from the transparency log", "seed: log entry 0", "CERTIFICATE ", "LOGGED ", "as entry 2"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("wipe output lacks %q: %d\n%s\n%s", want, code, out, errs)
		}
	}
	cj := f.journal + ".cert.json"
	code, out = r.verify(t, "--log-key", lg.vkey, "--require-log", "--pdf", f.journal+".cert.pdf", cj)
	for _, want := range []string{"VALID certificate", "logged       entry 2 in log 127.0.0.1/log", "proof verified", "seed from the transparency log (request entry 0)", "exactly this certificate's rendering"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("cert show lacks %q: %d\n%s", want, code, out)
		}
	}
	raw, _ := os.ReadFile(cj)
	if !strings.Contains(string(raw), `"verify_url":"`+lg.srv.URL+`/c/"`) {
		t.Fatal("verify URL is not the log's page")
	}
	// The QR target: the log's recycler page shows VALID.
	res, err := cert.Verify(raw, cert.Policy{Root: mustRoot(t, r), SkipRevocation: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(lg.srv.URL + "/c/" + res.ID)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(page), ">VALID<") {
		t.Fatalf("page:\n%s", page)
	}
	// Without the log key: valid, but the log proof and seed checkpoint are reported unchecked.
	if code, out := r.verify(t, cj); code != 0 || !strings.Contains(out, "proof NOT checked") {
		t.Fatalf("%d %s", code, out)
	}
	// --require-log without the key, or another log's key: refused.
	other, _, _ := note.GenerateKey("127.0.0.1/log")
	os2, _ := note.ParseSignerKey(other)
	otherV := filepath.Join(f.dir, "other.vkey")
	os.WriteFile(otherV, []byte(os2.VerifierKey()), 0o644)
	if code, out := r.verify(t, "--log-key", otherV, cj); code != 1 {
		t.Fatalf("other log key: %d %s", code, out)
	}

	// Offline: the log is down. Default fallback: full read-back, certificate unlogged.
	lg.srv.Close()
	j2 := filepath.Join(f.dir, "j2.journal")
	code, out, errs = runCLI(t, "wipe", "--execute", "--sample", "64", "--log", lg.srv.URL, "--log-key", lg.vkey,
		"--image", f.img, "--journal", j2, "--key", f.key, "--station-cert", r.stationCert, "--verify-url", cert.DefaultVerifyURL)
	for _, want := range []string{"log unreachable", "reading the whole target back instead", "VERIFIED (full)", "CERTIFICATE ", "not logged yet", "shunya cert submit"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("offline wipe lacks %q: %d\n%s\n%s", want, code, out, errs)
		}
	}
	if code, out := r.verify(t, "--log-key", lg.vkey, "--require-log", j2+".cert.json"); code != 1 || !strings.Contains(out, "not logged") {
		t.Fatalf("unlogged with --require-log: %d %s", code, out)
	}
	// --offline-seed local: sampled with a tool-drawn seed, labelled.
	j3 := filepath.Join(f.dir, "j3.journal")
	code, out, errs = runCLI(t, "wipe", "--execute", "--sample", "64", "--log", lg.srv.URL, "--log-key", lg.vkey, "--offline-seed", "local",
		"--image", f.img, "--journal", j3, "--key", f.key, "--station-cert", r.stationCert, "--verify-url", cert.DefaultVerifyURL)
	if code != 0 || !strings.Contains(out, "a random seed drawn by this tool") {
		t.Fatalf("local seed: %d\n%s\n%s", code, out, errs)
	}
	if code, out := r.verify(t, j3+".cert.json"); code != 0 || !strings.Contains(out, "station-generated random seed") {
		t.Fatalf("local seed warning: %d %s", code, out)
	}
	// The log is back (same files, restarted): submit later.
	lg2 := startLog(t, r, lg.dir, s)
	if code, out, errs := runCLI(t, "cert", "submit", "--log", lg2.srv.URL, "--log-key", lg2.vkey, j2+".cert.json"); code != 0 || !strings.Contains(out, "as entry 3") {
		t.Fatalf("submit: %d %s %s", code, out, errs)
	}
	if code, out := r.verify(t, "--log-key", lg2.vkey, "--require-log", j2+".cert.json"); code != 0 {
		t.Fatalf("after submit: %d %s", code, out)
	}
	// Submitting again: already logged, no new entry.
	if code, out, _ := runCLI(t, "cert", "submit", "--log", lg2.srv.URL, "--log-key", lg2.vkey, j2+".cert.json"); code != 0 || !strings.Contains(out, "already logged") {
		t.Fatalf("resubmit: %d %s", code, out)
	}
}

func mustRoot(t *testing.T, r rootFixture) ed25519.PublicKey {
	b, _ := os.ReadFile(r.pub)
	p, err := keys.ParsePublic(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLogFlagErrors(t *testing.T) {
	f := newFixture(t, 1<<20)
	for _, args := range [][]string{
		{"--sample", "8"}, // no seed source
		{"--sample", "8", "--seed", strings.Repeat("ab", 16), "--log", "http://127.0.0.1:1", "--log-key", "x"},
		{"--sample", "8", "--log", "http://127.0.0.1:1"},                   // no key
		{"--sample", "8", "--log", "http://127.0.0.1:1", "--log-key", "x"}, // no station cert
		{"--sample", "8", "--offline-seed", "maybe"},
		{"--seed", strings.Repeat("ab", 16)},
	} {
		a := append([]string{"wipe", "--execute", "--image", f.img, "--journal", f.journal, "--key", f.key}, args...)
		if code, _, errs := runCLI(t, a...); code != 2 {
			t.Errorf("%v: %d %s", args, code, errs)
		}
	}
}
