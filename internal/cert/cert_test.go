package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"shunya/internal/jcs"
	"shunya/internal/keys"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

type fixture struct {
	rootPub   ed25519.PublicKey
	rootPriv  ed25519.PrivateKey
	station   keys.StationCert
	stPriv    ed25519.PrivateKey
	crl       keys.RevocationList
	body      Certificate
	signed    []byte
	issueTime time.Time
}

func sample() Certificate {
	return Certificate{
		Format: Format, Version: 1, WipeID: "0123456789abcdef0123456789abcdef",
		Result: ResultErasedVerified,
		Tool:   Tool{Wipe: "shunya 0.7.0-dev", WipeBuildHash: strings.Repeat("ab", 32), Issuer: "shunya 0.7.0-dev", IssuerBuildHash: strings.Repeat("cd", 32), Build: "dev"},
		Device: Device{Path: "/dev/sdb", Model: "QEMU HARDDISK", Serial: "lab-é-1", SizeBytes: 1 << 30,
			Fingerprint: "fp2:" + strings.Repeat("0", 64), Media: "hdd", Virtual: true},
		Erasure: Erasure{Method: "overwrite", NISTLevel: "clear", Passes: []string{"random"}, SizeBytes: 1 << 30, SectorSize: 512,
			Started: "2026-11-01T10:00:00.123456789Z", Finished: "2026-11-01T10:05:00Z", Notes: []string{}, Steps: []Step{}},
		Hidden:        Hidden{Checked: true, DCO: "not-supported"},
		Verification:  []Verification{{Mode: "full", Pattern: "random", OK: true, BytesRead: 1 << 30}, {Mode: "sampled", OK: true, Samples: 1000, SeedSource: "operator", Seed: "00ff", Bound95: 0.0029956}},
		Interruptions: []Interruption{{Kind: "unclean-stop", Pass: 0, Offset: 4096, StoppedAt: "2026-11-01T10:01:00Z", ResumedAt: "2026-11-01T10:02:00Z"}},
		Journal:       Journal{SHA256: strings.Repeat("11", 32), Records: 12},
		VerifyURL:     DefaultVerifyURL,
	}
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{issueTime: t0.AddDate(0, 1, 0)}
	f.rootPub, f.rootPriv, _ = ed25519.GenerateKey(rand.Reader)
	var spub ed25519.PublicKey
	spub, f.stPriv, _ = ed25519.GenerateKey(rand.Reader)
	var err error
	if f.station, err = keys.IssueStation(f.rootPriv, "bay-3", spub, t0, t0.AddDate(1, 0, 0), t0); err != nil {
		t.Fatal(err)
	}
	if f.crl, err = keys.NewRevocationList(f.rootPriv, t0); err != nil {
		t.Fatal(err)
	}
	f.body = sample()
	f.body.Issued = keys.FormatTime(f.issueTime)
	f.body.Station = StationFor(spub, &f.station)
	f.body.Journal.KeyID = f.body.Station.KeyID
	if f.signed, err = Sign(f.body, f.stPriv); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) policy() Policy {
	return Policy{Root: f.rootPub, Revocations: &f.crl}
}

func TestSignVerify(t *testing.T) {
	f := newFixture(t)
	r, err := Verify(f.signed, f.policy())
	if err != nil {
		t.Fatal(err)
	}
	if r.Trust != TrustStation || r.ID != ID(mustBody(t, f.signed)) || len(r.ID) != 64 {
		t.Errorf("%+v", r)
	}
	if r.Certificate.Device.Serial != "lab-é-1" || r.Certificate.Station.Name != "bay-3" {
		t.Errorf("%+v", r.Certificate)
	}
	if r.QRPayload() != DefaultVerifyURL+r.ID {
		t.Errorf("qr %q", r.QRPayload())
	}
	// The file is its own canonical form plus one newline.
	if !bytes.HasSuffix(f.signed, []byte("}\n")) || bytes.Count(f.signed, []byte("\n")) != 1 {
		t.Errorf("layout %q", f.signed[len(f.signed)-10:])
	}
	// Signing is deterministic (Ed25519): same body, same file.
	again, _ := Sign(f.body, f.stPriv)
	if !bytes.Equal(again, f.signed) {
		t.Error("not deterministic")
	}
}

func mustBody(t *testing.T, signed []byte) []byte {
	var e struct {
		Certificate json.RawMessage `json:"certificate"`
	}
	if err := json.Unmarshal(signed, &e); err != nil {
		t.Fatal(err)
	}
	return e.Certificate
}

// Acceptance: changing any single byte of a certificate fails verification. Every
// byte is flipped in each of its 8 bits, and deleted.
func TestEverySingleByteChangeFails(t *testing.T) {
	f := newFixture(t)
	p := f.policy()
	n := 0
	try := func(b []byte, what string) {
		n++
		if _, err := Verify(b, p); err == nil {
			t.Fatalf("%s verified: %q", what, b)
		}
	}
	buf := make([]byte, len(f.signed))
	for i := range f.signed {
		for bit := 0; bit < 8; bit++ {
			copy(buf, f.signed)
			buf[i] ^= 1 << bit
			try(buf, "flip")
		}
		try(append(append([]byte{}, f.signed[:i]...), f.signed[i+1:]...), "deletion")
	}
	try(append(append([]byte{}, f.signed...), '\n'), "extra newline")
	t.Logf("%d modified certificates (%d bytes), all refused", n, len(f.signed))
}

func TestPolicy(t *testing.T) {
	f := newFixture(t)
	// Wrong root: the station certificate does not chain.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	p := f.policy()
	p.Root = other
	if _, err := Verify(f.signed, p); err == nil {
		t.Error("verified under another root")
	}
	// No revocation list is an error unless explicitly skipped.
	p = f.policy()
	p.Revocations = nil
	if _, err := Verify(f.signed, p); !errors.Is(err, ErrNoRevocations) {
		t.Errorf("no list: %v", err)
	}
	p.SkipRevocation = true
	if r, err := Verify(f.signed, p); err != nil || len(r.Warnings) == 0 {
		t.Errorf("skip: %v %v", r, err)
	}
	// Acceptance: a revoked (retired) station's certificates issued after the revocation
	// fail, earlier ones pass; a compromised station's all fail.
	retireAt := f.issueTime.Add(time.Hour)
	l, err := f.crl.Revoke(f.rootPriv, f.station.KeyID, keys.ReasonRetired, retireAt, retireAt)
	if err != nil {
		t.Fatal(err)
	}
	p = Policy{Root: f.rootPub, Revocations: &l}
	if _, err := Verify(f.signed, p); err != nil {
		t.Errorf("issued before retirement: %v", err)
	}
	late := f.body
	late.Issued = keys.FormatTime(retireAt.Add(time.Minute))
	lateSigned, _ := Sign(late, f.stPriv)
	if _, err := Verify(lateSigned, p); !errors.Is(err, keys.ErrRevoked) {
		t.Errorf("issued after retirement: %v", err)
	}
	lc, _ := l.Revoke(f.rootPriv, f.station.KeyID, keys.ReasonCompromised, retireAt, retireAt)
	if _, err := Verify(f.signed, Policy{Root: f.rootPub, Revocations: &lc}); !errors.Is(err, keys.ErrRevoked) {
		t.Errorf("compromised: %v", err)
	}
	// A revocation list from another root is refused.
	_, opriv, _ := ed25519.GenerateKey(rand.Reader)
	ol, _ := keys.NewRevocationList(opriv, t0)
	if _, err := Verify(f.signed, Policy{Root: f.rootPub, Revocations: &ol}); err == nil {
		t.Error("foreign revocation list accepted")
	}
	// Issued outside the station certificate's validity.
	for _, when := range []time.Time{t0.Add(-time.Hour), t0.AddDate(1, 0, 1)} {
		b := f.body
		b.Issued = keys.FormatTime(when)
		s, _ := Sign(b, f.stPriv)
		if _, err := Verify(s, f.policy()); err == nil {
			t.Errorf("issued %v outside validity: verified", when)
		}
	}
}

func TestDevKey(t *testing.T) {
	f := newFixture(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := f.body
	b.Station = StationFor(pub, nil)
	b.Journal.KeyID = b.Station.KeyID
	s, err := Sign(b, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s, f.policy()); !errors.Is(err, ErrDevKey) {
		t.Errorf("dev key: %v", err)
	}
	p := f.policy()
	p.AllowDevKey = true
	r, err := Verify(s, p)
	if err != nil || r.Trust != TrustDevKey || len(r.Warnings) == 0 {
		t.Errorf("%+v %v", r, err)
	}
	// The station key must match the signature: a station-certified body signed by
	// another key fails even though both keys are "valid".
	if _, err := Sign(f.body, priv); err == nil {
		t.Error("Sign accepted a body naming another station")
	}
	body, _ := jcs.Marshal(f.body)
	sig, _ := keys.SignJSON(priv, keys.CtxCertificate, json.RawMessage(body))
	forged, _ := jcs.Marshal(envelope{Certificate: body, Log: json.RawMessage("null"), Signature: sig})
	if _, err := Verify(append(forged, '\n'), f.policy()); !errors.Is(err, keys.ErrSignature) {
		t.Errorf("wrong signer: %v", err)
	}
}

func TestSemanticChecks(t *testing.T) {
	f := newFixture(t)
	for name, edit := range map[string]func(*Certificate){
		"purge by overwrite": func(c *Certificate) { c.Erasure.NISTLevel = "purge"; c.Device.Virtual = false }, // physical disk: only the overwrite rule applies
		"purge on virtual":   func(c *Certificate) { c.Erasure.Method = "nvme-format-user-data-erase"; c.Erasure.NISTLevel = "purge" },
		"unknown level":      func(c *Certificate) { c.Erasure.NISTLevel = "destroy" },
		"failed check":       func(c *Certificate) { c.Verification[1].OK = false },
		"no verification":    func(c *Certificate) { c.Verification = []Verification{} },
		"result":             func(c *Certificate) { c.Result = "erased" },
		"version":            func(c *Certificate) { c.Version = 2 },
		"format":             func(c *Certificate) { c.Format = "x" },
		"station mismatch":   func(c *Certificate) { c.Station.Name = "bay-4" },
		"journal key":        func(c *Certificate) { c.Journal.KeyID = "ed25519:0000000000000000" },
		"verify url":         func(c *Certificate) { c.VerifyURL = "http://example.org/" },
		"long url":           func(c *Certificate) { c.VerifyURL = "https://" + strings.Repeat("a", 120) + "/" },
		"issued time":        func(c *Certificate) { c.Issued = "2026-12-01 00:00:00" },
		"wipe id":            func(c *Certificate) { c.WipeID = "" },
	} {
		b := f.body
		b.Verification = append([]Verification{}, f.body.Verification...)
		edit(&b)
		s, err := Sign(b, f.stPriv)
		if err != nil {
			continue // refused at signing: fine too
		}
		if _, err := Verify(s, f.policy()); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Sign refuses what Verify would refuse.
	b := f.body
	b.Result = ""
	if _, err := Sign(b, f.stPriv); err == nil {
		t.Error("Sign accepted an invalid body")
	}
}

func TestStrictEnvelope(t *testing.T) {
	f := newFixture(t)
	var m map[string]json.RawMessage
	json.Unmarshal(f.signed, &m)
	for name, edit := range map[string]func(map[string]json.RawMessage){
		"extra member": func(m map[string]json.RawMessage) { m["x"] = json.RawMessage(`1`) },
		"log proof":    func(m map[string]json.RawMessage) { m["log"] = json.RawMessage(`{}`) },
		"no signature": func(m map[string]json.RawMessage) { delete(m, "signature") },
		"body member": func(m map[string]json.RawMessage) {
			var b map[string]json.RawMessage
			json.Unmarshal(m["certificate"], &b)
			b["extra"] = json.RawMessage(`"x"`)
			m["certificate"], _ = json.Marshal(b)
		},
	} {
		c := map[string]json.RawMessage{}
		for k, v := range m {
			c[k] = v
		}
		edit(c)
		raw, _ := json.Marshal(c)
		canon, err := Canonical(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(canon, f.policy()); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if _, err := Verify(bytes.Repeat([]byte(" "), MaxBytes+1), f.policy()); err == nil {
		t.Error("oversized input accepted")
	}
	// Same JSON meaning, not canonical: refused as such (before any other check).
	spaced := bytes.Replace(f.signed, []byte(`{"certificate":`), []byte(`{ "certificate":`), 1)
	if _, err := Verify(spaced, f.policy()); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("whitespace: %v", err)
	}
}

func FuzzVerify(f *testing.F) {
	fx := newFixture(f)
	f.Add(fx.signed)
	p := fx.policy()
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := Verify(b, p); err == nil && !bytes.Equal(b, fx.signed) {
			t.Fatalf("a different certificate verified:\n%s", b)
		}
	})
}
