package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func init() { rootIterations = 1000 } // PBKDF2 at full cost makes every test take seconds

var (
	t0   = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	pass = []byte("correct horse battery staple")
)

func newRoot(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestRootKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root.key")
	pub, err := CreateRoot(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateRoot(path, pass); err == nil {
		t.Error("existing root key overwritten")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode().Perm())
		}
	}
	priv, err := LoadRoot(path, pass)
	if err != nil || !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		t.Fatalf("load: %v", err)
	}
	if _, err := LoadRoot(path, []byte("wrong horse battery staple")); !errors.Is(err, ErrPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	if _, err := CreateRoot(filepath.Join(dir, "x.key"), nil); err == nil {
		t.Error("empty passphrase accepted")
	}
	// The plaintext seed must not appear in the file.
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, priv.Seed()) || strings.Contains(string(raw), b64(priv.Seed())) {
		t.Error("seed stored in clear")
	}

	// Every header field is bound by the AEAD: editing one fails as a wrong passphrase
	// would, and a swapped public key is caught even with the right passphrase.
	var f rootFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// The header is bound as additional data: the ciphertext does not open without it.
	g, err := f.aead(pass)
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(f.Nonce)
	ct, _ := base64.StdEncoding.DecodeString(f.Ciphertext)
	if _, err := g.Open(nil, nonce, ct, nil); err == nil {
		t.Error("ciphertext opens without the header as AAD")
	}
	other, _ := newRoot(t)
	for name, edit := range map[string]func(*rootFile){
		"iterations": func(f *rootFile) { f.Iterations++ },
		"salt":       func(f *rootFile) { f.Salt = b64(make([]byte, 16)) },
		"nonce":      func(f *rootFile) { f.Nonce = b64(make([]byte, 12)) },
		"ciphertext": func(f *rootFile) { c := []byte(f.Ciphertext); c[3] ^= 1; f.Ciphertext = string(c) },
		"public key": func(f *rootFile) { f.PublicKey = hexs(other) },
		"format":     func(f *rootFile) { f.Format = "shunya-root-key-v0" },
		"kdf":        func(f *rootFile) { f.KDF = "pbkdf2-sha1" },
		"huge cost":  func(f *rootFile) { f.Iterations = 1 << 30 },
	} {
		g := f
		edit(&g)
		b, _ := json.Marshal(g)
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".key")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRoot(p, pass); err == nil {
			t.Errorf("%s edited: loaded", name)
		}
	}
	if runtime.GOOS != "windows" {
		os.Chmod(path, 0o644)
		if _, err := LoadRoot(path, pass); err == nil {
			t.Error("world-readable root key loaded")
		}
	}
}

func TestPublicKeyFile(t *testing.T) {
	pub, _ := newRoot(t)
	p := filepath.Join(t.TempDir(), "root.pub")
	if err := WritePublic(p, pub); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPublic(p)
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("%x %v", got, err)
	}
	if got, err := ParsePublic(hexs(pub)); err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("hex: %v", err)
	}
	for _, bad := range []string{"", "zz", hexs(pub)[:62], "shunya-root-public-key-v1", "other-v1 " + hexs(pub)} {
		if _, err := ParsePublic(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func issue(t *testing.T, root ed25519.PrivateKey) (StationCert, ed25519.PrivateKey) {
	t.Helper()
	spub, spriv, _ := ed25519.GenerateKey(rand.Reader)
	c, err := IssueStation(root, "bay-3", spub, t0, t0.AddDate(1, 0, 0), t0)
	if err != nil {
		t.Fatal(err)
	}
	return c, spriv
}

func TestStationCertificate(t *testing.T) {
	rpub, rpriv := newRoot(t)
	c, spriv := issue(t, rpriv)
	if err := c.Verify(rpub); err != nil {
		t.Fatal(err)
	}
	if c.KeyID != KeyID(spriv.Public().(ed25519.PublicKey)) || c.Issuer != KeyID(rpub) {
		t.Errorf("%+v", c)
	}
	// Survives a JSON round trip (it travels inside certificates).
	b, _ := json.Marshal(c)
	c2, err := ParseStationCert(b, rpub)
	if err != nil || c2 != c {
		t.Fatalf("%v", err)
	}
	other, _ := newRoot(t)
	if err := c.Verify(other); err == nil || !strings.Contains(err.Error(), "not by root") {
		t.Error("verified under another root")
	}
	for name, edit := range map[string]func(*StationCert){
		"name":       func(c *StationCert) { c.Station = "bay-4" },
		"not after":  func(c *StationCert) { c.NotAfter = "2030-01-01T00:00:00Z" },
		"key id":     func(c *StationCert) { c.KeyID = "ed25519:0000000000000000" },
		"public key": func(c *StationCert) { c.PublicKey = hexs(other) },
		"signature":  func(c *StationCert) { c.Signature = c.Signature[:10] + "A" + c.Signature[11:] },
		"version":    func(c *StationCert) { c.Version = 2 },
	} {
		d := c
		edit(&d)
		if d == c {
			t.Fatalf("%s: edit did nothing", name)
		}
		if err := d.Verify(rpub); err == nil {
			t.Errorf("%s edited: verified", name)
		}
	}
	// Unknown members are refused, not ignored.
	var m map[string]any
	json.Unmarshal(b, &m)
	m["extra"] = "x"
	b2, _ := json.Marshal(m)
	if _, err := ParseStationCert(b2, rpub); err == nil {
		t.Error("unknown member accepted")
	}
	// encoding/json matches member names case-insensitively: "Station" must not pass
	// for "station" (the signature covers the bytes as written).
	if _, err := ParseStationCert(bytes.Replace(b, []byte(`"station":`), []byte(`"Station":`), 1), rpub); err == nil {
		t.Error("case-changed member name accepted")
	}
	if !c.ValidAt(t0) || !c.ValidAt(t0.AddDate(0, 6, 0)) || c.ValidAt(t0.Add(-time.Second)) || c.ValidAt(t0.AddDate(1, 0, 1)) {
		t.Error("ValidAt")
	}
	if _, err := IssueStation(rpriv, "", spriv.Public().(ed25519.PublicKey), t0, t0.AddDate(1, 0, 0), t0); err == nil {
		t.Error("empty name")
	}
	if _, err := IssueStation(rpriv, "x", spriv.Public().(ed25519.PublicKey), t0, t0, t0); err == nil {
		t.Error("empty validity")
	}
	if _, err := IssueStation(rpriv, "x", rpub, t0, t0.AddDate(1, 0, 0), t0); err == nil {
		t.Error("station certificate for the root key itself")
	}
}

func TestRevocationPolicy(t *testing.T) {
	rpub, rpriv := newRoot(t)
	l, err := NewRevocationList(rpriv, t0)
	if err != nil || l.Number != 1 || len(l.Revoked) != 0 {
		t.Fatalf("%+v %v", l, err)
	}
	if err := l.Verify(rpub); err != nil {
		t.Fatal(err)
	}
	a, b, c := "ed25519:aaaaaaaaaaaaaaaa", "ed25519:bbbbbbbbbbbbbbbb", "ed25519:cccccccccccccccc"
	at := t0.AddDate(0, 3, 0)
	l2, err := l.Revoke(rpriv, a, ReasonRetired, at, at)
	if err != nil {
		t.Fatal(err)
	}
	l3, err := l2.Revoke(rpriv, b, ReasonCompromised, at, at)
	if err != nil || l3.Number != 3 || l.Number != 1 {
		t.Fatalf("%v %d", err, l3.Number)
	}
	if err := l3.Verify(rpub); err != nil {
		t.Fatal(err)
	}
	before, after := at.Add(-time.Hour), at.Add(time.Hour)
	for _, v := range []struct {
		key    string
		issued time.Time
		ok     bool
	}{
		{a, before, true},  // retired: earlier certificates stand
		{a, at, false},     // from the revocation time on, refused
		{a, after, false},  //
		{b, before, false}, // compromised: the key's dates can't be trusted at all
		{b, after, false},
		{c, after, true}, // not revoked
	} {
		err := l3.Check(v.key, v.issued)
		if (err == nil) != v.ok || (err != nil && !errors.Is(err, ErrRevoked)) {
			t.Errorf("%s at %v: %v", v.key, v.issued, err)
		}
	}
	// Upgrading retired → compromised is allowed; downgrading, or repeating, is not.
	l4, err := l3.Revoke(rpriv, a, ReasonCompromised, after, after)
	if err != nil || l4.Check(a, before) == nil {
		t.Errorf("upgrade: %v", err)
	}
	if _, err := l4.Revoke(rpriv, b, ReasonRetired, after, after); err == nil {
		t.Error("downgrade accepted")
	}
	if _, err := l3.Revoke(rpriv, a, ReasonRetired, after, after); err == nil {
		t.Error("repeat accepted")
	}
	if _, err := l3.Revoke(rpriv, c, "lost", after, after); err == nil {
		t.Error("unknown reason accepted")
	}
	// A list signed by another root, edited, or replayed with a lower number.
	other, opriv := newRoot(t)
	if err := l3.Verify(other); err == nil {
		t.Error("verified under another root")
	}
	d := l3
	d.Revoked = d.Revoked[:1]
	if err := d.Verify(rpub); err == nil {
		t.Error("dropped entry verified")
	}
	if _, err := l3.Revoke(opriv, c, ReasonRetired, after, after); err == nil {
		t.Error("revoked with another root's key")
	}
	raw, _ := json.Marshal(l3)
	got, err := ParseRevocationList(raw, rpub)
	if err != nil || got.Number != 3 {
		t.Fatalf("%v", err)
	}
	if _, err := ParseRevocationList(raw, other); err == nil {
		t.Error("parsed under another root")
	}
}

func TestSignatureContexts(t *testing.T) {
	// A signature in one context never verifies in another.
	pub, priv := newRoot(t)
	v := map[string]string{"a": "b"}
	sig, err := SignJSON(priv, CtxStationCert, v)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"a":"b"}`)
	if err := VerifyCanonical(pub, CtxStationCert, body, sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanonical(pub, CtxRevocations, body, sig); err == nil {
		t.Error("cross-context signature accepted")
	}
	if err := VerifyCanonical(pub, CtxStationCert, []byte(`{ "a":"b"}`), sig); err == nil {
		t.Error("non-canonical body accepted")
	}
}

func FuzzParseStationCert(f *testing.F) {
	rpub, rpriv, _ := ed25519.GenerateKey(rand.Reader)
	spub, _, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := IssueStation(rpriv, "bay", spub, t0, t0.AddDate(1, 0, 0), t0)
	good, _ := json.Marshal(c)
	f.Add(good)
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := ParseStationCert(b, rpub)
		if err == nil && got != c {
			t.Fatalf("a different certificate verified: %+v", got)
		}
	})
}
