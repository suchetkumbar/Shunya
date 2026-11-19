package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"shunya/internal/cert"
	"shunya/internal/cert/certtest"
	"shunya/internal/keys"
	"shunya/internal/logentry"
	"shunya/internal/tilestore"
)

// fixture: an org, two certified wipes and one failed device, in one batch.
type fixture struct {
	org   *certtest.Org
	certs [][]byte
	m     Manifest
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	o := certtest.NewOrg(t)
	f := &fixture{org: o}
	fin := certtest.T0.Add(48 * time.Hour)
	for _, serial := range []string{"SER-A", "SER-B"} {
		f.certs = append(f.certs, o.Sign(t, o.Body(serial, fin)))
	}
	var items []Item
	for _, c := range f.certs {
		r, err := cert.Verify(c, o.Policy())
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, ItemFor(r))
	}
	items = append(items, Item{Path: "/dev/sdc", Model: "QEMU HARDDISK", Serial: "SER-C", Fingerprint: "fp2:" + strings.Repeat("cc", 32),
		Method: "ata-security-erase", Outcome: OutcomeFailed, Error: "the drive's security is frozen"})
	pub := o.StPriv.Public().(ed25519.PublicKey)
	st := o.Station
	f.m = Manifest{BatchID: strings.Repeat("0a", 16), Created: keys.FormatTime(fin.Add(2 * time.Minute)), Tool: "shunya test",
		Station: cert.StationFor(pub, &st), Items: items}
	return f
}

func (f *fixture) sign(t *testing.T) []byte {
	t.Helper()
	b, err := Sign(f.m, f.org.StPriv)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignVerify(t *testing.T) {
	f := newFixture(t)
	file := f.sign(t)
	r, err := Verify(file, f.org.Policy())
	if err != nil {
		t.Fatal(err)
	}
	if r.Trust != cert.TrustStation || len(r.Manifest.Items) != 3 || r.Logged != nil || len(r.ID) != 64 {
		t.Fatalf("result %+v", r)
	}
	if r.Certified() != 2 || r.Failed() != 1 {
		t.Fatalf("certified %d failed %d", r.Certified(), r.Failed())
	}
	var rs []*cert.Result
	for _, c := range f.certs {
		cr, err := cert.Verify(c, f.org.Policy())
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, cr)
	}
	if probs := r.CheckCertificates(rs); len(probs) != 0 {
		t.Fatalf("problems: %v", probs)
	}
	// A certificate missing from the set given is reported, by device.
	if probs := r.CheckCertificates(rs[:1]); len(probs) != 1 || !strings.Contains(probs[0], "SER-B") {
		t.Fatalf("missing certificate: %v", probs)
	}
	// A certificate for another device under a listed ID cannot exist (the ID is the
	// body hash), but one from another batch must not satisfy this one.
	other := f.org.Sign(t, f.org.Body("SER-Z", certtest.T0.Add(48*time.Hour)))
	oz, _ := cert.Verify(other, f.org.Policy())
	if probs := r.CheckCertificates([]*cert.Result{rs[0], oz}); len(probs) != 1 {
		t.Fatalf("foreign certificate: %v", probs)
	}
}

// Every single-byte change to the signed file fails verification.
func TestEveryByteMatters(t *testing.T) {
	f := newFixture(t)
	file := f.sign(t)
	for i := range file {
		b := bytes.Clone(file)
		b[i] ^= 0x01
		if _, err := Verify(b, f.org.Policy()); err == nil {
			t.Fatalf("byte %d changed (%q→%q): still verifies", i, file[i], b[i])
		}
	}
}

func TestRefusals(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(m *Manifest){
		"no items":            func(m *Manifest) { m.Items = nil },
		"bad outcome":         func(m *Manifest) { m.Items[2].Outcome = "fine" },
		"certified, no ID":    func(m *Manifest) { m.Items[0].CertificateID = "" },
		"failed, with ID":     func(m *Manifest) { m.Items[2].CertificateID = strings.Repeat("ab", 32) },
		"duplicate device":    func(m *Manifest) { m.Items[1].Fingerprint = m.Items[0].Fingerprint },
		"bad batch ID":        func(m *Manifest) { m.BatchID = "x" },
		"bad time":            func(m *Manifest) { m.Created = "yesterday" },
		"no fingerprint":      func(m *Manifest) { m.Items[2].Fingerprint = "" },
		"other station's key": func(m *Manifest) { m.Station.KeyID = "deadbeef" },
	}
	for name, mutate := range cases {
		g := *f
		g.m.Items = append([]Item(nil), f.m.Items...)
		mutate(&g.m)
		if _, err := Sign(g.m, f.org.StPriv); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	file := f.sign(t)
	// Not trusted: another root, a dev key, a revoked station.
	p := f.org.Policy()
	other := certtest.NewOrg(t)
	p.Root = other.RootPub
	if _, err := Verify(file, p); err == nil {
		t.Error("verified under another root")
	}
	rev, err := f.org.CRL.Revoke(f.org.RootPriv, f.m.Station.KeyID, keys.ReasonCompromised, certtest.T0, certtest.T0)
	if err != nil {
		t.Fatal(err)
	}
	p = f.org.Policy()
	p.Revocations = &rev
	if _, err := Verify(file, p); !errors.Is(err, keys.ErrRevoked) {
		t.Errorf("revoked station: %v", err)
	}
	g := *f
	_, dev, _ := ed25519.GenerateKey(rand.Reader)
	g.m.Station = cert.StationFor(dev.Public().(ed25519.PublicKey), nil)
	devFile, err := Sign(g.m, dev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(devFile, f.org.Policy()); !errors.Is(err, cert.ErrDevKey) {
		t.Errorf("dev key: %v", err)
	}
	p = f.org.Policy()
	p.AllowDevKey = true
	if r, err := Verify(devFile, p); err != nil || r.Trust != cert.TrustDevKey {
		t.Errorf("dev key allowed: %v", err)
	}
	// A certificate file is not a manifest, and the reverse.
	if _, err := Verify(f.certs[0], f.org.Policy()); err == nil {
		t.Error("certificate accepted as a manifest")
	}
	if _, err := cert.Verify(file, f.org.Policy()); err == nil {
		t.Error("manifest accepted as a certificate")
	}
}

func TestLogged(t *testing.T) {
	f := newFixture(t)
	file := f.sign(t)
	signer := certtest.LogKey(t, "example.org/log")
	lg, err := tilestore.Create(t.TempDir(), signer)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := LogEntry(file)
	if err != nil || entry[0] != logentry.TypeManifest {
		t.Fatalf("entry: %v", err)
	}
	lg.Append([]byte{logentry.TypeBeacon, 1})
	i, err := lg.Append(entry)
	if err != nil {
		t.Fatal(err)
	}
	proof, cp, err := lg.Prove(i)
	if err != nil {
		t.Fatal(err)
	}
	logged, err := WithLog(file, logentry.NewInclusion(i, cp, proof))
	if err != nil {
		t.Fatal(err)
	}
	p := f.org.Policy()
	p.LogKey = &signer.Verifier
	p.RequireLog = true
	r, err := Verify(logged, p)
	if err != nil || r.Logged == nil || !r.Logged.Checked || r.Logged.Index != i {
		t.Fatalf("logged: %+v %v", r, err)
	}
	if _, err := Verify(file, p); err == nil {
		t.Error("unlogged manifest passed RequireLog")
	}
	// The proof is for this manifest's entry: attached to a different manifest it fails.
	g := *f
	g.m.BatchID = strings.Repeat("0b", 16)
	other, _ := WithLog(g.sign(t), logentry.NewInclusion(i, cp, proof))
	if _, err := Verify(other, p); err == nil {
		t.Error("another manifest's proof accepted")
	}
}

func FuzzVerify(f *testing.F) {
	fx := newFixture(&testing.T{})
	f.Add(fx.sign(&testing.T{}))
	f.Add([]byte(`{"log":null,"manifest":{},"signature":""}` + "\n"))
	p := fx.org.Policy()
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Verify(b, p)
		if err == nil && (r == nil || len(r.Manifest.Items) == 0) {
			t.Fatal("verified an empty manifest")
		}
	})
}

// A manifest signed with a listed certificate ID but another device's fingerprint (or
// wipe) does not match that certificate.
func TestCertificateForAnotherDevice(t *testing.T) {
	f := newFixture(t)
	f.m.Items[0].Fingerprint = "fp2:" + strings.Repeat("ee", 32)
	r, err := Verify(f.sign(t), f.org.Policy())
	if err != nil {
		t.Fatal(err)
	}
	var rs []*cert.Result
	for _, c := range f.certs {
		cr, _ := cert.Verify(c, f.org.Policy())
		rs = append(rs, cr)
	}
	if probs := r.CheckCertificates(rs); len(probs) != 1 || !strings.Contains(probs[0], "another device or wipe") {
		t.Fatalf("problems: %v", probs)
	}
	g := newFixture(t)
	g.m.Items[1].WipeID = strings.Repeat("0f", 16)
	r, _ = Verify(g.sign(t), g.org.Policy())
	rs = rs[:0]
	for _, c := range g.certs {
		cr, _ := cert.Verify(c, g.org.Policy())
		rs = append(rs, cr)
	}
	if probs := r.CheckCertificates(rs); len(probs) != 1 {
		t.Fatalf("other wipe: %v", probs)
	}
}
