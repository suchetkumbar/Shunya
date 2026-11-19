package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"shunya/internal/logentry"
	"shunya/internal/note"
	"shunya/internal/tilestore"
)

type logFixture struct {
	*fixture
	log    *tilestore.Log
	signer *note.Signer
	v2     Certificate // log-seeded body
}

func logSigner(t testing.TB, name string) *note.Signer {
	skey, _, err := note.GenerateKey(name)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := note.ParseSignerKey(skey)
	return s
}

// seedFrom asks the log for a seed the way the station does: request, beacon,
// checkpoint, inclusion proof of the request.
func seedFrom(t testing.TB, l *tilestore.Log, q logentry.SeedRequest) *logentry.Inclusion {
	e, err := q.Entry()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := logentry.Beacon()
	i, err := l.Append(e, b)
	if err != nil {
		t.Fatal(err)
	}
	p, cp, err := l.Prove(i)
	if err != nil {
		t.Fatal(err)
	}
	in := logentry.NewInclusion(i, cp, p)
	return &in
}

func newLogFixture(t testing.TB) *logFixture {
	f := &logFixture{fixture: newFixture(t), signer: logSigner(t, "shunya.test/log")}
	var err error
	if f.log, err = tilestore.Create(t.TempDir(), f.signer); err != nil {
		t.Fatal(err)
	}
	f.log.Append([]byte{logentry.TypeBeacon, 1}) // someone else's entry first
	b := f.body
	b.Version = 2
	q, err := logentry.NewSeedRequest(f.stPriv, &f.station, b.WipeID, b.Device.Fingerprint,
		sha256.Sum256([]byte("journal")), "2026-11-01T10:05:01Z")
	if err != nil {
		t.Fatal(err)
	}
	in := seedFrom(t, f.log, q)
	text, _ := in.CheckpointText()
	b.Verification = []Verification{b.Verification[0], {Mode: "sampled", Pattern: "random", OK: true, BytesRead: 512 * 64,
		Samples: 64, SeedSource: SeedTlog, Seed: hex.EncodeToString(logentry.Seed(text, b.Device.Fingerprint)),
		Bound95: 0.0457, SeedRequest: &q, SeedLog: in}}
	f.v2 = b
	return f
}

func (f *logFixture) logPolicy() Policy {
	p := f.policy()
	p.LogKey = &f.signer.Verifier
	return p
}

func (f *logFixture) submit(t testing.TB, file []byte) []byte {
	e, err := LogEntry(file)
	if err != nil {
		t.Fatal(err)
	}
	i, err := f.log.Append(e)
	if err != nil {
		t.Fatal(err)
	}
	p, cp, _ := f.log.Prove(i)
	out, err := WithLog(file, logentry.NewInclusion(i, cp, p))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLogSeededCertificate(t *testing.T) {
	f := newLogFixture(t)
	file, err := Sign(f.v2, f.stPriv)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Verify(file, f.logPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if r.Logged != nil || len(r.Warnings) != 0 {
		t.Fatalf("unlogged: %+v %v", r.Logged, r.Warnings)
	}
	// Without the log key: valid, with a warning that the seed's checkpoint is unchecked.
	r, err = Verify(file, f.policy())
	if err != nil || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "not checked") {
		t.Fatalf("%v %v", err, r.Warnings)
	}
	if _, err := Verify(file, Policy{Root: f.rootPub, Revocations: &f.crl, RequireLog: true}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("RequireLog on an unlogged certificate: %v", err)
	}

	logged := f.submit(t, file)
	r, err = Verify(logged, f.logPolicy())
	if err != nil || r.Logged == nil || !r.Logged.Checked || r.Logged.Index != 3 || r.Logged.Checkpoint.Size != 4 {
		t.Fatalf("%v %+v", err, r.Logged)
	}
	if r2, _ := Verify(file, f.logPolicy()); r2.ID != r.ID {
		t.Fatal("logging changed the certificate ID")
	}
	p := f.logPolicy()
	p.RequireLog = true
	if _, err := Verify(logged, p); err != nil {
		t.Fatal(err)
	}
	// Without the log key, the proof is reported unchecked.
	r, err = Verify(logged, f.policy())
	if err != nil || len(r.Warnings) != 2 || r.Logged.Checked {
		t.Fatalf("%v %v", err, r.Warnings)
	}
	// The entry and the file round-trip.
	e, _ := LogEntry(logged)
	back, err := FromEntry(e)
	if err != nil || !bytes.Equal(back, file) {
		t.Fatal("FromEntry")
	}
	// Any single-byte change to the logged file still fails (the proof is covered by
	// the log's checkpoint signature, the body by the station's).
	for i := 0; i < len(logged)-1; i += 7 {
		m := bytes.Clone(logged)
		m[i] ^= 0x01
		if _, err := Verify(m, f.logPolicy()); err == nil {
			t.Fatalf("byte %d (%q) changed: verified", i, logged[max(0, i-20):i+1])
		}
	}
}

func TestLogProofRefusals(t *testing.T) {
	f := newLogFixture(t)
	file, _ := Sign(f.v2, f.stPriv)
	logged := f.submit(t, file)
	other := logSigner(t, "shunya.test/log")
	p := f.logPolicy()
	p.LogKey = &other.Verifier
	if _, err := Verify(logged, p); !errors.Is(err, ErrInvalid) {
		t.Fatalf("other log key: %v", err)
	}
	// A proof for a different certificate's entry.
	b := f.v2
	b.Device.Serial = "other"
	file2, _ := Sign(b, f.stPriv)
	logged2 := f.submit(t, file2)
	var in logentry.Inclusion
	mustDecode(t, logged2, &in)
	swapped, _ := WithLog(file, in)
	if _, err := Verify(swapped, f.logPolicy()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("someone else's proof: %v", err)
	}
	// Proof with the wrong index.
	mustDecode(t, logged, &in)
	in.Index--
	wrong, _ := WithLog(file, in)
	if _, err := Verify(wrong, f.logPolicy()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong index: %v", err)
	}
}

func mustDecode(t *testing.T, file []byte, in *logentry.Inclusion) {
	var e envelope
	if err := strict(file, &e); err != nil {
		t.Fatal(err)
	}
	if err := strict(e.Log, in); err != nil {
		t.Fatal(err)
	}
}

func TestSeedRefusals(t *testing.T) {
	f := newLogFixture(t)
	mk := func(edit func(v *Verification, c *Certificate)) error {
		b := f.v2
		b.Verification = append([]Verification{}, f.v2.Verification...)
		v := b.Verification[1]
		q := *v.SeedRequest
		v.SeedRequest = &q
		in := *v.SeedLog
		v.SeedLog = &in
		edit(&v, &b)
		b.Verification[1] = v
		file, err := Sign(b, f.stPriv)
		if err != nil {
			return err
		}
		_, err = Verify(file, f.logPolicy())
		return err
	}
	reseed := func(v *Verification, fp string) {
		text, _ := v.SeedLog.CheckpointText()
		v.Seed = hex.EncodeToString(logentry.Seed(text, fp))
	}
	cases := map[string]func(v *Verification, c *Certificate){
		"seed changed":        func(v *Verification, c *Certificate) { v.Seed = strings.Repeat("00", 32) },
		"operator seed + req": func(v *Verification, c *Certificate) { v.SeedSource = SeedOperator },
		"v1 with request":     func(v *Verification, c *Certificate) { c.Version = 1 },
		"no request":          func(v *Verification, c *Certificate) { v.SeedRequest = nil },
		"no checkpoint":       func(v *Verification, c *Certificate) { v.SeedLog = nil },
		"full with log seed":  func(v *Verification, c *Certificate) { v.Mode = "full" },
		"other wipe": func(v *Verification, c *Certificate) {
			c.WipeID = strings.Repeat("ab", 16)
		},
		"other device": func(v *Verification, c *Certificate) {
			// The seed still matches the request; only the device differs.
			c.Device.Fingerprint = "fp2:" + strings.Repeat("1", 64)
		},
		"other station": func(v *Verification, c *Certificate) {
			// A genuine, logged request, but made by another station's key.
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			q, _ := logentry.NewSeedRequest(priv, nil, c.WipeID, c.Device.Fingerprint, sha256.Sum256([]byte("journal")), "2026-11-01T10:05:01Z")
			v.SeedRequest, v.SeedLog = &q, seedFrom(t, f.log, q)
			reseed(v, c.Device.Fingerprint)
		},
		"request edited": func(v *Verification, c *Certificate) { v.SeedRequest.JournalSHA256 = strings.Repeat("22", 32) },
		"requested before the erase finished": func(v *Verification, c *Certificate) {
			c.Erasure.Finished = "2026-11-01T10:06:00Z"
		},
		"checkpoint of another tree": func(v *Verification, c *Certificate) {
			// A genuine log checkpoint, but one that does not include this request.
			l, _ := tilestore.Create(t.TempDir(), f.signer)
			b, _ := logentry.Beacon()
			l.Append(b, b)
			p, cp, _ := l.Prove(1)
			in := logentry.NewInclusion(v.SeedLog.Index, cp, p)
			v.SeedLog = &in
			reseed(v, c.Device.Fingerprint)
		},
	}
	for name, edit := range cases {
		if err := mk(edit); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if err := mk(func(*Verification, *Certificate) {}); err != nil {
		t.Fatalf("unedited: %v", err)
	}
}

func TestVerifyURLs(t *testing.T) {
	for u, ok := range map[string]bool{
		"https://verify.example/c/":           true,
		"http://127.0.0.1:8080/c/":            true,
		"http://localhost:8080/c/":            true,
		"http://127.0.0.1/c/":                 true,
		"http://127.0.0.1.evil/c/":            false,
		"http://localhost.evil/c/":            false,
		"http://example.org/c/":               false,
		"https://a b/":                        false,
		"ftp://127.0.0.1/":                    false,
		"https://" + strings.Repeat("a", 100): false,
	} {
		if ValidVerifyURL(u) != ok {
			t.Errorf("%q: want %v", u, ok)
		}
	}
}
