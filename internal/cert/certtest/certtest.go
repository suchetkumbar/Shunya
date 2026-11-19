// Package certtest builds keys, station certificates and certificate bodies for tests
// of the packages around cert (the log server, audit, CLI). Not used by any binary.
package certtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"shunya/internal/cert"
	"shunya/internal/keys"
	"shunya/internal/logentry"
	"shunya/internal/note"
)

// T0 is the fixtures' reference time; station certificates are valid for a year from it.
var T0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// Org is a root with one certified station and an empty revocation list.
type Org struct {
	RootPub  ed25519.PublicKey
	RootPriv ed25519.PrivateKey
	Station  keys.StationCert
	StPriv   ed25519.PrivateKey
	CRL      keys.RevocationList
}

// NewOrg makes an organisation with station "bay-3".
func NewOrg(t testing.TB) *Org {
	t.Helper()
	o := &Org{}
	o.RootPub, o.RootPriv, _ = ed25519.GenerateKey(rand.Reader)
	spub, spriv, _ := ed25519.GenerateKey(rand.Reader)
	o.StPriv = spriv
	var err error
	if o.Station, err = keys.IssueStation(o.RootPriv, "bay-3", spub, T0, T0.AddDate(1, 0, 0), T0); err != nil {
		t.Fatal(err)
	}
	if o.CRL, err = keys.NewRevocationList(o.RootPriv, T0); err != nil {
		t.Fatal(err)
	}
	return o
}

// Policy trusts the org's root and revocation list.
func (o *Org) Policy() cert.Policy { return cert.Policy{Root: o.RootPub, Revocations: &o.CRL} }

// Body is a valid version-2 certificate body from the org's station (full read-back
// only), with the given device serial and finish time.
func (o *Org) Body(serial string, finished time.Time) cert.Certificate {
	pub := o.StPriv.Public().(ed25519.PublicKey)
	h := sha256.Sum256([]byte(serial))
	c := cert.Certificate{
		Format: cert.Format, Version: cert.Version, WipeID: hex.EncodeToString(h[:16]),
		Issued: keys.FormatTime(finished.Add(time.Minute)), Result: cert.ResultErasedVerified,
		Tool: cert.Tool{Wipe: "shunya test", WipeBuildHash: strings.Repeat("ab", 32), Issuer: "shunya test", IssuerBuildHash: strings.Repeat("cd", 32), Build: "dev"},
		Device: cert.Device{Path: "/dev/nvme0n1", Model: "QEMU NVMe Ctrl", Serial: serial, SizeBytes: 1 << 30,
			Fingerprint: "fp2:" + hex.EncodeToString(h[:]), Media: "nvme", Virtual: true},
		Erasure: cert.Erasure{Method: "overwrite", NISTLevel: "clear", Passes: []string{"random"}, SizeBytes: 1 << 30, SectorSize: 512,
			Started: keys.FormatTime(finished.Add(-time.Hour)), Finished: keys.FormatTime(finished), Notes: []string{}, Steps: []cert.Step{}},
		Hidden:        cert.Hidden{Checked: true, DCO: "not-supported"},
		Verification:  []cert.Verification{{Mode: "full", Pattern: "random", OK: true, BytesRead: 1 << 30}},
		Interruptions: []cert.Interruption{},
		Journal:       cert.Journal{SHA256: strings.Repeat("11", 32), Records: 9, KeyID: keys.KeyID(pub)},
		Station:       cert.StationFor(pub, &o.Station),
		VerifyURL:     "http://127.0.0.1:8080/c/",
	}
	return c
}

// Sign signs a body with the station key.
func (o *Org) Sign(t testing.TB, c cert.Certificate) []byte {
	t.Helper()
	f, err := cert.Sign(c, o.StPriv)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// SeedRequest is a signed seed request for body c, made at "at".
func (o *Org) SeedRequest(t testing.TB, c cert.Certificate, at time.Time) logentry.SeedRequest {
	t.Helper()
	sc := o.Station
	q, err := logentry.NewSeedRequest(o.StPriv, &sc, c.WipeID, c.Device.Fingerprint, sha256.Sum256([]byte(c.WipeID)), keys.FormatTime(at))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// WithSeed adds a passing sampled verification seeded by the log's answer.
func WithSeed(c cert.Certificate, q logentry.SeedRequest, in *logentry.Inclusion, seed []byte) cert.Certificate {
	c.Verification = append(append([]cert.Verification{}, c.Verification...), cert.Verification{Mode: "sampled", Pattern: "random", OK: true,
		BytesRead: 512 * 64, Samples: 64, SeedSource: cert.SeedTlog, Seed: hex.EncodeToString(seed), Bound95: 0.0457,
		SeedRequest: &q, SeedLog: in})
	return c
}

// LogKey makes a log signing key.
func LogKey(t testing.TB, origin string) *note.Signer {
	t.Helper()
	skey, _, err := note.GenerateKey(origin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.ParseSignerKey(skey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
