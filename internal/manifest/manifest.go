// Package manifest is the batch manifest of a fleet run: one signed file that lists
// every device the batch tried, what happened to it, and the ID of each certificate.
//
// A manifest adds no new trust: each listed certificate stands on its own and is
// verified on its own. The manifest's job is completeness. It is signed by the same
// station key, so a batch cannot later claim fewer (or other) devices than it had, and
// devices that failed or were refused are on record next to those that were certified.
//
// The file is canonical JSON (RFC 8785), like a certificate:
//
//	{"log": null | inclusion proof, "manifest": {...}, "signature": "..."}
//
// with an Ed25519 signature over the body under the context "shunya/batch-manifest/v1".
// In the transparency log it is entry type 0x04, its envelope with "log": null.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"shunya/internal/cert"
	"shunya/internal/jcs"
	"shunya/internal/keys"
	"shunya/internal/logentry"
)

const (
	Format  = "shunya-batch-manifest"
	Version = 1
	Ctx     = "shunya/batch-manifest/v1"
	// MaxItems keeps a manifest within one log entry (entries are at most 64 KiB; a
	// station certificate and 100 items are well under that).
	MaxItems = 100
	// MaxBytes bounds a manifest file.
	MaxBytes = logentry.MaxEntry
)

// Outcomes of one device in a batch.
const (
	OutcomeCertified    = "certified"     // wiped, verified, certificate issued
	OutcomeNotCertified = "not-certified" // wiped, but no passing verification (no certificate)
	OutcomeVerifyFailed = "verify-failed" // the read-back found sectors that were not erased
	OutcomeInterrupted  = "interrupted"   // stopped; resumable from its journal
	OutcomeFailed       = "failed"        // the wipe or the certificate failed
	OutcomeRefused      = "refused"       // a guard or precondition refused the device
)

var outcomes = map[string]bool{OutcomeCertified: true, OutcomeNotCertified: true, OutcomeVerifyFailed: true,
	OutcomeInterrupted: true, OutcomeFailed: true, OutcomeRefused: true}

var ErrInvalid = errors.New("batch manifest invalid")

// Manifest is the signed body.
type Manifest struct {
	Format  string       `json:"format"`
	Version int          `json:"version"`
	BatchID string       `json:"batch_id"` // 32 hex digits
	Created string       `json:"created"`  // RFC 3339 UTC, seconds
	Tool    string       `json:"tool"`
	Station cert.Station `json:"station"`
	Items   []Item       `json:"items"`
}

// Item is one device of the batch.
type Item struct {
	Path          string `json:"path"`
	Model         string `json:"model"`
	Serial        string `json:"serial"`
	Fingerprint   string `json:"fingerprint"`
	Method        string `json:"method"`
	NISTLevel     string `json:"nist_level"`
	Outcome       string `json:"outcome"`
	WipeID        string `json:"wipe_id"`
	CertificateID string `json:"certificate_id"` // set exactly when Outcome is certified
	Error         string `json:"error"`
}

// ItemFor is the item of a certified device.
func ItemFor(r *cert.Result) Item {
	c := r.Certificate
	return Item{Path: c.Device.Path, Model: c.Device.Model, Serial: c.Device.Serial, Fingerprint: c.Device.Fingerprint,
		Method: c.Erasure.Method, NISTLevel: c.Erasure.NISTLevel, Outcome: OutcomeCertified, WipeID: c.WipeID, CertificateID: r.ID}
}

type envelope struct {
	Log       json.RawMessage `json:"log"`
	Manifest  json.RawMessage `json:"manifest"`
	Signature string          `json:"signature"`
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && s == hexLower(s)
}

func hexLower(s string) string {
	b, _ := hex.DecodeString(s)
	return hex.EncodeToString(b)
}

func (m Manifest) check() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(f, a...)) }
	switch {
	case m.Format != Format || m.Version != Version:
		return bad("format %q version %d", m.Format, m.Version)
	case !isHex(m.BatchID, 32):
		return bad("batch_id must be 32 lowercase hex digits")
	case len(m.Items) == 0 || len(m.Items) > MaxItems:
		return bad("%d items (1 to %d)", len(m.Items), MaxItems)
	case m.Station.KeyID == "":
		return bad("no station")
	}
	if _, err := keys.ParseTime(m.Created); err != nil {
		return bad("created: %v", err)
	}
	seen := map[string]bool{}
	for i, it := range m.Items {
		switch {
		case !outcomes[it.Outcome]:
			return bad("item %d: unknown outcome %q", i+1, it.Outcome)
		case it.Fingerprint == "":
			return bad("item %d: no device fingerprint", i+1)
		case seen[it.Fingerprint]:
			return bad("item %d: device %s listed twice", i+1, it.Fingerprint)
		case (it.Outcome == OutcomeCertified) != (it.CertificateID != ""):
			return bad("item %d: a certificate ID is given exactly for certified devices", i+1)
		case it.CertificateID != "" && !isHex(it.CertificateID, 64):
			return bad("item %d: certificate_id must be 64 lowercase hex digits", i+1)
		}
		seen[it.Fingerprint] = true
	}
	return nil
}

// Sign checks the body and returns the signed manifest file.
func Sign(m Manifest, priv ed25519.PrivateKey) ([]byte, error) {
	m.Format, m.Version = Format, Version
	if err := m.check(); err != nil {
		return nil, err
	}
	if m.Station.KeyID != keys.KeyID(priv.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("%w: body names station %s, not the signing key", ErrInvalid, m.Station.KeyID)
	}
	body, err := jcs.Marshal(m)
	if err != nil {
		return nil, err
	}
	sig, err := keys.SignJSON(priv, Ctx, json.RawMessage(body))
	if err != nil {
		return nil, err
	}
	out, err := jcs.Marshal(envelope{Log: json.RawMessage("null"), Manifest: body, Signature: sig})
	if err != nil {
		return nil, err
	}
	if len(out)+1 > MaxBytes {
		return nil, fmt.Errorf("%w: %d bytes, more than one log entry holds", ErrInvalid, len(out)+1)
	}
	return append(out, '\n'), nil
}

// Result is a verified manifest.
type Result struct {
	Manifest Manifest
	ID       string // hex SHA-256 of the canonical body
	Trust    string
	Logged   *cert.LogStatus
	Warnings []string
}

// Certified counts the certified devices; Failed every other one.
func (r *Result) Certified() int {
	n := 0
	for _, it := range r.Manifest.Items {
		if it.Outcome == OutcomeCertified {
			n++
		}
	}
	return n
}

func (r *Result) Failed() int { return len(r.Manifest.Items) - r.Certified() }

func decode(file []byte) (envelope, error) {
	var e envelope
	if len(file) > MaxBytes {
		return e, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxBytes)
	}
	if !bytes.HasSuffix(file, []byte("\n")) || !jcs.IsCanonical(file[:len(file)-1]) {
		return e, fmt.Errorf("%w: not in canonical form (modified or not written by Shunya)", ErrInvalid)
	}
	if err := cert.StrictDecode(file[:len(file)-1], &e); err != nil {
		return e, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return e, nil
}

// Verify checks a manifest file: form, signature, the station's trust under p (as for
// certificates) and, if present, the log proof.
func Verify(file []byte, p cert.Policy) (*Result, error) {
	e, err := decode(file)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := cert.StrictDecode(e.Manifest, &m); err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrInvalid, err)
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	pubB, err := hex.DecodeString(m.Station.PublicKey)
	if err != nil || len(pubB) != ed25519.PublicKeySize || keys.KeyID(pubB) != m.Station.KeyID {
		return nil, fmt.Errorf("%w: station public key", ErrInvalid)
	}
	if err := keys.VerifyCanonical(pubB, Ctx, e.Manifest, e.Signature); err != nil {
		return nil, fmt.Errorf("batch manifest: %w", err)
	}
	h := cert.ID(e.Manifest)
	r := &Result{Manifest: m, ID: h}
	entry, err := entryOf(e)
	if err != nil {
		return nil, err
	}
	var warn []string
	if r.Logged, warn, err = cert.CheckLogProof(e.Log, entry, p); err != nil {
		return nil, err
	}
	r.Warnings = append(r.Warnings, warn...)
	trust, warn, err := cert.CheckStation(m.Station, m.Created, p)
	if err != nil {
		return nil, err
	}
	r.Trust, r.Warnings = trust, append(r.Warnings, warn...)
	return r, nil
}

// CheckCertificates matches verified certificates against the manifest: every
// certified device needs one with its ID, for the same device, wipe and station.
// It returns one line per problem (none: the batch is complete).
func (r *Result) CheckCertificates(certs []*cert.Result) []string {
	byID := map[string]*cert.Result{}
	for _, c := range certs {
		byID[c.ID] = c
	}
	var probs []string
	for i, it := range r.Manifest.Items {
		if it.Outcome != OutcomeCertified {
			continue
		}
		c, ok := byID[it.CertificateID]
		name := fmt.Sprintf("item %d (%s, serial %s)", i+1, it.Path, it.Serial)
		switch {
		case !ok:
			probs = append(probs, name+": certificate "+it.CertificateID+" not found")
		case c.Certificate.Device.Fingerprint != it.Fingerprint || c.Certificate.WipeID != it.WipeID:
			probs = append(probs, name+": the certificate is for another device or wipe")
		case c.Certificate.Station.KeyID != r.Manifest.Station.KeyID:
			probs = append(probs, name+": the certificate is from another station")
		}
	}
	return probs
}

func entryOf(e envelope) ([]byte, error) {
	b, err := jcs.Marshal(envelope{Log: json.RawMessage("null"), Manifest: e.Manifest, Signature: e.Signature})
	if err != nil {
		return nil, err
	}
	return logentry.Entry(logentry.TypeManifest, b)
}

// LogEntry is the log entry for a manifest file (form checked, not the signature).
func LogEntry(file []byte) ([]byte, error) {
	e, err := decode(file)
	if err != nil {
		return nil, err
	}
	return entryOf(e)
}

// FileID is the ID of a manifest file (its body's hash), without verifying it.
func FileID(file []byte) (string, error) {
	e, err := decode(file)
	if err != nil {
		return "", err
	}
	return cert.ID(e.Manifest), nil
}

// IsManifest reports whether file looks like a manifest (has a "manifest" member),
// without verifying it.
func IsManifest(file []byte) bool {
	var probe struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	return json.Unmarshal(file, &probe) == nil && len(probe.Manifest) > 0
}

// WithLog returns the manifest file with its inclusion proof attached.
func WithLog(file []byte, in logentry.Inclusion) ([]byte, error) {
	e, err := decode(file)
	if err != nil {
		return nil, err
	}
	if e.Log, err = jcs.Marshal(in); err != nil {
		return nil, err
	}
	out, err := jcs.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
