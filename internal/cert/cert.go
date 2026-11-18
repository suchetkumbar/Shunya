// Package cert is Shunya's erasure certificate: the signed statement that a device was
// wiped, how, to which NIST SP 800-88 level, and how that was checked.
//
// A certificate file is the RFC 8785 canonical form of
//
//	{"certificate": BODY, "log": null, "signature": BASE64}
//
// followed by one newline. The signature is the station key's Ed25519 signature over
// the context keys.CtxCertificate and BODY's canonical bytes; the station key is
// certified by the organisation's root (keys.StationCert, embedded in BODY). The
// certificate ID is the SHA-256 of BODY's canonical bytes: the QR code carries it.
// "log" will hold the transparency-log inclusion proof (Milestone 8); it is outside
// the signature because it is added after signing and proves itself.
//
// Verify requires the exact canonical bytes, so any change to the file — even one
// that keeps the JSON meaning, such as added whitespace — fails.
package cert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"shunya/internal/jcs"
	"shunya/internal/keys"
)

const (
	Format = "shunya-erasure-certificate"
	// ResultErasedVerified: the wipe completed and every recorded check passed. Shunya
	// issues no certificate for anything less.
	ResultErasedVerified = "erased-and-verified"
	// DefaultVerifyURL is a placeholder (".invalid" is reserved, RFC 2606) until the
	// public verifier exists (Milestone 8); set your own with --verify-url.
	DefaultVerifyURL = "https://verify.shunya.invalid/c/"
	// MaxBytes bounds a certificate file.
	MaxBytes = 1 << 20
	// MaxURL keeps URL + ID within a version-10 QR code.
	MaxURL = 100
)

// Trust levels.
const (
	TrustStation = "station-certificate" // signed by a station key the root certified
	TrustDevKey  = "dev-key"             // signed by a key nobody certified (Milestones 3–6)
)

var (
	ErrInvalid       = errors.New("certificate invalid")
	ErrNotCanonical  = errors.New("certificate file is not in canonical form (modified or not written by Shunya)")
	ErrDevKey        = errors.New("certificate signed by an uncertified development key")
	ErrNoRevocations = errors.New("no revocation list given (or explicitly skip the check)")
)

// Certificate is the signed body.
type Certificate struct {
	Format        string         `json:"format"`
	Version       int            `json:"version"`
	WipeID        string         `json:"wipe_id"`
	Issued        string         `json:"issued"` // RFC 3339 UTC, seconds
	Result        string         `json:"result"`
	Tool          Tool           `json:"tool"`
	Device        Device         `json:"device"`
	Erasure       Erasure        `json:"erasure"`
	Hidden        Hidden         `json:"hidden_areas"`
	Verification  []Verification `json:"verification"`
	Interruptions []Interruption `json:"interruptions"`
	Journal       Journal        `json:"journal"`
	Station       Station        `json:"station"`
	VerifyURL     string         `json:"verify_url"`
}

// Tool identifies the binaries that wiped and that issued the certificate. Build
// hashes are SHA-256 of the executable; Shunya's builds are reproducible, so anyone
// can rebuild the tagged source and compare.
type Tool struct {
	Wipe            string `json:"wipe"`
	WipeBuildHash   string `json:"wipe_build_hash"` // "" for journals written before Milestone 7
	Issuer          string `json:"issuer"`
	IssuerBuildHash string `json:"issuer_build_hash"`
	Build           string `json:"build"` // dev or release (issuer)
}

// Device is the wiped target as identified when the wipe was planned.
type Device struct {
	Path              string `json:"path"`
	Model             string `json:"model"`
	Serial            string `json:"serial"`
	WWID              string `json:"wwid"`
	SizeBytes         int64  `json:"size_bytes"`
	Fingerprint       string `json:"fingerprint"`
	NativeFingerprint string `json:"native_fingerprint"`
	Media             string `json:"media"`
	Virtual           bool   `json:"virtual"`
}

// Erasure is what was done.
type Erasure struct {
	Method     string   `json:"method"`
	NISTLevel  string   `json:"nist_level"`
	Passes     []string `json:"passes"` // overwrite patterns (never their keys)
	SizeBytes  int64    `json:"size_bytes"`
	SectorSize int      `json:"sector_size"`
	Started    string   `json:"started"`
	Finished   string   `json:"finished"`
	Steps      []Step   `json:"steps"` // firmware erase / Security Erase steps, in order
	Notes      []string `json:"notes"` // the plan's caveats
}

// Step is one recorded firmware or Security Erase step (no passwords).
type Step struct {
	Step   string `json:"step"`
	Detail string `json:"detail"`
}

// Hidden is the state of HPA/DCO hidden areas and what was done about them.
type Hidden struct {
	Checked    bool   `json:"checked"`
	Reason     string `json:"reason"`
	HPA        bool   `json:"hpa"`
	HPASectors uint64 `json:"hpa_sectors"`
	DCO        string `json:"dco"`
	DCOSectors uint64 `json:"dco_sectors"`
	Policy     string `json:"policy"`
	Wiped      bool   `json:"hpa_wiped"`   // the HPA was removed for the wipe and its sectors erased
	Final      string `json:"final_state"` // last hidden-area event
	KeepReason string `json:"keep_reason"`
}

// Verification is one read-back check.
type Verification struct {
	Mode       string  `json:"mode"` // full, sampled or markers
	Pattern    string  `json:"pattern"`
	OK         bool    `json:"ok"`
	BytesRead  int64   `json:"bytes_read"`
	BadSectors int64   `json:"bad_sectors"`
	Samples    int     `json:"samples"`
	SeedSource string  `json:"seed_source"`
	Seed       string  `json:"seed"`
	Bound95    float64 `json:"bound95"`
	Scope      string  `json:"scope"`
}

// Interruption is one stop and resume.
type Interruption struct {
	Kind      string `json:"kind"`
	Reason    string `json:"reason"`
	Pass      int    `json:"pass"`
	Offset    int64  `json:"offset"`
	StoppedAt string `json:"stopped_at"`
	ResumedAt string `json:"resumed_at"`
	TornBytes int    `json:"torn_bytes"`
}

// Journal binds the certificate to the signed progress journal it summarises.
type Journal struct {
	SHA256  string `json:"sha256"` // of the journal's verified bytes
	Records int    `json:"records"`
	KeyID   string `json:"key_id"`
}

// Station is the signer.
type Station struct {
	KeyID       string            `json:"key_id"`
	PublicKey   string            `json:"public_key"`
	Name        string            `json:"name"`
	Certificate *keys.StationCert `json:"certificate"` // nil: dev key
}

// StationFor describes a signer; sc is its station certificate, or nil for a dev key.
func StationFor(pub ed25519.PublicKey, sc *keys.StationCert) Station {
	s := Station{KeyID: keys.KeyID(pub), PublicKey: hex.EncodeToString(pub), Certificate: sc}
	if sc != nil {
		s.Name = sc.Station
	}
	return s
}

type envelope struct {
	Certificate json.RawMessage `json:"certificate"`
	Log         json.RawMessage `json:"log"`
	Signature   string          `json:"signature"`
}

// ID is the certificate ID: hex SHA-256 of the body's canonical bytes.
func ID(canonicalBody []byte) string {
	h := sha256.Sum256(canonicalBody)
	return hex.EncodeToString(h[:])
}

// BodyID is the ID of a certificate body.
func BodyID(c Certificate) (string, error) {
	b, err := jcs.Marshal(c)
	if err != nil {
		return "", err
	}
	return ID(b), nil
}

// Canonical returns b's canonical form with the trailing newline of a certificate file.
func Canonical(b []byte) ([]byte, error) {
	c, err := jcs.Canonicalize(b)
	if err != nil {
		return nil, err
	}
	return append(c, '\n'), nil
}

// Sign checks the body and returns the signed certificate file.
func Sign(c Certificate, priv ed25519.PrivateKey) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if c.Station.KeyID != keys.KeyID(pub) {
		return nil, fmt.Errorf("%w: body names station %s, signing key is %s", ErrInvalid, c.Station.KeyID, keys.KeyID(pub))
	}
	body, err := jcs.Marshal(c)
	if err != nil {
		return nil, err
	}
	sig, err := keys.SignJSON(priv, keys.CtxCertificate, json.RawMessage(body))
	if err != nil {
		return nil, err
	}
	out, err := jcs.Marshal(envelope{Certificate: body, Log: json.RawMessage("null"), Signature: sig})
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// Policy is what a verifier trusts.
type Policy struct {
	Root           ed25519.PublicKey
	Revocations    *keys.RevocationList // verified by the caller against Root, or checked here
	SkipRevocation bool                 // explicitly verify without a revocation list
	AllowDevKey    bool                 // accept certificates from uncertified dev keys (marked)
}

// Result is a verified certificate.
type Result struct {
	Certificate Certificate
	ID          string
	Trust       string
	Body        []byte // canonical body
	Warnings    []string
}

// QRPayload is what the certificate's QR code holds: the verification URL and ID.
func (r *Result) QRPayload() string { return r.Certificate.VerifyURL + r.ID }

// Verify checks a certificate file completely: form, signature, station certificate,
// revocation and the body's internal consistency.
func Verify(file []byte, p Policy) (*Result, error) {
	if len(file) > MaxBytes {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrInvalid, MaxBytes)
	}
	if !bytes.HasSuffix(file, []byte("\n")) || !jcs.IsCanonical(file[:len(file)-1]) {
		return nil, ErrNotCanonical
	}
	var e envelope
	if err := strict(file, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if string(e.Log) != "null" {
		return nil, fmt.Errorf("%w: log proofs are not supported by this verifier version", ErrInvalid)
	}
	var c Certificate // every member present, none defaulted: it re-encodes to the signed bytes
	if err := strict(e.Certificate, &c); err != nil {
		return nil, fmt.Errorf("%w: body: %v", ErrInvalid, err)
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	pubB, err := hex.DecodeString(c.Station.PublicKey)
	if err != nil || len(pubB) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: station public key", ErrInvalid)
	}
	pub := ed25519.PublicKey(pubB)
	if keys.KeyID(pub) != c.Station.KeyID {
		return nil, fmt.Errorf("%w: station key id does not match its key", ErrInvalid)
	}
	if err := keys.VerifyCanonical(pub, keys.CtxCertificate, e.Certificate, e.Signature); err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	r := &Result{Certificate: c, ID: ID(e.Certificate), Body: e.Certificate}
	issued, _ := keys.ParseTime(c.Issued)

	if c.Station.Certificate == nil {
		if !p.AllowDevKey {
			return nil, ErrDevKey
		}
		r.Trust = TrustDevKey
		r.Warnings = append(r.Warnings, "signed by an uncertified development key: proves only that this file is unchanged since that key signed it")
		return r, nil
	}
	sc := *c.Station.Certificate
	if err := sc.Verify(p.Root); err != nil {
		return nil, err
	}
	if sc.PublicKey != c.Station.PublicKey || sc.Station != c.Station.Name {
		return nil, fmt.Errorf("%w: station certificate is for another key or name", ErrInvalid)
	}
	if !sc.ValidAt(issued) {
		return nil, fmt.Errorf("%w: issued %s, outside the station certificate's validity (%s – %s)", ErrInvalid, c.Issued, sc.NotBefore, sc.NotAfter)
	}
	switch {
	case p.Revocations != nil:
		if err := p.Revocations.Verify(p.Root); err != nil {
			return nil, err
		}
		if err := p.Revocations.Check(c.Station.KeyID, issued); err != nil {
			return nil, err
		}
	case p.SkipRevocation:
		r.Warnings = append(r.Warnings, "revocation status not checked")
	default:
		return nil, ErrNoRevocations
	}
	r.Trust = TrustStation
	return r, nil
}

// strict decodes canonical JSON b into v and requires that v encodes back to exactly
// b. encoding/json alone is not enough: it matches member names case-insensitively
// ("Certificate" fills Certificate) and defaults missing members.
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("data after the object")
	}
	again, err := jcs.Marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, bytes.TrimSuffix(b, []byte("\n"))) {
		return errors.New("members missing, misspelt or malformed")
	}
	return nil
}

// methods are the engine's erase methods (engine's tests check the two lists agree).
var methods = map[string]bool{
	"overwrite": true, "ata-secure-erase": true, "ata-enhanced-secure-erase": true,
	"ata-sanitize-crypto-scramble": true, "ata-sanitize-block-erase": true, "ata-sanitize-overwrite": true,
	"nvme-format-user-data-erase": true, "nvme-format-crypto-erase": true,
	"nvme-sanitize-crypto-erase": true, "nvme-sanitize-block-erase": true, "nvme-sanitize-overwrite": true,
}

// KnownMethod reports whether a certificate may name method m.
func KnownMethod(m string) bool { return methods[m] }

// check validates the body's form and internal consistency.
func (c Certificate) check() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(f, a...)) }
	switch {
	case c.Format != Format || c.Version != 1:
		return bad("unsupported format %q version %d", c.Format, c.Version)
	case len(c.WipeID) != 32 || strings.Trim(c.WipeID, "0123456789abcdef") != "":
		return bad("wipe id %q", c.WipeID)
	case c.Result != ResultErasedVerified:
		return bad("result %q", c.Result)
	case !methods[c.Erasure.Method]:
		return bad("unknown method %q", c.Erasure.Method)
	case c.Erasure.NISTLevel != "clear" && c.Erasure.NISTLevel != "purge":
		return bad("NIST level %q", c.Erasure.NISTLevel)
	case c.Erasure.Method == "overwrite" && c.Erasure.NISTLevel != "clear":
		return bad("an overwrite achieves Clear, never Purge")
	case c.Device.Virtual && c.Erasure.NISTLevel != "clear":
		return bad("a virtual disk's erase cannot be shown to reach the media: Clear at most")
	case len(c.Verification) == 0:
		return bad("no verification recorded")
	case !strings.HasPrefix(c.VerifyURL, "https://") || len(c.VerifyURL) > MaxURL || strings.ContainsAny(c.VerifyURL, " \"<>\\^`{|}"):
		return bad("verify URL %q (https, at most %d characters)", c.VerifyURL, MaxURL)
	case c.Journal.KeyID != c.Station.KeyID:
		return bad("journal signed by %s, certificate by %s", c.Journal.KeyID, c.Station.KeyID)
	case len(c.Journal.SHA256) != 64:
		return bad("journal hash")
	}
	for i, v := range c.Verification {
		if !v.OK {
			return bad("verification %d (%s) failed", i+1, v.Mode)
		}
	}
	if _, err := keys.ParseTime(c.Issued); err != nil {
		return bad("issued: %v", err)
	}
	if c.Station.Certificate == nil && c.Station.Name != "" {
		return bad("a dev-key station has no certified name")
	}
	return nil
}
