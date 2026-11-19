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
// "log" holds the transparency-log inclusion proof once the certificate is logged
// (logentry.Inclusion); it is outside the signature because it is added after signing
// and proves itself against the log's key. The logged entry is the envelope with
// "log": null (LogEntry).
//
// Version 2 (Milestone 8) adds, for a sampled verification whose seed came from the
// log, the signed seed request and its inclusion proof, from which a verifier
// recomputes the seed. Version 1 certificates still verify.
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
	"time"

	"shunya/internal/checkpoint"
	"shunya/internal/jcs"
	"shunya/internal/keys"
	"shunya/internal/logentry"
	"shunya/internal/note"
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
	// Version is what Shunya issues; Verify accepts 1 and 2.
	Version = 2
)

// Seed sources (engine.Seed*) as certificates name them.
const (
	SeedOperator = "operator"
	SeedTlog     = "tlog-checkpoint"
	SeedLocal    = "local-random"
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
	// Version 2, seed source tlog-checkpoint only: the station's signed request and
	// the log's checkpoint with the request's inclusion proof.
	SeedRequest *logentry.SeedRequest `json:"seed_request,omitempty"`
	SeedLog     *logentry.Inclusion   `json:"seed_log,omitempty"`
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
	LogKey         *note.Verifier       // the transparency log's key: check log proofs
	RequireLog     bool                 // refuse certificates without a log inclusion proof
}

// LogStatus is a certificate's place in the transparency log.
type LogStatus struct {
	Index      uint64
	Checkpoint checkpoint.Checkpoint // verified against Policy.LogKey when Checked
	Checked    bool
}

// Result is a verified certificate.
type Result struct {
	Certificate Certificate
	ID          string
	Trust       string
	Body        []byte // canonical body
	Logged      *LogStatus
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
	if err := r.checkLog(e, p); err != nil {
		return nil, err
	}
	if err := r.checkSeeds(p); err != nil {
		return nil, err
	}

	trust, warn, err := CheckStation(c.Station, c.Issued, p)
	if err != nil {
		return nil, err
	}
	r.Trust, r.Warnings = trust, append(r.Warnings, warn...)
	return r, nil
}

// CheckStation decides whether the signer st (whose signature the caller verified)
// is trusted under p for a document dated issued: a station certificate from the
// root, valid then, for this key and name, and not revoked; or a dev key if allowed.
// Batch manifests use the same rules as certificates.
func CheckStation(st Station, issued string, p Policy) (trust string, warnings []string, err error) {
	if st.Certificate == nil {
		if !p.AllowDevKey {
			return "", nil, ErrDevKey
		}
		return TrustDevKey, []string{"signed by an uncertified development key: proves only that this file is unchanged since that key signed it"}, nil
	}
	at, err := keys.ParseTime(issued)
	if err != nil {
		return "", nil, fmt.Errorf("%w: issued: %v", ErrInvalid, err)
	}
	sc := *st.Certificate
	if err := sc.Verify(p.Root); err != nil {
		return "", nil, err
	}
	if sc.PublicKey != st.PublicKey || sc.Station != st.Name {
		return "", nil, fmt.Errorf("%w: station certificate is for another key or name", ErrInvalid)
	}
	if !sc.ValidAt(at) {
		return "", nil, fmt.Errorf("%w: issued %s, outside the station certificate's validity (%s – %s)", ErrInvalid, issued, sc.NotBefore, sc.NotAfter)
	}
	switch {
	case p.Revocations != nil:
		if err := p.Revocations.Verify(p.Root); err != nil {
			return "", nil, err
		}
		if err := p.Revocations.Check(st.KeyID, at); err != nil {
			return "", nil, err
		}
	case p.SkipRevocation:
		warnings = append(warnings, "revocation status not checked")
	default:
		return "", nil, ErrNoRevocations
	}
	return TrustStation, warnings, nil
}

// checkLog verifies the envelope's log proof, if any, against the log key.
func (r *Result) checkLog(e envelope, p Policy) error {
	entry, err := entryOf(e.Certificate, e.Signature)
	if err != nil {
		return err
	}
	st, warn, err := CheckLogProof(e.Log, entry, p)
	r.Logged, r.Warnings = st, append(r.Warnings, warn...)
	return err
}

// CheckLogProof checks a file's "log" member (null, or a logentry.Inclusion) for the
// log entry the file is logged as. It returns nil status for an unlogged file.
func CheckLogProof(raw json.RawMessage, entry []byte, p Policy) (*LogStatus, []string, error) {
	if string(raw) == "null" {
		if p.RequireLog {
			return nil, nil, fmt.Errorf("%w: not logged (no inclusion proof) and the policy requires it", ErrInvalid)
		}
		return nil, nil, nil
	}
	var in logentry.Inclusion
	if err := strict(raw, &in); err != nil {
		return nil, nil, fmt.Errorf("%w: log proof: %v", ErrInvalid, err)
	}
	st := &LogStatus{Index: in.Index}
	if p.LogKey == nil {
		if p.RequireLog {
			return st, nil, fmt.Errorf("%w: a log proof is required but no log key was given", ErrInvalid)
		}
		return st, []string{fmt.Sprintf("log inclusion proof (entry %d) not checked: no log key given", in.Index)}, nil
	}
	cp, err := in.Verify(entry, p.LogKey)
	if err != nil {
		return st, nil, fmt.Errorf("%w: log proof: %v", ErrInvalid, err)
	}
	st.Checkpoint, st.Checked = cp, true
	return st, nil, nil
}

// StrictDecode decodes canonical JSON b into v and requires v to encode back to b
// exactly (see strict); for other signed Shunya files.
func StrictDecode(b []byte, v any) error { return strict(b, v) }

// checkSeeds checks each log-seeded sampled verification: the seed request is the
// station's, for this wipe and device, made after the erase finished; the seed is the
// one the checkpoint gives; and (with a log key) the checkpoint is the log's and
// includes the request.
func (r *Result) checkSeeds(p Policy) error {
	c := r.Certificate
	for i, v := range c.Verification {
		bad := func(f string, a ...any) error {
			return fmt.Errorf("%w: verification %d: %s", ErrInvalid, i+1, fmt.Sprintf(f, a...))
		}
		switch v.SeedSource {
		case SeedOperator:
			r.Warnings = append(r.Warnings, fmt.Sprintf("verification %d: sampled with an operator-chosen seed (the station could have chosen which sectors to read)", i+1))
		case SeedLocal:
			r.Warnings = append(r.Warnings, fmt.Sprintf("verification %d: sampled offline with a station-generated random seed (not independently unpredictable)", i+1))
		}
		if v.SeedSource != SeedTlog {
			continue
		}
		q, l := v.SeedRequest, v.SeedLog
		if err := q.Verify(); err != nil {
			return bad("seed request: %v", err)
		}
		switch {
		case q.WipeID != c.WipeID:
			return bad("seed request is for wipe %s", q.WipeID)
		case q.Fingerprint != c.Device.Fingerprint && q.Fingerprint != c.Device.NativeFingerprint:
			return bad("seed request is for device %s", q.Fingerprint)
		case q.StationKeyID != c.Station.KeyID:
			return bad("seed request made by station %s", q.StationKeyID)
		}
		req, _ := keys.ParseTime(q.Requested)
		// The request time has whole seconds; the finish time may have fractions.
		if fin, err := keys.ParseTime(c.Erasure.Finished); err == nil && req.Before(fin.Truncate(time.Second)) {
			return bad("seed requested at %s, before the erase finished at %s", q.Requested, c.Erasure.Finished)
		}
		text, err := l.CheckpointText()
		if err != nil {
			return bad("seed checkpoint: %v", err)
		}
		if hex.EncodeToString(logentry.Seed(text, q.Fingerprint)) != v.Seed {
			return bad("the seed is not the one the log checkpoint gives")
		}
		if p.LogKey == nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("verification %d: the log checkpoint behind the sampling seed was not checked: no log key given", i+1))
			continue
		}
		entry, err := q.Entry()
		if err != nil {
			return bad("seed request: %v", err)
		}
		if _, err := l.Verify(entry, p.LogKey); err != nil {
			return bad("seed request not in the log: %v", err)
		}
	}
	return nil
}

func entryOf(body []byte, sig string) ([]byte, error) {
	b, err := jcs.Marshal(envelope{Certificate: body, Log: json.RawMessage("null"), Signature: sig})
	if err != nil {
		return nil, err
	}
	return logentry.Entry(logentry.TypeCertificate, b)
}

// LogEntry is the transparency-log entry for a certificate file: its envelope with
// "log": null. The file's form is checked, not its signature.
func LogEntry(file []byte) ([]byte, error) {
	if !bytes.HasSuffix(file, []byte("\n")) || !jcs.IsCanonical(file[:len(file)-1]) {
		return nil, ErrNotCanonical
	}
	var e envelope
	if err := strict(file, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return entryOf(e.Certificate, e.Signature)
}

// WithLog returns the certificate file with its log inclusion proof attached
// (replacing any earlier one). The signature is unaffected.
func WithLog(file []byte, in logentry.Inclusion) ([]byte, error) {
	var e envelope
	if err := strict(file, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	l, err := jcs.Marshal(in)
	if err != nil {
		return nil, err
	}
	e.Log = l
	out, err := jcs.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// FromEntry turns a certificate log entry back into a certificate file (no proof).
func FromEntry(entry []byte) ([]byte, error) {
	typ, payload, err := logentry.Split(entry)
	if err != nil || typ != logentry.TypeCertificate {
		return nil, fmt.Errorf("%w: not a certificate entry", ErrInvalid)
	}
	return append(append([]byte(nil), payload...), '\n'), nil
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

// ValidVerifyURL: https, or http to the loopback address (a local verifier for demos
// and labs); printable without quoting; short enough for the QR code.
func ValidVerifyURL(u string) bool {
	local := strings.HasPrefix(u, "http://127.0.0.1:") || strings.HasPrefix(u, "http://127.0.0.1/") ||
		strings.HasPrefix(u, "http://localhost:") || strings.HasPrefix(u, "http://localhost/")
	return (strings.HasPrefix(u, "https://") || local) && len(u) <= MaxURL && !strings.ContainsAny(u, " \"<>\\^`{|}")
}

// KnownMethod reports whether a certificate may name method m.
func KnownMethod(m string) bool { return methods[m] }

// check validates the body's form and internal consistency.
func (c Certificate) check() error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(f, a...)) }
	switch {
	case c.Format != Format || (c.Version != 1 && c.Version != 2):
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
	case !ValidVerifyURL(c.VerifyURL):
		return bad("verify URL %q (https, or http to this machine only; at most %d characters)", c.VerifyURL, MaxURL)
	case c.Journal.KeyID != c.Station.KeyID:
		return bad("journal signed by %s, certificate by %s", c.Journal.KeyID, c.Station.KeyID)
	case len(c.Journal.SHA256) != 64:
		return bad("journal hash")
	}
	for i, v := range c.Verification {
		if !v.OK {
			return bad("verification %d (%s) failed", i+1, v.Mode)
		}
		hasLog := v.SeedRequest != nil || v.SeedLog != nil
		switch {
		case hasLog && (c.Version < 2 || v.SeedSource != SeedTlog):
			return bad("verification %d: seed request on a %q seed (version %d)", i+1, v.SeedSource, c.Version)
		case v.SeedSource == SeedTlog && (v.SeedRequest == nil || v.SeedLog == nil):
			return bad("verification %d: log seed without its request and checkpoint", i+1)
		case v.SeedSource == SeedTlog && v.Mode != "sampled":
			return bad("verification %d: log seed on a %s verification", i+1, v.Mode)
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
