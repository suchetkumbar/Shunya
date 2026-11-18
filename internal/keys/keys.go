// Package keys is Shunya's key hierarchy (brief Milestone 7):
//
//	offline root key ──signs──▶ station certificates (one per wiping station)
//	                 └─signs──▶ revocation list (numbered; newer replaces older)
//	station key ─────signs──▶ journals and erasure certificates
//
// The root key lives in a passphrase-encrypted file on an offline machine
// (PBKDF2-SHA256 + AES-256-GCM, every header field bound as additional data). Only its
// public key travels: a verifier needs nothing else. Every signature covers a context
// string and the RFC 8785 canonical form of the signed object, so a signature made for
// one kind of document never verifies as another.
package keys

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"shunya/internal/jcs"
	"shunya/internal/journal"
)

// Signature contexts.
const (
	CtxStationCert = "shunya/station-certificate/v1"
	CtxRevocations = "shunya/revocation-list/v1"
	CtxCertificate = "shunya/erasure-certificate/v1"
)

var (
	// ErrPassphrase: the root key file did not decrypt (wrong passphrase or edited).
	ErrPassphrase = errors.New("wrong passphrase, or the root key file was modified")
	// ErrSignature: a signature did not verify.
	ErrSignature = errors.New("signature does not verify")
	// ErrRevoked is wrapped when the revocation list refuses a station key.
	ErrRevoked = errors.New("station key revoked")
)

// KeyID names a public key (the same IDs journals use).
func KeyID(pub ed25519.PublicKey) string { return journal.KeyID(pub) }

func b64(b []byte) string  { return base64.StdEncoding.EncodeToString(b) }
func hexs(b []byte) string { return hex.EncodeToString(b) }

func signingInput(ctx string, canonical []byte) []byte {
	return append(append([]byte(ctx), 0), canonical...)
}

// SignJSON signs the canonical form of v in context ctx (base64 signature).
func SignJSON(priv ed25519.PrivateKey, ctx string, v any) (string, error) {
	c, err := jcs.Marshal(v)
	if err != nil {
		return "", err
	}
	return b64(ed25519.Sign(priv, signingInput(ctx, c))), nil
}

// VerifyCanonical checks sig over canonical, which must already be in canonical form.
func VerifyCanonical(pub ed25519.PublicKey, ctx string, canonical []byte, sig string) error {
	if !jcs.IsCanonical(canonical) {
		return fmt.Errorf("%w: signed data is not canonical JSON", ErrSignature)
	}
	s, err := base64.StdEncoding.Strict().DecodeString(sig)
	if err != nil || len(s) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: malformed signature or key", ErrSignature)
	}
	if !ed25519.Verify(pub, signingInput(ctx, canonical), s) {
		return ErrSignature
	}
	return nil
}

// decodeStrict unmarshals one JSON object, refusing unknown members and trailing data.
func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("data after the object")
	}
	return nil
}

// unsigned returns the canonical form of the object in raw without its "signature"
// member, and that member. It is what the signature covers, taken from the bytes as
// they are (not from a re-encoding, which could drop or default members).
func unsigned(raw []byte) (body []byte, sig string, err error) {
	if _, err := jcs.Canonicalize(raw); err != nil { // strict: no duplicate members
		return nil, "", err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "", err
	}
	if s, ok := m["signature"]; ok {
		if err := json.Unmarshal(s, &sig); err != nil {
			return nil, "", fmt.Errorf("signature: %w", err)
		}
		delete(m, "signature")
	}
	body, err = jcs.Marshal(m)
	return body, sig, err
}

// ParseTime reads the RFC 3339 UTC second-precision times used in signed documents.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || FormatTime(t) != s {
		return time.Time{}, fmt.Errorf("time %q: want RFC 3339 UTC to the second (2006-01-02T15:04:05Z)", s)
	}
	return t, nil
}

// FormatTime is ParseTime's inverse.
func FormatTime(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }

// --- root key file ---

const (
	rootFormat = "shunya-root-key-v1"
	rootKDF    = "pbkdf2-sha256"
	pubFormat  = "shunya-root-public-key-v1"
)

// rootIterations is the PBKDF2 cost for new root keys (OWASP 2023 for PBKDF2-SHA256).
// Loading accepts 1000…10 000 000 (an edited count fails decryption anyway; the upper
// bound stops a file from costing hours).
var rootIterations = 600_000

type rootFile struct {
	Format     string `json:"format"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	PublicKey  string `json:"public_key"`
	KeyID      string `json:"key_id"`
}

// aad is the header the AEAD binds: everything except nonce and ciphertext.
func (f rootFile) aad() ([]byte, error) {
	return jcs.Marshal(map[string]any{"format": f.Format, "kdf": f.KDF, "iterations": f.Iterations,
		"salt": f.Salt, "public_key": f.PublicKey, "key_id": f.KeyID})
}

func (f rootFile) aead(pass []byte) (cipher.AEAD, error) {
	salt, err := base64.StdEncoding.Strict().DecodeString(f.Salt)
	if err != nil || len(salt) < 16 {
		return nil, errors.New("bad salt")
	}
	k, err := pbkdf2.Key(sha256.New, string(pass), salt, f.Iterations, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// CreateRoot generates a root key and writes it, encrypted under pass, to path (0600,
// never overwriting an existing file).
func CreateRoot(path string, pass []byte) (ed25519.PublicKey, error) {
	if len(pass) == 0 {
		return nil, errors.New("root key: empty passphrase")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt, nonce := make([]byte, 16), make([]byte, 12)
	rand.Read(salt)
	rand.Read(nonce)
	f := rootFile{Format: rootFormat, KDF: rootKDF, Iterations: rootIterations, Salt: b64(salt),
		Nonce: b64(nonce), PublicKey: hexs(pub), KeyID: KeyID(pub)}
	g, err := f.aead(pass)
	if err != nil {
		return nil, err
	}
	aad, err := f.aad()
	if err != nil {
		return nil, err
	}
	f.Ciphertext = b64(g.Seal(nil, nonce, priv.Seed(), aad))
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return pub, writeNew(path, append(b, '\n'), 0o600)
}

// LoadRoot decrypts the root key at path.
func LoadRoot(path string, pass []byte) (ed25519.PrivateKey, error) {
	if err := privateFile(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f rootFile
	if err := decodeStrict(b, &f); err != nil {
		return nil, fmt.Errorf("root key %s: %w", path, err)
	}
	if f.Format != rootFormat || f.KDF != rootKDF {
		return nil, fmt.Errorf("root key %s: unsupported format %q / kdf %q", path, f.Format, f.KDF)
	}
	if f.Iterations < 1000 || f.Iterations > 10_000_000 {
		return nil, fmt.Errorf("root key %s: iteration count %d out of range", path, f.Iterations)
	}
	nonce, err1 := base64.StdEncoding.Strict().DecodeString(f.Nonce)
	ct, err2 := base64.StdEncoding.Strict().DecodeString(f.Ciphertext)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("root key %s: bad encoding", path)
	}
	g, err := f.aead(pass)
	if err != nil {
		return nil, fmt.Errorf("root key %s: %w", path, err)
	}
	if len(nonce) != g.NonceSize() {
		return nil, fmt.Errorf("root key %s: bad nonce", path)
	}
	aad, err := f.aad()
	if err != nil {
		return nil, err
	}
	seed, err := g.Open(nil, nonce, ct, aad)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrPassphrase
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if hexs(priv.Public().(ed25519.PublicKey)) != f.PublicKey || f.KeyID != KeyID(priv.Public().(ed25519.PublicKey)) {
		return nil, fmt.Errorf("root key %s: public key does not match", path)
	}
	return priv, nil
}

// privateFile refuses, on Unix, a key file readable by group or others.
func privateFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("key %s: permissions %v are too open (want 0600)", path, st.Mode().Perm())
	}
	return nil
}

// writeNew writes a new file (O_EXCL) and syncs it.
func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// WritePublic writes the root public key file ("shunya-root-public-key-v1 <hex>").
func WritePublic(path string, pub ed25519.PublicKey) error {
	return writeNew(path, []byte(pubFormat+" "+hexs(pub)+"\n"), 0o644)
}

// ReadPublic reads a public key file.
func ReadPublic(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublic(string(b))
}

// ParsePublic accepts a public key file's contents or a bare 64-digit hex key.
func ParsePublic(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if head, rest, ok := strings.Cut(s, " "); ok {
		if head != pubFormat {
			return nil, fmt.Errorf("not a %s file", pubFormat)
		}
		s = rest
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("public key: want 64 hex digits")
	}
	return ed25519.PublicKey(b), nil
}

// --- station certificates ---

const stationFormat = "shunya-station-certificate"

// StationCert is the root's statement that a station key may sign certificates
// between NotBefore and NotAfter.
type StationCert struct {
	Format    string `json:"format"`
	Version   int    `json:"version"`
	Station   string `json:"station"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	Issuer    string `json:"issuer"`
	Issued    string `json:"issued"`
	Signature string `json:"signature,omitempty"`
}

// IssueStation certifies a station key with the root key.
func IssueStation(root ed25519.PrivateKey, station string, pub ed25519.PublicKey, notBefore, notAfter, now time.Time) (StationCert, error) {
	if strings.TrimSpace(station) == "" || len(station) > 200 {
		return StationCert{}, errors.New("station certificate: name must be 1–200 bytes")
	}
	if len(pub) != ed25519.PublicKeySize {
		return StationCert{}, errors.New("station certificate: bad public key")
	}
	rootPub := root.Public().(ed25519.PublicKey)
	if bytes.Equal(pub, rootPub) {
		return StationCert{}, errors.New("station certificate: the root key must not be a station key")
	}
	if !notAfter.Truncate(time.Second).After(notBefore.Truncate(time.Second)) {
		return StationCert{}, errors.New("station certificate: not-after must follow not-before")
	}
	c := StationCert{Format: stationFormat, Version: 1, Station: station, PublicKey: hexs(pub), KeyID: KeyID(pub),
		NotBefore: FormatTime(notBefore), NotAfter: FormatTime(notAfter), Issuer: KeyID(rootPub), Issued: FormatTime(now)}
	sig, err := SignJSON(root, CtxStationCert, c)
	if err != nil {
		return StationCert{}, err
	}
	c.Signature = sig
	return c, nil
}

// Verify checks the certificate's form and the root's signature.
func (c StationCert) Verify(root ed25519.PublicKey) error {
	if c.Format != stationFormat || c.Version != 1 {
		return fmt.Errorf("station certificate: unsupported format %q version %d", c.Format, c.Version)
	}
	pub, err := c.Public()
	if err != nil {
		return err
	}
	if c.KeyID != KeyID(pub) {
		return errors.New("station certificate: key id does not match the key")
	}
	if c.Issuer != KeyID(root) {
		return fmt.Errorf("station certificate: issued by %s, not by root %s", c.Issuer, KeyID(root))
	}
	nb, err1 := ParseTime(c.NotBefore)
	na, err2 := ParseTime(c.NotAfter)
	_, err3 := ParseTime(c.Issued)
	if err := errors.Join(err1, err2, err3); err != nil {
		return fmt.Errorf("station certificate: %w", err)
	}
	if !na.After(nb) {
		return errors.New("station certificate: empty validity period")
	}
	u := c
	u.Signature = ""
	body, err := jcs.Marshal(u)
	if err != nil {
		return err
	}
	if err := VerifyCanonical(root, CtxStationCert, body, c.Signature); err != nil {
		return fmt.Errorf("station certificate: %w", err)
	}
	return nil
}

// Public returns the certified station key.
func (c StationCert) Public() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(c.PublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("station certificate: bad public key")
	}
	return ed25519.PublicKey(b), nil
}

// ValidAt reports whether t is within the validity period (inclusive).
func (c StationCert) ValidAt(t time.Time) bool {
	nb, err1 := ParseTime(c.NotBefore)
	na, err2 := ParseTime(c.NotAfter)
	return err1 == nil && err2 == nil && !t.Before(nb) && !t.After(na)
}

// ParseStationCert decodes and verifies a station certificate. The signature is
// checked over the members as they appear, so an extra or missing member fails.
func ParseStationCert(raw []byte, root ed25519.PublicKey) (StationCert, error) {
	var c StationCert
	if err := parseSigned(raw, &c, func() any { u := c; u.Signature = ""; return u }); err != nil {
		return StationCert{}, fmt.Errorf("station certificate: %w", err)
	}
	return c, c.Verify(root)
}

// DecodeStationCert decodes a station certificate strictly without checking the root's
// signature: a station need not hold the root public key (verifiers check the chain).
func DecodeStationCert(raw []byte) (StationCert, error) {
	var c StationCert
	if err := parseSigned(raw, &c, func() any { u := c; u.Signature = ""; return u }); err != nil {
		return StationCert{}, fmt.Errorf("station certificate: %w", err)
	}
	if c.Format != stationFormat || c.Version != 1 {
		return StationCert{}, fmt.Errorf("station certificate: unsupported format %q version %d", c.Format, c.Version)
	}
	return c, nil
}

// parseSigned strictly decodes raw into v and checks that what the signature covers
// (raw without "signature") is exactly the re-encoding of v without its signature.
func parseSigned(raw []byte, v any, withoutSig func() any) error {
	body, _, err := unsigned(raw)
	if err != nil {
		return err
	}
	if err := decodeStrict(raw, v); err != nil {
		return err
	}
	again, err := jcs.Marshal(withoutSig())
	if err != nil {
		return err
	}
	if !bytes.Equal(body, again) {
		return errors.New("members missing or not in their canonical form")
	}
	return nil
}

// --- revocation list ---

const revocationFormat = "shunya-revocation-list"

// Revocation reasons.
const (
	// ReasonRetired: the station stopped using the key. Certificates it issued before
	// At remain valid; later ones are refused.
	ReasonRetired = "retired"
	// ReasonCompromised: someone else may hold the key. Its certificates carry
	// timestamps the key itself asserted, which a thief can backdate, so all of them are
	// refused. (Milestone 8: a transparency-log entry made before the revocation will
	// prove a certificate's age independently.)
	ReasonCompromised = "compromised"
)

// Revocation is one revoked station key.
type Revocation struct {
	KeyID  string `json:"key_id"`
	Reason string `json:"reason"`
	At     string `json:"at"`
	Note   string `json:"note,omitempty"`
}

// RevocationList is the root's current list. Number increases with every change; a
// verifier given two lists keeps the higher.
type RevocationList struct {
	Format    string       `json:"format"`
	Version   int          `json:"version"`
	Issuer    string       `json:"issuer"`
	Number    uint64       `json:"number"`
	Issued    string       `json:"issued"`
	Revoked   []Revocation `json:"revoked"`
	Signature string       `json:"signature,omitempty"`
}

// NewRevocationList returns the empty list number 1.
func NewRevocationList(root ed25519.PrivateKey, now time.Time) (RevocationList, error) {
	l := RevocationList{Format: revocationFormat, Version: 1, Issuer: KeyID(root.Public().(ed25519.PublicKey)),
		Number: 1, Issued: FormatTime(now), Revoked: []Revocation{}}
	return l.sign(root)
}

func (l RevocationList) sign(root ed25519.PrivateKey) (RevocationList, error) {
	l.Signature = ""
	sig, err := SignJSON(root, CtxRevocations, l)
	if err != nil {
		return RevocationList{}, err
	}
	l.Signature = sig
	return l, nil
}

// Revoke returns the next list with keyID revoked. A retired key may later be marked
// compromised; anything else already listed is refused.
func (l RevocationList) Revoke(root ed25519.PrivateKey, keyID, reason string, at, now time.Time) (RevocationList, error) {
	if KeyID(root.Public().(ed25519.PublicKey)) != l.Issuer {
		return RevocationList{}, errors.New("revoke: the list belongs to another root key")
	}
	if reason != ReasonRetired && reason != ReasonCompromised {
		return RevocationList{}, fmt.Errorf("revoke: reason %q (want %s or %s)", reason, ReasonRetired, ReasonCompromised)
	}
	if !strings.HasPrefix(keyID, "ed25519:") || len(keyID) != len("ed25519:")+16 {
		return RevocationList{}, fmt.Errorf("revoke: %q is not a key id", keyID)
	}
	n := l
	n.Revoked = make([]Revocation, 0, len(l.Revoked)+1)
	found := false
	for _, r := range l.Revoked {
		if r.KeyID == keyID {
			if r.Reason != ReasonRetired || reason != ReasonCompromised {
				return RevocationList{}, fmt.Errorf("revoke: %s is already revoked (%s)", keyID, r.Reason)
			}
			r.Reason, r.At, found = reason, FormatTime(at), true
		}
		n.Revoked = append(n.Revoked, r)
	}
	if !found {
		n.Revoked = append(n.Revoked, Revocation{KeyID: keyID, Reason: reason, At: FormatTime(at)})
	}
	n.Number, n.Issued = l.Number+1, FormatTime(now)
	return n.sign(root)
}

// Verify checks the list's form and signature.
func (l RevocationList) Verify(root ed25519.PublicKey) error {
	if l.Format != revocationFormat || l.Version != 1 {
		return fmt.Errorf("revocation list: unsupported format %q version %d", l.Format, l.Version)
	}
	if l.Issuer != KeyID(root) {
		return fmt.Errorf("revocation list: issued by %s, not by root %s", l.Issuer, KeyID(root))
	}
	if _, err := ParseTime(l.Issued); err != nil {
		return fmt.Errorf("revocation list: %w", err)
	}
	seen := map[string]bool{}
	for _, r := range l.Revoked {
		if _, err := ParseTime(r.At); err != nil || (r.Reason != ReasonRetired && r.Reason != ReasonCompromised) || seen[r.KeyID] {
			return fmt.Errorf("revocation list: bad entry %+v", r)
		}
		seen[r.KeyID] = true
	}
	u := l
	u.Signature = ""
	body, err := jcs.Marshal(u)
	if err != nil {
		return err
	}
	if err := VerifyCanonical(root, CtxRevocations, body, l.Signature); err != nil {
		return fmt.Errorf("revocation list: %w", err)
	}
	return nil
}

// ParseRevocationList decodes and verifies a list.
func ParseRevocationList(raw []byte, root ed25519.PublicKey) (RevocationList, error) {
	var l RevocationList
	if err := parseSigned(raw, &l, func() any { u := l; u.Signature = ""; return u }); err != nil {
		return RevocationList{}, fmt.Errorf("revocation list: %w", err)
	}
	return l, l.Verify(root)
}

// Check applies the revocation policy to a certificate issued at issued by keyID.
func (l RevocationList) Check(keyID string, issued time.Time) error {
	for _, r := range l.Revoked {
		if r.KeyID != keyID {
			continue
		}
		at, _ := ParseTime(r.At)
		switch {
		case r.Reason == ReasonCompromised:
			return fmt.Errorf("%w: %s compromised (list %d): none of its certificates can be trusted", ErrRevoked, keyID, l.Number)
		case !issued.Before(at):
			return fmt.Errorf("%w: %s retired at %s, certificate issued %s (list %d)", ErrRevoked, keyID, r.At, FormatTime(issued), l.Number)
		}
	}
	return nil
}
