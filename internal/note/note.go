// Package note implements C2SP signed notes (c2sp.org/signed-note) with Ed25519
// signatures (type 0x01): the format of transparency-log checkpoints.
//
// A signed note is UTF-8 text ending in a newline, a blank line, then one or more
// signature lines "— <name> base64(keyID[4] || signature)". The key ID is
// SHA-256(name || "\n" || 0x01 || public key)[:4]. Keys are written in the usual
// textual forms: verifier key "name+hex(id)+base64(0x01||pub)" and signer key
// "PRIVATE+KEY+name+hex(id)+base64(0x01||seed)".
//
// The parser is strict: canonical base64, no control characters except newline,
// bounded size and signature count; a signature by a known key that fails to verify
// rejects the whole note.
package note

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	algEd25519 = 0x01
	// MaxSize bounds a note; MaxSigs bounds its signature lines (the spec requires
	// accepting at least 16).
	MaxSize = 1 << 16
	MaxSigs = 32
	dash    = "— " // U+2014 EM DASH, space
)

var (
	ErrMalformed  = errors.New("note: malformed")
	ErrBadSig     = errors.New("note: signature by a known key does not verify")
	ErrUnverified = errors.New("note: no signature by a known key")
	b64           = base64.StdEncoding.Strict()
)

// KeyID is SHA-256(name || "\n" || 0x01 || pub)[:4], big-endian.
func KeyID(name string, pub ed25519.PublicKey) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', algEd25519})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// ValidName reports whether name may name a key: non-empty, valid UTF-8, no Unicode
// spaces, no '+', no control characters.
func ValidName(name string) bool {
	if name == "" || !utf8.ValidString(name) || strings.ContainsRune(name, '+') {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Verifier checks signatures of one key.
type Verifier struct {
	Name string
	ID   uint32
	Pub  ed25519.PublicKey
}

// Signer makes signatures with one key.
type Signer struct {
	Verifier
	priv ed25519.PrivateKey
}

// NewSigner names an Ed25519 private key.
func NewSigner(name string, priv ed25519.PrivateKey) (*Signer, error) {
	if !ValidName(name) || len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: key name %q", ErrMalformed, name)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{Verifier{name, KeyID(name, pub), pub}, priv}, nil
}

// GenerateKey makes a new named key and returns its signer and verifier key strings.
func GenerateKey(name string) (skey, vkey string, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	s, err := NewSigner(name, priv)
	if err != nil {
		return "", "", err
	}
	return s.SignerKey(), s.VerifierKey(), nil
}

// VerifierKey is "name+hex(id)+base64(0x01||pub)".
func (v Verifier) VerifierKey() string {
	return fmt.Sprintf("%s+%08x+%s", v.Name, v.ID, b64.EncodeToString(append([]byte{algEd25519}, v.Pub...)))
}

// SignerKey is "PRIVATE+KEY+name+hex(id)+base64(0x01||seed)". It is a secret.
func (s *Signer) SignerKey() string {
	return fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", s.Name, s.ID, b64.EncodeToString(append([]byte{algEd25519}, s.priv.Seed()...)))
}

func parseKey(k string, size int) (name string, id uint32, key []byte, err error) {
	bad := fmt.Errorf("%w: key", ErrMalformed)
	parts := strings.SplitN(k, "+", 3) // base64 may contain "+"
	if len(parts) != 3 || !ValidName(parts[0]) || len(parts[1]) != 8 || strings.ToLower(parts[1]) != parts[1] {
		return "", 0, nil, bad
	}
	id64, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return "", 0, nil, bad
	}
	raw, err := b64.DecodeString(parts[2])
	if err != nil || len(raw) != 1+size || raw[0] != algEd25519 {
		return "", 0, nil, bad
	}
	return parts[0], uint32(id64), raw[1:], nil
}

// ParseVerifierKey parses a verifier key and checks that its ID matches the key.
func ParseVerifierKey(vkey string) (*Verifier, error) {
	name, id, pub, err := parseKey(strings.TrimSpace(vkey), ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	if KeyID(name, pub) != id {
		return nil, fmt.Errorf("%w: key ID does not match the key", ErrMalformed)
	}
	return &Verifier{name, id, ed25519.PublicKey(pub)}, nil
}

// ParseSignerKey parses a signer key.
func ParseSignerKey(skey string) (*Signer, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(skey), "PRIVATE+KEY+")
	if !ok {
		return nil, fmt.Errorf("%w: not a signer key", ErrMalformed)
	}
	name, id, seed, err := parseKey(rest, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	s, err := NewSigner(name, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return nil, err
	}
	if s.ID != id {
		return nil, fmt.Errorf("%w: key ID does not match the key", ErrMalformed)
	}
	return s, nil
}

// validText: non-empty, valid UTF-8, ends in "\n", no control characters but "\n",
// and no blank last line (a text ending in "\n\n" would be ambiguous with the separator).
func validText(text []byte) bool {
	if len(text) == 0 || text[len(text)-1] != '\n' || bytes.HasSuffix(text, []byte("\n\n")) || !utf8.Valid(text) {
		return false
	}
	for _, c := range text {
		if (c < 0x20 && c != '\n') || c == 0x7f {
			return false
		}
	}
	return true
}

// Sign returns text followed by the signers' signatures.
func Sign(text []byte, signers ...*Signer) ([]byte, error) {
	if !validText(text) || len(text) > MaxSize || len(signers) == 0 {
		return nil, fmt.Errorf("%w: text", ErrMalformed)
	}
	var b bytes.Buffer
	b.Write(text)
	b.WriteByte('\n')
	for _, s := range signers {
		sig := make([]byte, 4, 4+ed25519.SignatureSize)
		binary.BigEndian.PutUint32(sig, s.ID)
		sig = append(sig, ed25519.Sign(s.priv, text)...)
		fmt.Fprintf(&b, "%s%s %s\n", dash, s.Name, b64.EncodeToString(sig))
	}
	return b.Bytes(), nil
}

// Signature is one parsed signature line.
type Signature struct {
	Name string
	ID   uint32
	Sig  []byte
}

// Note is a parsed signed note.
type Note struct {
	Text     []byte
	Sigs     []Signature
	Verified []Signature // signatures by the given verifiers that verified
}

// Open parses msg and verifies it against the given keys. It fails if no known key
// signed it, or if any signature by a known key (same name and ID) does not verify.
// Signatures by unknown keys are kept in Sigs but not trusted.
func Open(msg []byte, verifiers ...*Verifier) (*Note, error) {
	n, err := parse(msg, verifiers)
	if err != nil {
		return nil, err
	}
	if len(n.Verified) == 0 {
		return nil, ErrUnverified
	}
	return n, nil
}

// Parse parses msg without verifying any signature. Its text must not be trusted; it
// is for reading what a note claims before or without checking it.
func Parse(msg []byte) (*Note, error) { return parse(msg, nil) }

func parse(msg []byte, verifiers []*Verifier) (*Note, error) {
	if len(msg) > MaxSize || !utf8.Valid(msg) {
		return nil, fmt.Errorf("%w: size or encoding", ErrMalformed)
	}
	for _, c := range msg {
		if (c < 0x20 && c != '\n') || c == 0x7f {
			return nil, fmt.Errorf("%w: control character", ErrMalformed)
		}
	}
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		return nil, fmt.Errorf("%w: no signature block", ErrMalformed)
	}
	n := &Note{Text: msg[:i+1]}
	if !validText(n.Text) {
		return nil, fmt.Errorf("%w: text", ErrMalformed)
	}
	block := msg[i+2:]
	if len(block) == 0 || block[len(block)-1] != '\n' {
		return nil, fmt.Errorf("%w: signature block", ErrMalformed)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(block[:len(block)-1]), "\n") {
		rest, ok := strings.CutPrefix(line, dash)
		if !ok {
			return nil, fmt.Errorf("%w: signature line %q", ErrMalformed, line)
		}
		name, enc, ok := strings.Cut(rest, " ")
		raw, err := b64.DecodeString(enc)
		if !ok || !ValidName(name) || err != nil || len(raw) < 5 {
			return nil, fmt.Errorf("%w: signature line %q", ErrMalformed, line)
		}
		s := Signature{Name: name, ID: binary.BigEndian.Uint32(raw), Sig: raw[4:]}
		k := fmt.Sprintf("%s+%08x", s.Name, s.ID)
		if seen[k] {
			return nil, fmt.Errorf("%w: two signatures by %s", ErrMalformed, k)
		}
		seen[k] = true
		n.Sigs = append(n.Sigs, s)
		if len(n.Sigs) > MaxSigs {
			return nil, fmt.Errorf("%w: more than %d signatures", ErrMalformed, MaxSigs)
		}
		for _, v := range verifiers {
			if v.Name == s.Name && v.ID == s.ID {
				if len(s.Sig) != ed25519.SignatureSize || !ed25519.Verify(v.Pub, n.Text, s.Sig) {
					return nil, fmt.Errorf("%w: %s", ErrBadSig, k)
				}
				n.Verified = append(n.Verified, s)
			}
		}
	}
	return n, nil
}
