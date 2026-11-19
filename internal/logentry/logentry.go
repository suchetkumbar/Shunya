// Package logentry defines what Shunya's transparency log holds and how a log proof is
// carried and checked.
//
// An entry is one type byte followed by its payload:
//
//	0x01 certificate   the certificate file's canonical envelope with "log": null (no newline)
//	0x02 seed request  RFC 8785 JSON of a SeedRequest, signed by the station key
//	0x03 beacon        32 random bytes the log adds after each seed request
//
// Unpredictable sampling (brief §3.3): after a wipe completes, the station sends a
// signed seed request naming the wipe, the device fingerprint and the journal hash.
// The log appends the request and a beacon of its own randomness, signs a checkpoint
// covering both and returns it with the request's inclusion proof. The sampling seed
// is SHA-256(ctx || checkpoint text || fingerprint): the station cannot know it before
// the log answered, and a verifier recomputes it from the certificate. A station that
// asks again to get different positions leaves a second request in the public log,
// which an auditor sees.
package logentry

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"shunya/internal/checkpoint"
	"shunya/internal/jcs"
	"shunya/internal/keys"
	"shunya/internal/note"
	"shunya/internal/tlog"
)

const (
	TypeCertificate = 0x01
	TypeSeedRequest = 0x02
	TypeBeacon      = 0x03
	// TypeManifest (Milestone 9): a signed batch manifest from fleet mode, "log": null.
	TypeManifest = 0x04
	// MaxEntry is the tlog-tiles limit (entry bundles use 16-bit lengths).
	MaxEntry = 1<<16 - 1

	CtxSeedRequest = "shunya/seed-request/v1"
	seedFormat     = "shunya-seed-request"
	ctxSeed        = "shunya/sample-seed/v1"
)

var ErrInvalid = errors.New("log entry invalid")

// Entry returns typ || payload, refusing entries the tile format cannot hold.
func Entry(typ byte, payload []byte) ([]byte, error) {
	if typ < TypeCertificate || typ > TypeManifest || len(payload)+1 > MaxEntry {
		return nil, fmt.Errorf("%w: type %d, %d bytes", ErrInvalid, typ, len(payload))
	}
	return append([]byte{typ}, payload...), nil
}

// Split returns an entry's type and payload.
func Split(e []byte) (byte, []byte, error) {
	if len(e) < 1 || e[0] < TypeCertificate || e[0] > TypeManifest || len(e) > MaxEntry {
		return 0, nil, fmt.Errorf("%w: unknown type or size", ErrInvalid)
	}
	if e[0] == TypeBeacon && len(e) != 33 {
		return 0, nil, fmt.Errorf("%w: beacon of %d bytes", ErrInvalid, len(e)-1)
	}
	return e[0], e[1:], nil
}

// Beacon is a fresh beacon entry.
func Beacon() ([]byte, error) {
	b := make([]byte, 33)
	b[0] = TypeBeacon
	_, err := rand.Read(b[1:])
	return b, err
}

// SeedRequest asks the log for an unpredictable sampling seed after a wipe.
type SeedRequest struct {
	Format             string            `json:"format"`
	Version            int               `json:"version"`
	WipeID             string            `json:"wipe_id"`
	Fingerprint        string            `json:"fingerprint"`    // identity of the sampled target
	JournalSHA256      string            `json:"journal_sha256"` // the journal up to and including "done"
	Requested          string            `json:"requested"`      // station clock, RFC 3339
	StationKeyID       string            `json:"station_key_id"`
	StationPublicKey   string            `json:"station_public_key"`
	StationCertificate *keys.StationCert `json:"station_certificate"` // nil: dev key
	Signature          string            `json:"signature,omitempty"`
}

// NewSeedRequest builds and signs a request.
func NewSeedRequest(priv ed25519.PrivateKey, sc *keys.StationCert, wipeID, fingerprint string, journalSHA [32]byte, requested string) (SeedRequest, error) {
	pub := priv.Public().(ed25519.PublicKey)
	r := SeedRequest{Format: seedFormat, Version: 1, WipeID: wipeID, Fingerprint: fingerprint,
		JournalSHA256: hex.EncodeToString(journalSHA[:]), Requested: requested,
		StationKeyID: keys.KeyID(pub), StationPublicKey: hex.EncodeToString(pub), StationCertificate: sc}
	sig, err := keys.SignJSON(priv, CtxSeedRequest, r)
	if err != nil {
		return SeedRequest{}, err
	}
	r.Signature = sig
	return r, nil
}

// Public is the requesting station's key.
func (r SeedRequest) Public() (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(r.StationPublicKey)
	if err != nil || len(b) != ed25519.PublicKeySize || keys.KeyID(b) != r.StationKeyID {
		return nil, fmt.Errorf("%w: seed request station key", ErrInvalid)
	}
	return b, nil
}

// Verify checks the request's form and its station signature. It does not check the
// station certificate against a root; callers that need that do it with Root.
func (r SeedRequest) Verify() error {
	switch {
	case r.Format != seedFormat || r.Version != 1:
		return fmt.Errorf("%w: seed request format %q version %d", ErrInvalid, r.Format, r.Version)
	case len(r.WipeID) != 32 || r.Fingerprint == "" || len(r.JournalSHA256) != 64:
		return fmt.Errorf("%w: seed request fields", ErrInvalid)
	}
	if _, err := keys.ParseTime(r.Requested); err != nil {
		return fmt.Errorf("%w: seed request time: %v", ErrInvalid, err)
	}
	pub, err := r.Public()
	if err != nil {
		return err
	}
	if r.StationCertificate != nil && r.StationCertificate.PublicKey != r.StationPublicKey {
		return fmt.Errorf("%w: seed request station certificate is for another key", ErrInvalid)
	}
	u := r
	u.Signature = ""
	body, err := jcs.Marshal(u)
	if err != nil {
		return err
	}
	return keys.VerifyCanonical(pub, CtxSeedRequest, body, r.Signature)
}

// Entry is the request's log entry.
func (r SeedRequest) Entry() ([]byte, error) {
	b, err := jcs.Marshal(r)
	if err != nil {
		return nil, err
	}
	return Entry(TypeSeedRequest, b)
}

// Inclusion is a log inclusion proof as carried in certificates and API responses:
// the entry's index, the signed checkpoint, and the audit path (base64 hashes).
type Inclusion struct {
	Index      uint64   `json:"index"`
	Checkpoint string   `json:"checkpoint"`
	Proof      []string `json:"proof"`
}

// NewInclusion encodes a proof.
func NewInclusion(index uint64, signedCheckpoint []byte, proof []tlog.Hash) Inclusion {
	in := Inclusion{Index: index, Checkpoint: string(signedCheckpoint), Proof: []string{}}
	for _, h := range proof {
		in.Proof = append(in.Proof, base64.StdEncoding.EncodeToString(h[:]))
	}
	return in
}

// Hashes decodes the audit path.
func (in Inclusion) Hashes() ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(in.Proof))
	for i, s := range in.Proof {
		b, err := base64.StdEncoding.Strict().DecodeString(s)
		if err != nil || len(b) != tlog.HashSize {
			return nil, fmt.Errorf("%w: proof hash %d", ErrInvalid, i)
		}
		out[i] = tlog.Hash(b)
	}
	return out, nil
}

// Verify checks that entry is at Index in the tree the checkpoint, signed by the log
// key, commits to.
func (in Inclusion) Verify(entry []byte, log *note.Verifier) (checkpoint.Checkpoint, error) {
	cp, err := checkpoint.Open([]byte(in.Checkpoint), log)
	if err != nil {
		return checkpoint.Checkpoint{}, err
	}
	p, err := in.Hashes()
	if err != nil {
		return checkpoint.Checkpoint{}, err
	}
	if err := tlog.VerifyInclusion(in.Index, cp.Size, tlog.LeafHash(entry), p, cp.Root); err != nil {
		return checkpoint.Checkpoint{}, err
	}
	return cp, nil
}

// CheckpointText is the checkpoint's note text, unverified.
func (in Inclusion) CheckpointText() ([]byte, error) {
	n, err := note.Parse([]byte(in.Checkpoint))
	if err != nil {
		return nil, err
	}
	if _, err := checkpoint.ParseText(n.Text); err != nil {
		return nil, err
	}
	return n.Text, nil
}

// Seed is the sampling seed a checkpoint gives for a device fingerprint.
func Seed(checkpointText []byte, fingerprint string) []byte {
	h := sha256.New()
	h.Write([]byte(ctxSeed))
	h.Write([]byte{0})
	h.Write(checkpointText)
	h.Write([]byte{0})
	h.Write([]byte(fingerprint))
	return h.Sum(nil)
}
