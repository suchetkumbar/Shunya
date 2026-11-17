// Package canary is the forensic canary harness (brief §3.6): it fills a target with
// recognisable per-sector canaries, plants real files, and after a wipe scans the raw
// target at every byte offset for any residue. It is test and lab tooling; the wipe
// engine never imports it.
//
// A canary token is 32 bytes:
//
//	magic (8) ‖ sector (6, big-endian) ‖ index (2) ‖ tag (16)
//
// magic is derived from the run key, so it is unique per harness run (2⁻⁶⁴ chance per
// offset of appearing in random data). tag = HMAC-SHA256(key, "shunya-canary-v1" ‖
// sector)[:16] with the index XORed into its last two bytes, so every token is unique,
// names the sector it was written to, and can't be forged without the key. A sector is
// filled with consecutive tokens, so any surviving fragment of at least 32 aligned-or-not
// bytes contains a whole token.
package canary

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
)

// Sizes of a token and its parts.
const (
	KeySize   = 32
	TokenSize = 32
	MagicSize = 8
	tagSize   = 16
	maxSector = 1<<48 - 1
)

// Set generates and validates the canaries of one harness run.
type Set struct {
	key   []byte
	magic [MagicSize]byte
	mac   hash.Hash
	// one-entry cache: a sector's tokens are adjacent, so a scan validates many tokens
	// of the same sector in a row
	cached    bool
	cacheSec  uint64
	cachedTag [tagSize]byte
}

// NewSet returns the canary set for a 32-byte run key.
func NewSet(key []byte) (*Set, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("canary: key must be %d bytes, got %d", KeySize, len(key))
	}
	s := &Set{key: append([]byte(nil), key...), mac: hmac.New(sha256.New, key)}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("shunya-canary-magic-v1"))
	copy(s.magic[:], m.Sum(nil))
	return s, nil
}

// Magic is the 8-byte prefix every token of this run starts with.
func (s *Set) Magic() []byte { return s.magic[:] }

// sectorTag is HMAC(key, "shunya-canary-v1" ‖ sector)[:16]. Set is not safe for
// concurrent use (it reuses one HMAC state).
func (s *Set) sectorTag(sector uint64) [tagSize]byte {
	if s.cached && s.cacheSec == sector {
		return s.cachedTag
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sector)
	s.mac.Reset()
	s.mac.Write([]byte("shunya-canary-v1"))
	s.mac.Write(b[:])
	var tag [tagSize]byte
	copy(tag[:], s.mac.Sum(nil))
	s.cached, s.cacheSec, s.cachedTag = true, sector, tag
	return tag
}

func putToken(dst []byte, magic *[MagicSize]byte, tag [tagSize]byte, sector uint64, idx uint16) {
	copy(dst, magic[:])
	var id [8]byte
	binary.BigEndian.PutUint64(id[:], sector<<16|uint64(idx))
	copy(dst[MagicSize:], id[:])
	tag[tagSize-2] ^= byte(idx >> 8)
	tag[tagSize-1] ^= byte(idx)
	copy(dst[MagicSize+8:], tag[:])
}

// Token writes token (sector, idx) into dst[:TokenSize].
func (s *Set) Token(dst []byte, sector uint64, idx uint16) {
	putToken(dst, &s.magic, s.sectorTag(sector&maxSector), sector&maxSector, idx)
}

// FillSector fills buf (a multiple of TokenSize, normally one sector) with the tokens
// of sector: index 0, 1, 2, …
func (s *Set) FillSector(buf []byte, sector uint64) {
	sector &= maxSector
	tag := s.sectorTag(sector)
	for i := 0; i+TokenSize <= len(buf); i += TokenSize {
		putToken(buf[i:], &s.magic, tag, sector, uint16(i/TokenSize))
	}
}

// Validate reports whether tok is a genuine token of this run, and which.
func (s *Set) Validate(tok []byte) (sector uint64, idx uint16, ok bool) {
	if len(tok) < TokenSize || subtle.ConstantTimeCompare(tok[:MagicSize], s.magic[:]) != 1 {
		return 0, 0, false
	}
	id := binary.BigEndian.Uint64(tok[MagicSize:])
	sector, idx = id>>16, uint16(id)
	want := make([]byte, TokenSize)
	putToken(want, &s.magic, s.sectorTag(sector), sector, idx)
	return sector, idx, subtle.ConstantTimeCompare(want, tok[:TokenSize]) == 1
}
