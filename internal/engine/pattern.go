// Package engine plans and runs overwrite wipes (NIST SP 800-88 Clear): pattern
// generation, the generator → buffer pool → writer pipeline, progress reporting,
// cancellation, read-back verification and the crash-safe progress journal.
package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"math/bits"
)

// Pattern produces the bytes an overwrite pass writes. Fill must be a pure function of
// (off, len(buf)): any range can be regenerated later, which is what makes resuming a
// pass and verifying it possible without storing what was written.
type Pattern interface {
	Name() string
	Fill(buf []byte, off int64)
}

// Pattern names accepted by NewPattern.
const (
	PatternZero   = "zero"
	PatternOne    = "one"
	PatternRandom = "random"
)

// RandomKeySize is the AES-256 key length of the random pattern.
const RandomKeySize = 32

// NewPattern returns the named pattern. "random" needs a 32-byte key; the others take none.
func NewPattern(name string, key []byte) (Pattern, error) {
	switch name {
	case PatternZero, PatternOne:
		if key != nil {
			return nil, fmt.Errorf("pattern %q takes no key", name)
		}
		b := byte(0x00)
		if name == PatternOne {
			b = 0xff
		}
		return constPattern{name, b}, nil
	case PatternRandom:
		if len(key) != RandomKeySize {
			return nil, fmt.Errorf("pattern random: key must be %d bytes, got %d", RandomKeySize, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return randomPattern{block}, nil
	}
	return nil, fmt.Errorf("unknown pattern %q (want zero, one or random)", name)
}

type constPattern struct {
	name string
	b    byte
}

func (c constPattern) Name() string { return c.name }

func (c constPattern) Fill(buf []byte, _ int64) {
	if c.b == 0 {
		clear(buf)
		return
	}
	if len(buf) == 0 {
		return
	}
	// Doubling copy: fills n bytes in log2(n) copy calls.
	buf[0] = c.b
	for i := 1; i < len(buf); i *= 2 {
		copy(buf[i:], buf[:i])
	}
}

// randomPattern is the AES-256-CTR keystream with a zero initial counter block: byte i
// of the device is byte i of the keystream. CTR mode makes the stream seekable — block k
// is AES(key, k) — so Fill can start anywhere.
//
// It is a pattern, not a secret: its job is to be incompressible and unpredictable to
// the drive's firmware (which could otherwise "store" zeros without writing them) and
// to be reproducible for verification. The key is kept in the journal for that reason.
type randomPattern struct{ block cipher.Block }

func (randomPattern) Name() string { return PatternRandom }

func (r randomPattern) Fill(buf []byte, off int64) { keystream(r.block, [16]byte{}, buf, off) }

// keystream writes the CTR keystream for counter base, starting at byte off, into buf.
func keystream(b cipher.Block, base [16]byte, buf []byte, off int64) {
	if off < 0 {
		panic("engine: negative pattern offset")
	}
	iv := base
	addCounter(&iv, uint64(off)/aes.BlockSize)
	clear(buf)
	s := cipher.NewCTR(b, iv[:])
	if skip := int(off % aes.BlockSize); skip > 0 {
		var tmp [aes.BlockSize]byte
		s.XORKeyStream(tmp[:skip], tmp[:skip])
	}
	s.XORKeyStream(buf, buf) // keystream XOR zeros = keystream
}

// addCounter adds n to the 128-bit big-endian counter block, as CTR mode increments it.
func addCounter(iv *[16]byte, n uint64) {
	lo := binary.BigEndian.Uint64(iv[8:])
	hi := binary.BigEndian.Uint64(iv[:8])
	lo, carry := bits.Add64(lo, n, 0)
	hi += carry
	binary.BigEndian.PutUint64(iv[8:], lo)
	binary.BigEndian.PutUint64(iv[:8], hi)
}
