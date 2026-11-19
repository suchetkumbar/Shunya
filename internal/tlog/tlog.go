// Package tlog is the RFC 6962 / RFC 9162 Merkle hash tree used by Shunya's
// transparency log: leaf and node hashes with domain separation, inclusion and
// consistency proofs, and their verification.
//
// Leaf hash = SHA-256(0x00 || data); node hash = SHA-256(0x01 || left || right). The
// different prefixes stop a 64-byte leaf from being passed off as an inner node (a
// "second-preimage" attack on the tree).
//
// Tree keeps every complete subtree hash in memory ("stored hashes": level h holds the
// hashes of the aligned subtrees of 2^h leaves), which is what the tile store writes out
// and what proofs are built from. At 32 bytes per stored hash that is about 64 bytes
// per leaf, fine for a station or demo log of millions of certificates.
package tlog

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
)

const HashSize = 32

// Hash is a SHA-256 tree hash.
type Hash [HashSize]byte

// EmptyRoot is the root of the empty tree: SHA-256 of the empty string.
var EmptyRoot = Hash(sha256.Sum256(nil))

var (
	ErrProof = errors.New("tlog: proof does not verify")
	ErrRange = errors.New("tlog: index or size out of range")
)

// LeafHash is SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	return Hash(h.Sum(nil))
}

// NodeHash is SHA-256(0x01 || l || r).
func NodeHash(l, r Hash) Hash {
	var b [1 + 2*HashSize]byte
	b[0] = 1
	copy(b[1:], l[:])
	copy(b[1+HashSize:], r[:])
	return Hash(sha256.Sum256(b[:]))
}

// Tree is an append-only Merkle tree. The zero value is an empty tree.
type Tree struct {
	levels [][]Hash // levels[h][i] = hash of leaves [i<<h, (i+1)<<h)
}

// FromLeafHashes builds a tree from its leaf hashes.
func FromLeafHashes(leaves []Hash) *Tree {
	t := &Tree{}
	for _, l := range leaves {
		t.AppendHash(l)
	}
	return t
}

// Size is the number of leaves.
func (t *Tree) Size() uint64 {
	if len(t.levels) == 0 {
		return 0
	}
	return uint64(len(t.levels[0]))
}

// Append adds a leaf with the given data and returns its index.
func (t *Tree) Append(data []byte) uint64 { return t.AppendHash(LeafHash(data)) }

// AppendHash adds a leaf by its leaf hash and returns its index.
func (t *Tree) AppendHash(h Hash) uint64 {
	idx := t.Size()
	for level := 0; ; level++ {
		if level == len(t.levels) {
			t.levels = append(t.levels, nil)
		}
		t.levels[level] = append(t.levels[level], h)
		n := len(t.levels[level])
		if n%2 == 1 {
			return idx
		}
		h = NodeHash(t.levels[level][n-2], h)
	}
}

// Stored returns the hash of the complete subtree of 2^level leaves at position n.
func (t *Tree) Stored(level int, n uint64) (Hash, error) {
	if level < 0 || level >= len(t.levels) || n >= uint64(len(t.levels[level])) {
		return Hash{}, ErrRange
	}
	return t.levels[level][n], nil
}

// Root is the tree's current root hash.
func (t *Tree) Root() Hash {
	r, _ := t.RootAt(t.Size())
	return r
}

// RootAt is the root of the tree's first n leaves.
func (t *Tree) RootAt(n uint64) (Hash, error) {
	if n > t.Size() {
		return Hash{}, ErrRange
	}
	if n == 0 {
		return EmptyRoot, nil
	}
	return t.hash(0, n), nil
}

// split is the largest power of two smaller than n (n >= 2).
func split(n uint64) uint64 { return 1 << (bits.Len64(n-1) - 1) }

// hash is MTH(D[lo:hi]) for lo < hi <= Size.
func (t *Tree) hash(lo, hi uint64) Hash {
	n := hi - lo
	if n&(n-1) == 0 && lo%n == 0 { // complete, aligned subtree: stored
		level := bits.TrailingZeros64(n)
		return t.levels[level][lo>>level]
	}
	k := split(n)
	return NodeHash(t.hash(lo, lo+k), t.hash(lo+k, hi))
}

// InclusionProof is the audit path (RFC 6962 §2.1.1) for leaf index in the tree of
// the first size leaves.
func (t *Tree) InclusionProof(index, size uint64) ([]Hash, error) {
	if index >= size || size > t.Size() {
		return nil, ErrRange
	}
	return t.path(index, 0, size), nil
}

func (t *Tree) path(m, lo, hi uint64) []Hash {
	if hi-lo == 1 {
		return nil
	}
	k := split(hi - lo)
	if m-lo < k {
		return append(t.path(m, lo, lo+k), t.hash(lo+k, hi))
	}
	return append(t.path(m, lo+k, hi), t.hash(lo, lo+k))
}

// ConsistencyProof proves the tree of size m is a prefix of the tree of size n
// (RFC 6962 §2.1.2). It is empty when m == n or m == 0.
func (t *Tree) ConsistencyProof(m, n uint64) ([]Hash, error) {
	if m > n || n > t.Size() {
		return nil, ErrRange
	}
	if m == 0 || m == n {
		return nil, nil
	}
	return t.subproof(m, 0, n, true), nil
}

func (t *Tree) subproof(m, lo, hi uint64, b bool) []Hash {
	n := hi - lo
	if m == n {
		if b {
			return nil
		}
		return []Hash{t.hash(lo, hi)}
	}
	k := split(n)
	if m <= k {
		return append(t.subproof(m, lo, lo+k, b), t.hash(lo+k, hi))
	}
	return append(t.subproof(m-k, lo+k, hi, false), t.hash(lo, lo+k))
}

// VerifyInclusion checks an inclusion proof (RFC 9162 §2.1.3.2).
func VerifyInclusion(index, size uint64, leaf Hash, proof []Hash, root Hash) error {
	r, err := RootFromInclusion(index, size, leaf, proof)
	if err != nil {
		return err
	}
	if r != root {
		return fmt.Errorf("%w: root mismatch", ErrProof)
	}
	return nil
}

// RootFromInclusion computes the root an inclusion proof implies.
func RootFromInclusion(index, size uint64, leaf Hash, proof []Hash) (Hash, error) {
	if index >= size {
		return Hash{}, fmt.Errorf("%w: index %d not below size %d", ErrProof, index, size)
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range proof {
		if sn == 0 {
			return Hash{}, fmt.Errorf("%w: proof too long", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return Hash{}, fmt.Errorf("%w: proof too short", ErrProof)
	}
	return r, nil
}

// VerifyConsistency checks that root2 (size2) extends root1 (size1) (RFC 9162 §2.1.4.2).
func VerifyConsistency(size1, size2 uint64, proof []Hash, root1, root2 Hash) error {
	switch {
	case size1 == 0:
		// Every tree extends the empty tree, so such a proof shows nothing; callers start
		// from a checkpoint of at least one leaf. (transparency-dev/merkle does the same.)
		return fmt.Errorf("%w: consistency from the empty tree proves nothing", ErrProof)
	case size2 < size1:
		return fmt.Errorf("%w: size %d after %d", ErrProof, size2, size1)
	case size1 == size2:
		if len(proof) != 0 {
			return fmt.Errorf("%w: proof for equal sizes must be empty", ErrProof)
		}
		if root1 != root2 {
			return fmt.Errorf("%w: same size, different roots", ErrProof)
		}
		return nil
	case len(proof) == 0:
		return fmt.Errorf("%w: empty proof", ErrProof)
	}
	path := proof
	if size1&(size1-1) == 0 { // size1 is a power of two: its root is a node in the path
		path = append([]Hash{root1}, proof...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return fmt.Errorf("%w: proof too long", ErrProof)
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("%w: proof too short", ErrProof)
	}
	if fr != root1 || sr != root2 {
		return fmt.Errorf("%w: root mismatch", ErrProof)
	}
	return nil
}
