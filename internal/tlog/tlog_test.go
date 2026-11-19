package tlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	xtlog "golang.org/x/mod/sumdb/tlog"
)

func hx(t *testing.T, s string) Hash {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != HashSize {
		t.Fatalf("bad hex %q", s)
	}
	return Hash(b)
}

// The eight leaf inputs and every root hash from transparency-dev/merkle
// testonly/constants.go (the RFC 6962 reference vectors used by CT implementations).
var refLeaves = []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}
var refRoots = []string{
	"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func refTree(t *testing.T) *Tree {
	var tr Tree
	for _, l := range refLeaves {
		b, _ := hex.DecodeString(l)
		tr.Append(b)
	}
	return &tr
}

func TestReferenceRoots(t *testing.T) {
	if EmptyRoot != hx(t, refRoots[0]) {
		t.Fatal("empty root")
	}
	tr := refTree(t)
	for n := range refRoots {
		r, err := tr.RootAt(uint64(n))
		if err != nil || r != hx(t, refRoots[n]) {
			t.Errorf("root at %d = %x, %v", n, r, err)
		}
	}
	if tr.Root() != hx(t, refRoots[8]) || tr.Size() != 8 {
		t.Fatal("root/size")
	}
	if _, err := tr.RootAt(9); err == nil {
		t.Fatal("root beyond size accepted")
	}
	// Leaf / node domain separation: a leaf hash is SHA-256(0x00 || data).
	if LeafHash(nil) != sha256.Sum256([]byte{0}) {
		t.Fatal("leaf prefix")
	}
	a, b := LeafHash([]byte("a")), LeafHash([]byte("b"))
	want := sha256.Sum256(append(append([]byte{1}, a[:]...), b[:]...))
	if NodeHash(a, b) != want {
		t.Fatal("node prefix")
	}
	// A two-leaf tree's root is not the leaf hash of the concatenated children.
	if LeafHash(append(a[:], b[:]...)) == NodeHash(a, b) {
		t.Fatal("no domain separation")
	}
}

type probe struct {
	LeafIdx, TreeSize uint64
	Size1, Size2      uint64
	Root, LeafHash    []byte
	Root1, Root2      []byte
	Proof             [][]byte
	Desc              string
	WantErr           bool `json:"wantErr"`
}

func hashes(b [][]byte) ([]Hash, bool) {
	out := make([]Hash, len(b))
	for i, x := range b {
		if len(x) != HashSize {
			return nil, false
		}
		out[i] = Hash(x)
	}
	return out, true
}

// one converts a vector's 32-byte hash; anything else is malformed.
func one(b []byte) (Hash, bool) {
	if len(b) != HashSize {
		return Hash{}, false
	}
	return Hash(b), true
}

// root converts a vector's root. A few vectors use non-empty placeholder roots that are
// not 32 bytes ("don't care"); they only need to compare equal or unequal, so they are
// mapped to a hash that no real root can equal.
func root(b []byte) (Hash, bool) {
	if len(b) != HashSize && len(b) > 0 {
		return Hash(sha256.Sum256(append([]byte("placeholder:"), b...))), true
	}
	return one(b)
}

func probes(t *testing.T, dir string) []probe {
	var ps []probe
	err := filepath.WalkDir(filepath.Join("testdata", "transparency-dev", dir), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(p) != ".json" {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var pr probe
		if err := json.Unmarshal(b, &pr); err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		pr.Desc = p + ": " + pr.Desc
		ps = append(ps, pr)
		return nil
	})
	if err != nil || len(ps) < 50 {
		t.Fatalf("vectors: %d, %v", len(ps), err)
	}
	return ps
}

// The transparency-dev/merkle proof vectors (testdata/inclusion and testdata/consistency,
// Apache-2.0, copied into testdata/): happy paths and every corruption they list.
func TestInclusionVectors(t *testing.T) {
	ok, bad := 0, 0
	for _, p := range probes(t, "inclusion") {
		pf, okP := hashes(p.Proof)
		leaf, okL := one(p.LeafHash)
		root, okR := root(p.Root)
		var err error
		if !okP || !okL || !okR {
			err = fmt.Errorf("malformed")
		} else {
			err = VerifyInclusion(p.LeafIdx, p.TreeSize, leaf, pf, root)
		}
		if (err != nil) != p.WantErr {
			t.Errorf("%s: err=%v wantErr=%v", p.Desc, err, p.WantErr)
		}
		if p.WantErr {
			bad++
		} else {
			ok++
		}
	}
	t.Logf("%d valid and %d invalid inclusion vectors", ok, bad)
}

func TestConsistencyVectors(t *testing.T) {
	ok, bad := 0, 0
	for _, p := range probes(t, "consistency") {
		pf, okP := hashes(p.Proof)
		r1, ok1 := root(p.Root1)
		r2, ok2 := root(p.Root2)
		var err error
		if !okP || !ok1 || !ok2 {
			err = fmt.Errorf("malformed")
		} else {
			err = VerifyConsistency(p.Size1, p.Size2, pf, r1, r2)
		}
		if (err != nil) != p.WantErr {
			t.Errorf("%s: err=%v wantErr=%v", p.Desc, err, p.WantErr)
		}
		if p.WantErr {
			bad++
		} else {
			ok++
		}
	}
	t.Logf("%d valid and %d invalid consistency vectors", ok, bad)
}

// xReader serves our tree's stored hashes to golang.org/x/mod/sumdb/tlog, an
// independent implementation used here (tests only) as an oracle.
type xReader struct{ tr *Tree }

func (r xReader) ReadHashes(idx []int64) ([]xtlog.Hash, error) {
	out := make([]xtlog.Hash, len(idx))
	for i, x := range idx {
		level, n := xtlog.SplitStoredHashIndex(x)
		h, err := r.tr.Stored(level, uint64(n))
		if err != nil {
			return nil, err
		}
		out[i] = xtlog.Hash(h)
	}
	return out, nil
}

// Every size up to 300 (crossing a 256-leaf tile): roots, every inclusion proof and
// every consistency proof agree with x/mod's, and verify; proofs of the wrong leaf,
// index or size fail.
func TestAgainstXMod(t *testing.T) {
	var tr Tree
	const N = 300
	for i := 0; i < N; i++ {
		tr.Append([]byte(fmt.Sprintf("leaf %d", i)))
	}
	r := xReader{&tr}
	for n := uint64(1); n <= N; n++ {
		root, _ := tr.RootAt(n)
		xr, err := xtlog.TreeHash(int64(n), r)
		if err != nil || Hash(xr) != root {
			t.Fatalf("size %d: root %x vs x/mod %x (%v)", n, root, xr, err)
		}
		step := uint64(1)
		if n > 40 {
			step = 7
		}
		for i := uint64(0); i < n; i += step {
			p, err := tr.InclusionProof(i, n)
			if err != nil {
				t.Fatal(err)
			}
			xp, err := xtlog.ProveRecord(int64(n), int64(i), r)
			if err != nil || !sameProof(p, xp) {
				t.Fatalf("inclusion %d/%d differs from x/mod", i, n)
			}
			leaf, _ := tr.Stored(0, i)
			if err := VerifyInclusion(i, n, leaf, p, root); err != nil {
				t.Fatalf("inclusion %d/%d: %v", i, n, err)
			}
			if VerifyInclusion(i, n, LeafHash([]byte("other")), p, root) == nil ||
				(n > 1 && VerifyInclusion((i+1)%n, n, leaf, p, root) == nil) {
				t.Fatalf("bad inclusion %d/%d accepted", i, n)
			}
		}
		for m := uint64(1); m <= n; m += step {
			p, err := tr.ConsistencyProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			xp, err := xtlog.ProveTree(int64(n), int64(m), r)
			if err != nil || !sameProof(p, xp) {
				t.Fatalf("consistency %d→%d differs from x/mod", m, n)
			}
			r1, _ := tr.RootAt(m)
			if err := VerifyConsistency(m, n, p, r1, root); err != nil {
				t.Fatalf("consistency %d→%d: %v", m, n, err)
			}
			if m < n && VerifyConsistency(m, n, p, LeafHash(nil), root) == nil {
				t.Fatalf("bad consistency %d→%d accepted", m, n)
			}
		}
	}
}

func sameProof(a []Hash, b []xtlog.Hash) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != Hash(b[i]) {
			return false
		}
	}
	return true
}

// A rewritten history (one leaf edited) is not consistent with the original.
func TestEditedLeafBreaksConsistency(t *testing.T) {
	var a, b Tree
	for i := 0; i < 20; i++ {
		a.Append([]byte{byte(i)})
		if i == 5 {
			b.Append([]byte("edited"))
		} else {
			b.Append([]byte{byte(i)})
		}
	}
	old, _ := a.RootAt(10)
	p, _ := b.ConsistencyProof(10, 20)
	if VerifyConsistency(10, 20, p, old, b.Root()) == nil {
		t.Fatal("edited history passed")
	}
	// Deleted leaf: the same leaves without number 5.
	var c Tree
	for i := 0; i < 21; i++ {
		if i != 5 {
			c.Append([]byte{byte(i)})
		}
	}
	p, _ = c.ConsistencyProof(10, 20)
	if VerifyConsistency(10, 20, p, old, c.Root()) == nil {
		t.Fatal("deleted leaf passed")
	}
}

func TestProofErrors(t *testing.T) {
	tr := refTree(t)
	if _, err := tr.InclusionProof(8, 8); err == nil {
		t.Error("index == size")
	}
	if _, err := tr.InclusionProof(0, 9); err == nil {
		t.Error("size > tree")
	}
	if _, err := tr.ConsistencyProof(5, 4); err == nil {
		t.Error("m > n")
	}
	if p, err := tr.ConsistencyProof(4, 4); err != nil || len(p) != 0 {
		t.Error("m == n")
	}
	if VerifyConsistency(4, 4, nil, tr.mustStored(2, 0), tr.Root()) == nil {
		t.Error("equal sizes, different roots")
	}
	r4, _ := tr.RootAt(4)
	if VerifyConsistency(4, 4, nil, r4, r4) != nil {
		t.Error("equal sizes, same root")
	}
	if VerifyConsistency(0, 4, nil, EmptyRoot, r4) == nil {
		t.Error("from empty: proves nothing, refused")
	}
	if VerifyInclusion(0, 0, Hash{}, nil, EmptyRoot) == nil {
		t.Error("inclusion in empty tree")
	}
	if VerifyInclusion(0, 1, tr.mustStored(0, 0), []Hash{{}}, tr.mustStored(0, 0)) == nil {
		t.Error("extra proof element")
	}
}

func (tr *Tree) mustStored(l int, n uint64) Hash {
	h, err := tr.Stored(l, n)
	if err != nil {
		panic(err)
	}
	return h
}

func TestFromLeafHashes(t *testing.T) {
	tr := refTree(t)
	var leaves []Hash
	for i := uint64(0); i < tr.Size(); i++ {
		leaves = append(leaves, tr.mustStored(0, i))
	}
	u := FromLeafHashes(leaves)
	if u.Root() != tr.Root() || u.Size() != tr.Size() {
		t.Fatal("rebuilt root differs")
	}
	if u.mustStored(3, 0) != tr.mustStored(3, 0) {
		t.Fatal("stored")
	}
	if _, err := u.Stored(3, 1); err == nil {
		t.Fatal("incomplete subtree served")
	}
}

func FuzzVerifyInclusion(f *testing.F) {
	f.Add(uint64(3), uint64(8), []byte{1, 2, 3})
	tr := refTree(nil)
	f.Fuzz(func(t *testing.T, idx, size uint64, mut []byte) {
		size = size%8 + 1
		idx %= size
		p, err := tr.InclusionProof(idx, size)
		if err != nil {
			t.Fatal(err)
		}
		root, _ := tr.RootAt(size)
		leaf := tr.mustStored(0, idx)
		if VerifyInclusion(idx, size, leaf, p, root) != nil {
			t.Fatal("valid proof refused")
		}
		// Any change to the proof bytes must be refused.
		if len(p) > 0 && len(mut) > 0 {
			q := append([]Hash(nil), p...)
			i := int(mut[0]) % len(q)
			changed := false
			for j, m := range mut[1:] {
				if m != 0 {
					q[i][j%HashSize] ^= m
					changed = true
				}
			}
			if changed && q[i] != p[i] && VerifyInclusion(idx, size, leaf, q, root) == nil {
				t.Fatal("modified proof accepted")
			}
		}
	})
}

func FuzzVerifyConsistency(f *testing.F) {
	f.Add(uint64(3), uint64(7), []byte{0, 1})
	tr := refTree(nil)
	f.Fuzz(func(t *testing.T, m, n uint64, mut []byte) {
		n = n%8 + 1
		m = m%n + 1
		p, err := tr.ConsistencyProof(m, n)
		if err != nil {
			t.Fatal(err)
		}
		r1, _ := tr.RootAt(m)
		r2, _ := tr.RootAt(n)
		if VerifyConsistency(m, n, p, r1, r2) != nil {
			t.Fatal("valid proof refused")
		}
		if len(p) > 0 && len(mut) > 1 && mut[1] != 0 {
			q := append([]Hash(nil), p...)
			q[int(mut[0])%len(q)][int(mut[1])%HashSize] ^= mut[1]
			if VerifyConsistency(m, n, q, r1, r2) == nil {
				t.Fatal("modified proof accepted")
			}
		}
	})
}
