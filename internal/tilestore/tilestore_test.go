package tilestore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xtlog "golang.org/x/mod/sumdb/tlog"

	"shunya/internal/checkpoint"
	"shunya/internal/note"
	"shunya/internal/tlog"
)

func signer(t *testing.T) *note.Signer {
	skey, _, err := note.GenerateKey("shunya.test/log")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := note.ParseSignerKey(skey)
	return s
}

// The examples in c2sp.org/tlog-tiles.
func TestSpecExamples(t *testing.T) {
	if p := TilePath(0, 1234067, 256); p != "tile/0/x001/x234/067" {
		t.Fatal(p)
	}
	if p := TilePath(-1, 5, 17); p != "tile/entries/005.p/17" {
		t.Fatal(p)
	}
	count := func(s uint64) map[string]int {
		m := map[string]int{}
		for _, tl := range tilesFor(0, s) {
			if tl.level < 0 {
				continue
			}
			kind := "full"
			if tl.w < TileWidth {
				kind = fmt.Sprintf("p%d", tl.w)
			}
			m[fmt.Sprintf("L%d %s", tl.level, kind)]++
		}
		return m
	}
	// "a tree of size 70,000 will be represented by 273 full level 0 tiles, one partial
	// level 0 tile of width 112, one full level 1 tile, one partial level 1 tile of
	// width 17, and one partial level 2 tile of width 1."
	got := count(70000)
	want := map[string]int{"L0 full": 273, "L0 p112": 1, "L1 full": 1, "L1 p17": 1, "L2 p1": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("70000: %v", got)
	}
	// "a tree of size 256 will be represented by a full level 0 tile and a partial
	// level 1 tile of width 1."
	if g := count(256); fmt.Sprint(g) != fmt.Sprint(map[string]int{"L0 full": 1, "L1 p1": 1}) {
		t.Fatalf("256: %v", g)
	}
}

type xReader struct{ tr *tlog.Tree }

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

// Tiles, their paths and contents agree with golang.org/x/mod/sumdb/tlog (whose tiles
// differ only by the height "8" in the path, and "data" for "entries").
func TestTilesAgainstXMod(t *testing.T) {
	dir := t.TempDir()
	l, err := Create(dir, signer(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 70; i++ {
		var batch [][]byte
		for j := 0; j < 1+i%11; j++ {
			batch = append(batch, []byte(fmt.Sprintf("entry %d.%d", i, j)))
		}
		if _, err := l.Append(batch...); err != nil {
			t.Fatal(err)
		}
	}
	size := l.Size()
	if size < 300 {
		t.Fatal(size)
	}
	r := xReader{l.tree}
	for _, xt := range xtlog.NewTiles(8, 0, int64(size)) {
		want, err := xtlog.ReadTileData(xt, r)
		if err != nil {
			t.Fatal(err)
		}
		p := strings.Replace(xt.Path(), "tile/8/", "tile/", 1)
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

func TestAppendLoadProve(t *testing.T) {
	dir := t.TempDir()
	s := signer(t)
	l, err := Create(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(dir, s); err == nil {
		t.Fatal("second Create over a log")
	}
	var all [][]byte
	for i := 0; i < 600; i += 37 {
		var batch [][]byte
		for j := i; j < min(i+37, 600); j++ {
			batch = append(batch, []byte(fmt.Sprintf("e%03d", j)))
		}
		first, err := l.Append(batch...)
		if err != nil || first != uint64(len(all)) {
			t.Fatalf("append: %d %v", first, err)
		}
		all = append(all, batch...)
	}
	m, err := Load(dir, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := Load(dir, nil, &s.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ro.Append([]byte("x")); err == nil {
		t.Fatal("read-only append")
	}
	cp, err := checkpoint.Open(m.Checkpoint(), &s.Verifier)
	if err != nil || cp.Size != 600 {
		t.Fatal(err, cp.Size)
	}
	for _, i := range []uint64{0, 255, 256, 599} {
		e, _ := m.Entry(i)
		if !bytes.Equal(e, all[i]) {
			t.Fatal("entry", i)
		}
		p, _, err := m.Prove(i)
		if err != nil || tlog.VerifyInclusion(i, cp.Size, tlog.LeafHash(e), p, cp.Root) != nil {
			t.Fatal("proof", i, err)
		}
	}
	p, _, _ := m.Consistency(100)
	old := tlog.FromLeafHashes(nil)
	for _, e := range all[:100] {
		old.Append(e)
	}
	if tlog.VerifyConsistency(100, 600, p, old.Root(), cp.Root) != nil {
		t.Fatal("consistency")
	}
	// Appending after reload continues the same tree.
	if _, err := m.Append([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, nil, &s.Verifier); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Append(make([]byte, 1<<16)); err == nil {
		t.Fatal("oversized entry")
	}
}

func filled(t *testing.T, n int) (string, *note.Signer) {
	dir := t.TempDir()
	s := signer(t)
	l, err := Create(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	var batch [][]byte
	for i := 0; i < n; i++ {
		batch = append(batch, []byte(fmt.Sprintf("entry-%04d", i)))
	}
	if _, err := l.Append(batch[:n/2]...); err != nil { // two appends: older partials exist too
		t.Fatal(err)
	}
	if _, err := l.Append(batch[n/2:]...); err != nil {
		t.Fatal(err)
	}
	return dir, s
}

// Edited, deleted or reordered entries and edited tiles are found on load.
func TestTamperFoundOnLoad(t *testing.T) {
	edit := func(rel string, f func([]byte) []byte) func(string) {
		return func(dir string) {
			p := filepath.Join(dir, filepath.FromSlash(rel))
			b, err := os.ReadFile(p)
			if err != nil {
				panic(err)
			}
			os.WriteFile(p, f(b), 0o644)
		}
	}
	cases := map[string]func(string){
		"entry byte edited": edit("tile/entries/000", func(b []byte) []byte {
			i := bytes.Index(b, []byte("entry-0007"))
			b[i+9] = '8'
			return b
		}),
		"entries swapped": edit("tile/entries/000", func(b []byte) []byte {
			a, c := bytes.Index(b, []byte("entry-0001")), bytes.Index(b, []byte("entry-0002"))
			copy(b[a:], "entry-0002")
			copy(b[c:], "entry-0001")
			return b
		}),
		"entry deleted": edit("tile/entries/001.p/44", func(b []byte) []byte { return b[12:] }),
		"tile edited":   edit("tile/0/000", func(b []byte) []byte { b[5] ^= 1; return b }),
		"level-1 tile":  edit("tile/1/000.p/1", func(b []byte) []byte { b[0] ^= 1; return b }),
		"bundle gone":   func(dir string) { os.Remove(filepath.Join(dir, "tile", "entries", "000")) },
		"checkpoint edited": edit("checkpoint", func(b []byte) []byte {
			return bytes.Replace(b, []byte("\n300\n"), []byte("\n299\n"), 1)
		}),
	}
	// Entries and tiles rewritten together (self-consistent), the signed checkpoint kept:
	// only the root comparison sees it.
	cases["entries and tiles rewritten"] = func(dir string) {
		other := t.TempDir()
		l, _ := Create(other, signer(t))
		var es [][]byte
		for i := 0; i < 300; i++ {
			es = append(es, []byte(fmt.Sprintf("entry-%04d", i)))
		}
		es[7] = []byte("entry-9999")
		l.Append(es...)
		os.RemoveAll(filepath.Join(dir, "tile"))
		os.Rename(filepath.Join(other, "tile"), filepath.Join(dir, "tile"))
	}
	for name, tamper := range cases {
		dir, s := filled(t, 300)
		if _, err := Load(dir, s, nil); err != nil {
			t.Fatal(err)
		}
		tamper(dir)
		if _, err := Load(dir, s, nil); err == nil {
			t.Errorf("%s: not found", name)
		}
	}
}

// Debris from an append that crashed before publishing is overwritten; a file the
// published checkpoint covers is never changed.
func TestCrashDebrisAndImmutability(t *testing.T) {
	dir, s := filled(t, 10)
	os.MkdirAll(filepath.Join(dir, "tile", "entries", "000.p"), 0o755)
	os.WriteFile(filepath.Join(dir, "tile", "entries", "000.p", "11"), []byte("junk"), 0o644)
	os.WriteFile(filepath.Join(dir, "tile", "0", "000.p", "11"), []byte("junk"), 0o644)
	l, err := Load(dir, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append([]byte("eleventh")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, s, nil); err != nil {
		t.Fatal(err)
	}
	err = l.writeImmutable("tile/0/000.p/11", []byte("changed"), tile{0, 0, 11}, 11)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("covered tile rewritten: %v", err)
	}
}
