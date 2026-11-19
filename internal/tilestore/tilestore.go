// Package tilestore keeps a transparency log as C2SP tlog-tiles static files
// (c2sp.org/tlog-tiles):
//
//	DIR/checkpoint                       the signed checkpoint (replaced atomically)
//	DIR/tile/<L>/<N>[.p/<W>]             Merkle tree tiles: 256 hashes, or W for a partial tile
//	DIR/tile/entries/<N>[.p/<W>]         entry bundles: uint16-length-prefixed entries
//
// N is written in 3-digit groups, all but the last prefixed with "x" (1234067 →
// x001/x234/067). A level-L tile holds the hashes of the complete subtrees of 256^L
// leaves; partial tiles are kept for every checkpoint size that was published.
//
// One process writes (Append is serialised). Every append writes and syncs tiles and
// bundles first and the checkpoint last, so a crash leaves the old checkpoint valid;
// files beyond it are rewritten on the next append. Files covered by the current
// checkpoint are never changed: a write that would change one is an error.
//
// Load re-reads every entry, rebuilds the tree, and checks the root against the
// checkpoint and every tile against the rebuilt hashes: an edited, deleted or
// reordered entry, or an edited tile, is found before the log serves anything.
package tilestore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"shunya/internal/checkpoint"
	"shunya/internal/note"
	"shunya/internal/tlog"
)

const (
	TileWidth = 256
	tileH     = 8 // tree levels per tile
)

var ErrCorrupt = errors.New("tilestore: log files are inconsistent")

// TilePath is a tile's path relative to the log root; level -1 is the entry bundle.
func TilePath(level int, n uint64, width int) string {
	var b strings.Builder
	b.WriteString("tile/")
	if level < 0 {
		b.WriteString("entries")
	} else {
		b.WriteString(strconv.Itoa(level))
	}
	b.WriteString("/")
	b.WriteString(indexPath(n))
	if width < TileWidth {
		fmt.Fprintf(&b, ".p/%d", width)
	}
	return b.String()
}

func indexPath(n uint64) string {
	parts := []string{fmt.Sprintf("%03d", n%1000)}
	for n /= 1000; n > 0; n /= 1000 {
		parts = append([]string{fmt.Sprintf("x%03d", n%1000)}, parts...)
	}
	return strings.Join(parts, "/")
}

// Log is an open tile store.
type Log struct {
	dir    string
	signer *note.Signer // nil: read-only
	origin string

	mu      sync.Mutex
	tree    *tlog.Tree
	entries [][]byte
	signed  []byte // current signed checkpoint
}

// Create starts an empty log in dir (which must not already hold one) and signs its
// first checkpoint (size 0). The signer's key name is the log's origin.
func Create(dir string, s *note.Signer) (*Log, error) {
	if _, err := os.Stat(filepath.Join(dir, "checkpoint")); err == nil {
		return nil, fmt.Errorf("tilestore: %s already holds a log", dir)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tile"), 0o755); err != nil {
		return nil, err
	}
	l := &Log{dir: dir, signer: s, origin: s.Name, tree: &tlog.Tree{}}
	if err := l.publish(); err != nil {
		return nil, err
	}
	return l, nil
}

// Load opens a log for appending (s != nil) or reading (s == nil, with v the log's
// verifier key), checking all of it.
func Load(dir string, s *note.Signer, v *note.Verifier) (*Log, error) {
	if s != nil {
		v = &s.Verifier
	}
	signed, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		return nil, err
	}
	cp, err := checkpoint.Open(signed, v)
	if err != nil {
		return nil, fmt.Errorf("%w: checkpoint: %v", ErrCorrupt, err)
	}
	entries, err := ReadEntries(os.DirFS(dir), cp.Size)
	if err != nil {
		return nil, err
	}
	l := &Log{dir: dir, signer: s, origin: cp.Origin, tree: &tlog.Tree{}, entries: entries, signed: signed}
	for _, e := range entries {
		l.tree.Append(e)
	}
	if err := CheckTiles(os.DirFS(dir), l.tree, cp); err != nil {
		return nil, err
	}
	return l, nil
}

// ReadEntries reads the first size entries from the bundles in fsys.
func ReadEntries(fsys fs.FS, size uint64) ([][]byte, error) {
	var out [][]byte
	for n := uint64(0); n*TileWidth < size; n++ {
		w := int(min(size-n*TileWidth, TileWidth))
		b, err := fs.ReadFile(fsys, TilePath(-1, n, w))
		if err != nil {
			return nil, fmt.Errorf("%w: entry bundle %d: %v", ErrCorrupt, n, err)
		}
		es, err := SplitBundle(b)
		if err != nil || len(es) != w {
			return nil, fmt.Errorf("%w: entry bundle %d holds %d entries, want %d (%v)", ErrCorrupt, n, len(es), w, err)
		}
		out = append(out, es...)
	}
	return out, nil
}

// SplitBundle parses an entry bundle.
func SplitBundle(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("truncated length")
		}
		n := int(binary.BigEndian.Uint16(b))
		if len(b) < 2+n {
			return nil, errors.New("truncated entry")
		}
		out = append(out, b[2:2+n])
		b = b[2+n:]
	}
	return out, nil
}

// CheckTiles checks that the root matches the checkpoint and that every tile the
// checkpoint requires matches the tree rebuilt from the entries.
func CheckTiles(fsys fs.FS, t *tlog.Tree, cp checkpoint.Checkpoint) error {
	if t.Size() != cp.Size {
		return fmt.Errorf("%w: %d entries, checkpoint size %d", ErrCorrupt, t.Size(), cp.Size)
	}
	if t.Root() != cp.Root {
		return fmt.Errorf("%w: the entries do not hash to the checkpoint's root (an entry was edited, deleted or reordered)", ErrCorrupt)
	}
	for _, tl := range tilesFor(0, cp.Size) {
		if tl.level < 0 {
			continue
		}
		b, err := fs.ReadFile(fsys, TilePath(tl.level, tl.n, tl.w))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if !bytes.Equal(b, tileBytes(t, tl)) {
			return fmt.Errorf("%w: tile %s does not match the entries", ErrCorrupt, TilePath(tl.level, tl.n, tl.w))
		}
	}
	return nil
}

type tile struct {
	level int // -1: entry bundle
	n     uint64
	w     int
}

// tilesFor lists the tiles (and bundles) a tree of size s1 needs that change between
// size s0 and s1: at each level the tiles from the one holding hash s0 onwards.
func tilesFor(s0, s1 uint64) []tile {
	var out []tile
	for level := 0; ; level++ {
		w1 := s1 >> (tileH * level) // hashes at this level
		if w1 == 0 {
			break
		}
		w0 := s0 >> (tileH * level)
		first := w0 / TileWidth
		if s0 == 0 {
			first = 0
		}
		for n := first; n*TileWidth < w1; n++ {
			w := int(min(w1-n*TileWidth, TileWidth))
			if n*TileWidth+uint64(w) <= w0 { // unchanged since s0
				continue
			}
			out = append(out, tile{level, n, w})
			if level == 0 {
				out = append(out, tile{-1, n, w})
			}
		}
	}
	return out
}

func tileBytes(t *tlog.Tree, tl tile) []byte {
	b := make([]byte, 0, tl.w*tlog.HashSize)
	for i := 0; i < tl.w; i++ {
		h, err := t.Stored(tl.level*tileH, tl.n*TileWidth+uint64(i))
		if err != nil {
			panic(err) // the caller asked for a tile the tree has
		}
		b = append(b, h[:]...)
	}
	return b
}

func bundleBytes(entries [][]byte, tl tile) []byte {
	var b []byte
	for _, e := range entries[tl.n*TileWidth : tl.n*TileWidth+uint64(tl.w)] {
		b = binary.BigEndian.AppendUint16(b, uint16(len(e)))
		b = append(b, e...)
	}
	return b
}

// Size is the published tree size.
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(len(l.entries))
}

// Origin is the log's checkpoint origin.
func (l *Log) Origin() string { return l.origin }

// Checkpoint is the current signed checkpoint.
func (l *Log) Checkpoint() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.signed
}

// Entry returns entry i.
func (l *Log) Entry(i uint64) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i >= uint64(len(l.entries)) {
		return nil, false
	}
	return l.entries[i], true
}

// Entries calls f for every entry in order, holding the lock; f must not call l.
func (l *Log) Entries(f func(i uint64, e []byte)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i, e := range l.entries {
		f(uint64(i), e)
	}
}

// Prove returns an inclusion proof of entry i against the current checkpoint, with
// that checkpoint.
func (l *Log) Prove(i uint64) ([]tlog.Hash, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := l.tree.InclusionProof(i, l.tree.Size())
	return p, l.signed, err
}

// Consistency proves the tree of size m is a prefix of the current one.
func (l *Log) Consistency(m uint64) ([]tlog.Hash, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := l.tree.ConsistencyProof(m, l.tree.Size())
	return p, l.signed, err
}

// Append adds entries, writes their tiles and publishes a new checkpoint. It returns
// the first entry's index. Nothing is published unless every file was written.
func (l *Log) Append(entries ...[]byte) (uint64, error) {
	if l.signer == nil {
		return 0, errors.New("tilestore: log opened read-only")
	}
	for _, e := range entries {
		if len(e) > 1<<16-1 {
			return 0, fmt.Errorf("tilestore: entry of %d bytes exceeds the 65535-byte limit", len(e))
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	first := l.tree.Size()
	n := len(l.entries)
	for _, e := range entries {
		l.entries = append(l.entries, append([]byte(nil), e...))
		l.tree.Append(e)
	}
	if err := l.publishFrom(first); err != nil {
		// Roll back in memory; the files on disk past the old checkpoint are harmless
		// and get rewritten next time.
		l.entries = l.entries[:n]
		rebuilt := &tlog.Tree{}
		for _, e := range l.entries {
			rebuilt.Append(e)
		}
		l.tree = rebuilt
		return 0, err
	}
	return first, nil
}

func (l *Log) publish() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.publishFrom(0)
}

// publishFrom writes the tiles that changed since size s0, then the checkpoint.
func (l *Log) publishFrom(s0 uint64) error {
	s1 := l.tree.Size()
	for _, tl := range tilesFor(s0, s1) {
		var data []byte
		if tl.level < 0 {
			data = bundleBytes(l.entries, tl)
		} else {
			data = tileBytes(l.tree, tl)
		}
		if err := l.writeImmutable(TilePath(tl.level, tl.n, tl.w), data, tl, s0); err != nil {
			return err
		}
	}
	cp := checkpoint.Checkpoint{Origin: l.origin, Size: s1, Root: l.tree.Root()}
	signed, err := checkpoint.Sign(cp, l.signer)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(l.dir, "checkpoint"), signed); err != nil {
		return err
	}
	l.signed = signed
	return nil
}

// writeImmutable writes a tile file. An existing file with the same content is left;
// one with different content is replaced only if the published checkpoint (size s0)
// does not cover it, i.e. it is debris from an append that crashed before publishing.
func (l *Log) writeImmutable(rel string, data []byte, tl tile, s0 uint64) error {
	p := filepath.Join(l.dir, filepath.FromSlash(rel))
	if old, err := os.ReadFile(p); err == nil {
		if bytes.Equal(old, data) {
			return nil
		}
		level := max(tl.level, 0)
		if tl.n*TileWidth+uint64(tl.w) <= s0>>(tileH*level) {
			return fmt.Errorf("%w: %s differs from the published log", ErrCorrupt, rel)
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return writeAtomic(p, data)
}

// writeAtomic writes via a synced temporary file renamed into place, then syncs the
// directory so the rename survives power loss.
func writeAtomic(p string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" { // directories cannot be synced there
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
