package canary

import (
	"bytes"
	"context"
	"math/rand/v2"
	"testing"
)

func randomBytes(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func scan(t *testing.T, sc *Scanner, data []byte, chunk int) Residue {
	t.Helper()
	res, err := sc.Scan(context.Background(), bytes.NewReader(data), int64(len(data)), chunk)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A single token planted at every byte offset 0..1023 of random data (so across the
// 512-byte chunk boundary too) is found exactly once, at the right offset.
func TestScanFindsTokenAtEveryOffset(t *testing.T) {
	s := testSet(t)
	sc := NewScanner(s, nil, 512)
	tok := make([]byte, TokenSize)
	s.Token(tok, 3, 0)
	for off := 0; off <= 2048-TokenSize; off++ {
		data := randomBytes(2048, 9)
		copy(data[off:], tok)
		res := scan(t, sc, data, 512)
		if res.Tokens != 1 || res.Partial != 0 || res.FirstOffset != int64(off) {
			t.Fatalf("offset %d: %+v", off, res)
		}
		wantDisplaced := int64(0)
		if off/512 != 3 {
			wantDisplaced = 1
		}
		if res.Displaced != wantDisplaced {
			t.Fatalf("offset %d: displaced %d", off, res.Displaced)
		}
	}
}

func TestScanWholeCanaryImage(t *testing.T) {
	s := testSet(t)
	const sectors = 257
	data := make([]byte, sectors*512)
	for i := range sectors {
		s.FillSector(data[i*512:(i+1)*512], uint64(i))
	}
	for _, chunk := range []int{512, 4096, 64 << 10} {
		res := scan(t, NewScanner(s, nil, 512), data, chunk)
		if res.Tokens != sectors*16 || res.Displaced != 0 || res.Partial != 0 || res.LastOffset != int64(len(data)-TokenSize) {
			t.Fatalf("chunk %d: %+v", chunk, res)
		}
	}
	// Overwrite all but the last sector: only its 16 tokens remain.
	clear(data[:len(data)-512])
	res := scan(t, NewScanner(s, nil, 512), data, 4096)
	if res.Tokens != 16 || res.FirstOffset != int64(len(data)-512) {
		t.Fatalf("tail residue: %+v", res)
	}
}

func TestScanPartialAndForged(t *testing.T) {
	s := testSet(t)
	tok := make([]byte, TokenSize)
	s.Token(tok, 1, 0)
	data := randomBytes(4096, 1)
	copy(data[100:], tok[:20])     // cut by a later write: magic + 12 bytes
	copy(data[1000:], tok)         // whole
	data[1000+TokenSize-1] ^= 1    // ...but altered
	copy(data[4096-10:], tok[:10]) // cut off by the end of the device
	res := scan(t, NewScanner(s, nil, 512), data, 512)
	if res.Tokens != 0 || res.Partial != 3 {
		t.Fatalf("%+v", res)
	}
	if res.Clean() {
		t.Fatal("partial residue reported clean")
	}
}

func TestScanMarkersAndClean(t *testing.T) {
	s := testSet(t)
	mk := []string{"SHUNYA-MARKER-aaaa", "SHUNYA-MARKER-bbbb"}
	sc := NewScanner(s, mk, 512)
	data := randomBytes(8192, 2)
	if res := scan(t, sc, data, 512); !res.Clean() || res.FirstOffset != -1 {
		t.Fatalf("random data not clean: %+v", res)
	}
	copy(data[510:], mk[0]) // across a chunk boundary
	copy(data[3000:], mk[0])
	copy(data[8192-len(mk[1]):], mk[1])
	res := scan(t, sc, data, 512)
	if res.Markers[mk[0]] != 2 || res.Markers[mk[1]] != 1 || res.MarkerHits() != 3 || res.Clean() {
		t.Fatalf("%+v", res)
	}
}

func BenchmarkScan(b *testing.B) {
	s := testSet(b)
	data := randomBytes(16<<20, 5)
	sc := NewScanner(s, []string{"SHUNYA-MARKER-0123456789abcdef"}, 512)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if _, err := sc.Scan(context.Background(), bytes.NewReader(data), int64(len(data)), 1<<20); err != nil {
			b.Fatal(err)
		}
	}
}

// Any data, any chunk size: a token planted anywhere is found, and the scan never
// panics or reports offsets outside the data.
func FuzzScan(f *testing.F) {
	f.Add([]byte("some data"), uint16(0), uint8(1))
	f.Add(make([]byte, 1500), uint16(511), uint8(2))
	s := testSet(f)
	tok := make([]byte, TokenSize)
	s.Token(tok, 9, 1)
	f.Fuzz(func(t *testing.T, data []byte, at uint16, chunkSectors uint8) {
		if len(data) < TokenSize {
			return
		}
		pos := int(at) % (len(data) - TokenSize + 1)
		d := append([]byte(nil), data...)
		copy(d[pos:], tok)
		sc := NewScanner(s, []string{"SHUNYA-MARKER-x"}, 512)
		res, err := sc.Scan(context.Background(), bytes.NewReader(d), int64(len(d)), 512*(int(chunkSectors%8)+1))
		if err != nil {
			t.Fatal(err)
		}
		if res.Tokens < 1 || res.FirstOffset < 0 || res.LastOffset > int64(len(d)-MagicSize) || res.BytesScanned != int64(len(d)) {
			t.Fatalf("pos %d: %+v", pos, res)
		}
	})
}
