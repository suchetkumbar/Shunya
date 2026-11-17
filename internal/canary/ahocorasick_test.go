package canary

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"testing"
)

type hit struct {
	pat int
	end int64
}

func naive(pats [][]byte, data []byte) []hit {
	var out []hit
	for end := 1; end <= len(data); end++ {
		for i, p := range pats {
			if end >= len(p) && bytes.Equal(data[end-len(p):end], p) {
				out = append(out, hit{i, int64(end)})
			}
		}
	}
	return out
}

func acHits(m *Matcher, data []byte, chunk int) []hit {
	var out []hit
	st := m.Start()
	var base int64
	for len(data) > 0 {
		n := min(chunk, len(data))
		st = m.Feed(st, data[:n], base, func(pat int, end int64) { out = append(out, hit{pat, end}) })
		base += int64(n)
		data = data[n:]
	}
	return out
}

func sortHits(h []hit) []hit {
	slices.SortFunc(h, func(a, b hit) int {
		if a.end != b.end {
			return int(a.end - b.end)
		}
		return a.pat - b.pat
	})
	return h
}

func TestMatcherClassic(t *testing.T) {
	pats := [][]byte{[]byte("he"), []byte("she"), []byte("his"), []byte("hers")}
	m := NewMatcher(pats)
	got := sortHits(acHits(m, []byte("ushers"), 1))
	want := []hit{{0, 4}, {1, 4}, {3, 6}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func FuzzMatcherVsNaive(f *testing.F) {
	f.Add([]byte("abcabcab"), []byte("abcababcabcabab"), uint8(3))
	f.Add([]byte("aaaa"), []byte("aaaaaaaaaa"), uint8(1))
	f.Fuzz(func(t *testing.T, patSrc, data []byte, chunk uint8) {
		// Split patSrc into up to 4 non-empty patterns over a small alphabet, so matches happen.
		var pats [][]byte
		for i := 0; i < len(patSrc) && len(pats) < 4; i += 3 {
			p := patSrc[i:min(i+3, len(patSrc))]
			q := make([]byte, len(p))
			for j, c := range p {
				q[j] = 'a' + c%3
			}
			pats = append(pats, q)
		}
		if len(pats) == 0 {
			return
		}
		d := make([]byte, len(data))
		for i, c := range data {
			d[i] = 'a' + c%3
		}
		m := NewMatcher(pats)
		got := sortHits(acHits(m, d, int(chunk%17)+1))
		want := sortHits(naive(pats, d))
		if !slices.Equal(got, want) {
			t.Fatalf("pats %q data %q: got %v want %v", pats, d, got, want)
		}
	})
}

func BenchmarkMatcher(b *testing.B) {
	r := rand.New(rand.NewPCG(1, 1))
	data := make([]byte, 4<<20)
	for i := range data {
		data[i] = byte(r.Uint32())
	}
	m := NewMatcher([][]byte{[]byte("12345678"), []byte("SHUNYA-MARKER-0123456789abcdef")})
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		m.Feed(m.Start(), data, 0, func(int, int64) {})
	}
}
