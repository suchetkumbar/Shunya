package canary

import (
	"bytes"
	"testing"
)

func testSet(t testing.TB) *Set {
	t.Helper()
	s, err := NewSet(bytes.Repeat([]byte{0x11}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTokensUniqueAndValid(t *testing.T) {
	s := testSet(t)
	seen := map[string]bool{}
	for sector := uint64(0); sector < 64; sector++ {
		buf := make([]byte, 512)
		s.FillSector(buf, sector)
		for i := 0; i < len(buf); i += TokenSize {
			tok := buf[i : i+TokenSize]
			if seen[string(tok)] {
				t.Fatalf("duplicate token at sector %d index %d", sector, i/TokenSize)
			}
			seen[string(tok)] = true
			sec, idx, ok := s.Validate(tok)
			if !ok || sec != sector || int(idx) != i/TokenSize {
				t.Fatalf("validate sector %d index %d: got %d %d %v", sector, i/TokenSize, sec, idx, ok)
			}
			if !bytes.Equal(tok[:MagicSize], s.Magic()) {
				t.Fatal("token does not start with the magic")
			}
		}
	}
}

func TestFillDeterministicAndKeyed(t *testing.T) {
	a, b := make([]byte, 4096), make([]byte, 4096)
	testSet(t).FillSector(a, 7)
	testSet(t).FillSector(b, 7)
	if !bytes.Equal(a, b) {
		t.Fatal("same key, same sector: different canaries")
	}
	other, _ := NewSet(bytes.Repeat([]byte{0x22}, KeySize))
	other.FillSector(b, 7)
	if bytes.Equal(a[:MagicSize], b[:MagicSize]) || bytes.Equal(a, b) {
		t.Fatal("different keys gave the same magic or canaries")
	}
}

func TestValidateRejectsForgery(t *testing.T) {
	s := testSet(t)
	tok := make([]byte, TokenSize)
	s.Token(tok, 1234, 5)
	for i := range tok {
		bad := bytes.Clone(tok)
		bad[i] ^= 0x01
		if _, _, ok := s.Validate(bad); ok {
			t.Fatalf("flipped byte %d still validates", i)
		}
	}
	if _, _, ok := s.Validate(tok[:TokenSize-1]); ok {
		t.Fatal("short token validates")
	}
	other, _ := NewSet(bytes.Repeat([]byte{0x22}, KeySize))
	if _, _, ok := other.Validate(tok); ok {
		t.Fatal("token validates under another key")
	}
}

func TestNewSetRejectsBadKey(t *testing.T) {
	if _, err := NewSet(make([]byte, 16)); err == nil {
		t.Fatal("16-byte key accepted")
	}
}

func BenchmarkFillSector(b *testing.B) {
	s := testSet(b)
	buf := make([]byte, 1<<20)
	b.SetBytes(int64(len(buf)))
	var sector uint64
	for b.Loop() {
		for off := 0; off < len(buf); off += 512 {
			s.FillSector(buf[off:off+512], sector)
			sector++
		}
	}
}
