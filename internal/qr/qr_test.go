package qr

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Published values (ISO/IEC 18004:2015 Annex C/D tables, reproduced in the Thonky QR
// tutorial https://www.thonky.com/qr-code-tutorial/): the 1-M Reed–Solomon example for
// "HELLO WORLD", the level-M format strings and the version 7–10 information strings.

func TestReedSolomonHelloWorld(t *testing.T) {
	data := []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17}
	want := []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23}
	if got := rsRemainder(data, 10); !bytes.Equal(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

func TestFormatBits(t *testing.T) {
	want := []string{"101010000010010", "101000100100101", "101111001111100", "101101101001011",
		"100010111111001", "100000011001110", "100111110010111", "100101010100000"}
	for mask, w := range want {
		if got := fmt.Sprintf("%015b", formatBits(mask)); got != w {
			t.Errorf("mask %d: %s, want %s", mask, got, w)
		}
	}
}

func TestVersionBits(t *testing.T) {
	for v, w := range map[int]string{7: "000111110010010100", 8: "001000010110111100",
		9: "001001101010011001", 10: "001010010011010011"} {
		if got := fmt.Sprintf("%018b", versionBits(v)); got != w {
			t.Errorf("version %d: %s, want %s", v, got, w)
		}
	}
}

func TestBlockTable(t *testing.T) {
	// Total codewords per version (ISO 18004 Table 1) and byte-mode capacity at level M
	// (Table 7).
	total := []int{0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346}
	capM := []int{0, 14, 26, 42, 62, 84, 106, 122, 152, 180, 213}
	for v := 1; v <= MaxVersion; v++ {
		b := blocks[v]
		n := 0
		for _, g := range b.groups {
			n += g.count * (g.data + b.ecc)
		}
		if n != total[v] {
			t.Errorf("v%d: %d codewords, want %d", v, n, total[v])
		}
		if c := Capacity(v); c != capM[v] {
			t.Errorf("v%d: capacity %d, want %d", v, c, capM[v])
		}
		// Raw module count = codewords*8 + remainder bits.
		if raw := rawModules(v); raw/8 != total[v] {
			t.Errorf("v%d: %d data modules for %d codewords", v, raw, total[v])
		}
	}
}

func TestStructure(t *testing.T) {
	for _, n := range []int{1, 14, 15, 100, 152, 153, 213} {
		data := bytes.Repeat([]byte("a"), n)
		c, err := Encode(data)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		for Capacity(want) < n {
			want++
		}
		if c.Version != want || c.Size != 17+4*want {
			t.Errorf("%d bytes: version %d size %d, want version %d", n, c.Version, c.Size, want)
		}
		// Finder patterns: 7×7 dark ring, light ring, 3×3 dark centre, at three corners.
		for _, o := range [][2]int{{0, 0}, {c.Size - 7, 0}, {0, c.Size - 7}} {
			for y := 0; y < 7; y++ {
				for x := 0; x < 7; x++ {
					d := max(abs(x-3), abs(y-3))
					if c.Black(o[0]+x, o[1]+y) != (d != 2) {
						t.Fatalf("v%d finder at %v broken at %d,%d", c.Version, o, x, y)
					}
				}
			}
		}
		for i := 8; i < c.Size-8; i++ {
			if c.Black(i, 6) != (i%2 == 0) || c.Black(6, i) != (i%2 == 0) {
				t.Fatalf("v%d timing pattern at %d", c.Version, i)
			}
		}
		if !c.Black(8, 4*c.Version+9) {
			t.Error("dark module")
		}
		got, err := decode(c)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: decoded %q %v", n, got, err)
		}
	}
	if _, err := Encode(make([]byte, Capacity(MaxVersion)+1)); !errors.Is(err, ErrTooLong) {
		t.Errorf("over capacity: %v", err)
	}
}

func TestAllMasksDecode(t *testing.T) {
	data := []byte("https://verify.shunya.invalid/c/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	seen := map[string]bool{}
	for m := 0; m < 8; m++ {
		c, err := encodeMask(data, m)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decode(c)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("mask %d: %q %v", m, got, err)
		}
		seen[c.String()] = true
	}
	if len(seen) != 8 {
		t.Errorf("masks produced %d distinct symbols", len(seen))
	}
	// Encode picks the mask with the lowest penalty, deterministically.
	a, _ := Encode(data)
	b, _ := Encode(data)
	if a.String() != b.String() || a.Mask < 0 {
		t.Error("not deterministic")
	}
	for m := 0; m < 8; m++ {
		c, _ := encodeMask(data, m)
		if penalty(c) < penalty(a) {
			t.Errorf("mask %d has penalty %d < chosen %d", m, penalty(c), penalty(a))
		}
	}
}

func TestPenaltyRules(t *testing.T) {
	// A 21×21 all-light symbol: N1 per row and column 3+(21-5), N2 for each 2×2 block,
	// N4 for 0 % dark (10 points per 5 % from 50 %).
	c := &Code{Size: 21, mods: make([]bool, 21*21)}
	want := 2*21*(3+16) + 20*20*3 + 100
	if got := penalty(c); got != want {
		t.Errorf("all light: %d, want %d", got, want)
	}
	// The finder-like run 1011101 with four light modules on one side costs 40.
	row := "10111010000"
	c = &Code{Size: len(row), mods: make([]bool, len(row)*len(row))}
	for x, ch := range row {
		c.mods[x] = ch == '1'
	}
	if n3 := finderLike(c); n3 != 40 {
		t.Errorf("N3 %d, want 40", n3)
	}
}

func FuzzEncode(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{0xff}, 213))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Encode(data)
		if len(data) > Capacity(MaxVersion) {
			if err == nil {
				t.Fatal("over capacity accepted")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		got, err := decode(c)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("round trip: %q %v", got, err)
		}
	})
}

// decode reads a symbol back: format information, unmasking, the zigzag codeword
// order, de-interleaving, a Reed–Solomon check of every block and the byte-mode
// segment. (An independent decoder, zbarimg, checks rendered PDFs in the lab.)
func decode(c *Code) ([]byte, error) {
	v := (c.Size - 17) / 4
	// Format information, first copy (Nayuki/ISO positions), nearest valid string.
	var fb int
	for i := 0; i <= 5; i++ {
		fb |= bit(c.Black(8, i)) << i
	}
	fb |= bit(c.Black(8, 7))<<6 | bit(c.Black(8, 8))<<7 | bit(c.Black(7, 8))<<8
	for i := 9; i < 15; i++ {
		fb |= bit(c.Black(14-i, 8)) << i
	}
	mask := -1
	for m := 0; m < 8; m++ {
		if formatBits(m) == fb {
			mask = m
		}
	}
	if mask < 0 {
		return nil, fmt.Errorf("format bits %015b are not level M", fb)
	}
	fn := functionMap(v)
	var bits []bool
	for right := c.Size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := 0; vert < c.Size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = c.Size - 1 - vert
				}
				if !fn[y*c.Size+x] {
					bits = append(bits, c.Black(x, y) != maskBit(mask, x, y))
				}
			}
		}
	}
	cw := make([]byte, len(bits)/8)
	for i := range cw {
		for k := 0; k < 8; k++ {
			if bits[i*8+k] {
				cw[i] |= 0x80 >> k
			}
		}
	}
	// De-interleave.
	b := blocks[v]
	var lens []int
	for _, g := range b.groups {
		for range g.count {
			lens = append(lens, g.data)
		}
	}
	data := make([][]byte, len(lens))
	i := 0
	for col := 0; col < lens[len(lens)-1]; col++ {
		for k, n := range lens {
			if col < n {
				data[k] = append(data[k], cw[i])
				i++
			}
		}
	}
	ecc := make([][]byte, len(lens))
	for col := 0; col < b.ecc; col++ {
		for k := range lens {
			ecc[k] = append(ecc[k], cw[i])
			i++
		}
	}
	var all []byte
	for k := range lens {
		if !bytes.Equal(rsRemainder(data[k], b.ecc), ecc[k]) {
			return nil, fmt.Errorf("block %d fails the Reed–Solomon check", k)
		}
		all = append(all, data[k]...)
	}
	if all[0]>>4 != 0b0100 {
		return nil, fmt.Errorf("mode %04b, want byte mode", all[0]>>4)
	}
	r := bitReader{b: all, pos: 4}
	n := r.read(countBits(v))
	out := make([]byte, n)
	for k := range out {
		out[k] = byte(r.read(8))
	}
	return out, nil
}

type bitReader struct {
	b   []byte
	pos int
}

func (r *bitReader) read(n int) int {
	v := 0
	for range n {
		v = v<<1 | int(r.b[r.pos/8]>>(7-r.pos%8)&1)
		r.pos++
	}
	return v
}

func bit(b bool) int {
	if b {
		return 1
	}
	return 0
}

// String draws the symbol (tests compare symbols with it).
func (c *Code) String() string {
	var s strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				s.WriteByte('#')
			} else {
				s.WriteByte('.')
			}
		}
		s.WriteByte('\n')
	}
	return s.String()
}
