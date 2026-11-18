// Package qr encodes QR Code symbols (ISO/IEC 18004) for certificate links: byte
// mode, error correction level M (about 15 % of the symbol can be damaged), versions
// 1–10 (up to 213 bytes). All eight masks are evaluated with the standard penalty
// rules and the lowest wins, so the output is deterministic.
//
// Only what Shunya needs is implemented; the structure follows the standard's
// description (and Project Nayuki's reference implementation, MIT).
package qr

import "errors"

// MaxVersion is the largest symbol supported (57×57 modules).
const MaxVersion = 10

// ErrTooLong: the data does not fit a version-10 level-M symbol.
var ErrTooLong = errors.New("qr: data too long")

// Code is an encoded symbol.
type Code struct {
	Version int
	Size    int // modules per side, 17+4·Version (without the quiet zone)
	Mask    int
	mods    []bool
}

// Black reports whether module (x, y) is dark; (0, 0) is the top-left.
func (c *Code) Black(x, y int) bool { return c.mods[y*c.Size+x] }

type group struct{ count, data int }

// blocks is ISO 18004 Table 9 for level M: ECC codewords per block, then the
// block groups (number of blocks × data codewords).
var blocks = [MaxVersion + 1]struct {
	ecc    int
	groups []group
}{
	1:  {10, []group{{1, 16}}},
	2:  {16, []group{{1, 28}}},
	3:  {26, []group{{1, 44}}},
	4:  {18, []group{{2, 32}}},
	5:  {24, []group{{2, 43}}},
	6:  {16, []group{{4, 27}}},
	7:  {18, []group{{4, 31}}},
	8:  {22, []group{{2, 38}, {2, 39}}},
	9:  {22, []group{{3, 36}, {2, 37}}},
	10: {26, []group{{4, 43}, {1, 44}}},
}

// alignment centres (ISO 18004 Annex E).
var alignment = [MaxVersion + 1][]int{
	2: {6, 18}, 3: {6, 22}, 4: {6, 26}, 5: {6, 30}, 6: {6, 34},
	7: {6, 22, 38}, 8: {6, 24, 42}, 9: {6, 26, 46}, 10: {6, 28, 50},
}

func dataCodewords(v int) int {
	n := 0
	for _, g := range blocks[v].groups {
		n += g.count * g.data
	}
	return n
}

func countBits(v int) int {
	if v <= 9 {
		return 8
	}
	return 16
}

// Capacity is the number of bytes a version-v level-M symbol holds.
func Capacity(v int) int { return (dataCodewords(v)*8 - 4 - countBits(v)) / 8 }

// Encode returns the smallest symbol holding data, with the best mask.
func Encode(data []byte) (*Code, error) {
	best := (*Code)(nil)
	bestScore := 0
	for m := 0; m < 8; m++ {
		c, err := encodeMask(data, m)
		if err != nil {
			return nil, err
		}
		if s := penalty(c); best == nil || s < bestScore {
			best, bestScore = c, s
		}
	}
	return best, nil
}

func encodeMask(data []byte, mask int) (*Code, error) {
	v := 1
	for v <= MaxVersion && Capacity(v) < len(data) {
		v++
	}
	if v > MaxVersion {
		return nil, ErrTooLong
	}
	cw := interleave(v, codewords(v, data))
	c := &Code{Version: v, Size: 17 + 4*v, Mask: mask}
	c.mods = make([]bool, c.Size*c.Size)
	fn := c.drawFunction()
	// Data modules in the zigzag order, then the mask (function modules untouched).
	i := 0
	for right := c.Size - 1; right >= 1; right -= 2 {
		if right == 6 { // the vertical timing pattern
			right = 5
		}
		for vert := 0; vert < c.Size; vert++ {
			for j := 0; j < 2; j++ {
				x, y := right-j, vert
				if (right+1)&2 == 0 { // upward column pair
					y = c.Size - 1 - vert
				}
				if fn[y*c.Size+x] {
					continue
				}
				dark := false
				if i < len(cw)*8 {
					dark = cw[i/8]>>(7-i%8)&1 == 1
					i++
				} // remainder bits stay light before masking
				c.mods[y*c.Size+x] = dark != maskBit(mask, x, y)
			}
		}
	}
	c.drawFormat(formatBits(mask))
	return c, nil
}

// codewords builds the data codewords: mode, count, bytes, terminator, padding.
func codewords(v int, data []byte) []byte {
	n := dataCodewords(v)
	var bits []bool
	put := func(val, k int) {
		for i := k - 1; i >= 0; i-- {
			bits = append(bits, val>>i&1 == 1)
		}
	}
	put(0b0100, 4)
	put(len(data), countBits(v))
	for _, b := range data {
		put(int(b), 8)
	}
	put(0, min(4, n*8-len(bits)))
	for len(bits)%8 != 0 {
		bits = append(bits, false)
	}
	out := make([]byte, 0, n)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for k := 0; k < 8; k++ {
			if bits[i+k] {
				b |= 0x80 >> k
			}
		}
		out = append(out, b)
	}
	for pad := byte(0xec); len(out) < n; pad ^= 0xec ^ 0x11 {
		out = append(out, pad)
	}
	return out
}

// interleave splits the data into blocks, appends each block's ECC and interleaves
// (data codewords column by column, then ECC codewords).
func interleave(v int, data []byte) []byte {
	b := blocks[v]
	var ds, es [][]byte
	off := 0
	for _, g := range b.groups {
		for range g.count {
			d := data[off : off+g.data]
			off += g.data
			ds = append(ds, d)
			es = append(es, rsRemainder(d, b.ecc))
		}
	}
	var out []byte
	for col := 0; col < len(ds[len(ds)-1]); col++ {
		for _, d := range ds {
			if col < len(d) {
				out = append(out, d[col])
			}
		}
	}
	for col := 0; col < b.ecc; col++ {
		for _, e := range es {
			out = append(out, e[col])
		}
	}
	return out
}

// --- GF(256), polynomial 0x11d, generator α = 2 ---

func gfMul(a, b byte) byte {
	var p byte
	for b != 0 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return p
}

// rsRemainder is the Reed–Solomon ECC: data·x^n mod ∏(x − α^i), i < n.
func rsRemainder(data []byte, n int) []byte {
	gen := []byte{1} // coefficients, highest degree first (leading 1 implied below)
	root := byte(1)
	for range n {
		next := make([]byte, len(gen)+1)
		for i, g := range gen {
			next[i] ^= g
			next[i+1] ^= gfMul(g, root)
		}
		gen = next
		root = gfMul(root, 2)
	}
	gen = gen[1:]
	rem := make([]byte, n)
	for _, d := range data {
		f := d ^ rem[0]
		copy(rem, rem[1:])
		rem[n-1] = 0
		for i := range rem {
			rem[i] ^= gfMul(gen[i], f)
		}
	}
	return rem
}

// --- function patterns ---

// functionMap marks the modules that are not data (finders, separators, timing,
// alignment, format and version information, the dark module).
func functionMap(v int) []bool {
	c := &Code{Version: v, Size: 17 + 4*v}
	c.mods = make([]bool, c.Size*c.Size)
	return c.drawFunction()
}

func (c *Code) drawFunction() []bool {
	n := c.Size
	fn := make([]bool, n*n)
	set := func(x, y int, dark bool) {
		c.mods[y*n+x] = dark
		fn[y*n+x] = true
	}
	for i := 0; i < n; i++ {
		set(6, i, i%2 == 0)
		set(i, 6, i%2 == 0)
	}
	for _, o := range [][2]int{{3, 3}, {n - 4, 3}, {3, n - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				x, y := o[0]+dx, o[1]+dy
				if x < 0 || x >= n || y < 0 || y >= n {
					continue
				}
				d := max(abs(dx), abs(dy))
				set(x, y, d != 2 && d != 4)
			}
		}
	}
	al := alignment[c.Version]
	for i, ax := range al {
		for j, ay := range al {
			if (i == 0 && j == 0) || (i == 0 && j == len(al)-1) || (i == len(al)-1 && j == 0) {
				continue // overlaps a finder
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					set(ax+dx, ay+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	// Reserve the format areas (drawn later) and draw the version information.
	for i := 0; i < 9; i++ {
		fn[8*n+i], fn[i*n+8] = true, true
	}
	for i := 0; i < 8; i++ {
		fn[8*n+n-1-i], fn[(n-1-i)*n+8] = true, true
	}
	set(8, n-8, true) // the dark module
	if c.Version >= 7 {
		vb := versionBits(c.Version)
		for i := 0; i < 18; i++ {
			dark := vb>>i&1 == 1
			a, b := n-11+i%3, i/3
			set(a, b, dark)
			set(b, a, dark)
		}
	}
	return fn
}

// drawFormat writes both copies of the 15 format bits.
func (c *Code) drawFormat(bits int) {
	n := c.Size
	set := func(x, y, i int) { c.mods[y*n+x] = bits>>i&1 == 1 }
	for i := 0; i <= 5; i++ {
		set(8, i, i)
	}
	set(8, 7, 6)
	set(8, 8, 7)
	set(7, 8, 8)
	for i := 9; i < 15; i++ {
		set(14-i, 8, i)
	}
	for i := 0; i < 8; i++ {
		set(n-1-i, 8, i)
	}
	for i := 8; i < 15; i++ {
		set(8, n-15+i, i)
	}
	c.mods[(n-8)*n+8] = true
}

// formatBits: level M (00) and the mask, BCH(15,5) with generator 0x537, XOR 0x5412.
func formatBits(mask int) int {
	data := 0b00<<3 | mask
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	return (data<<10 | rem) ^ 0x5412
}

// versionBits: BCH(18,6) with generator 0x1f25.
func versionBits(v int) int {
	rem := v
	for range 12 {
		rem = rem<<1 ^ (rem>>11)*0x1f25
	}
	return v<<12 | rem
}

// maskBit reports whether mask m inverts module (x, y) (ISO 18004 Table 10; i is the
// row, j the column).
func maskBit(m, x, y int) bool {
	i, j := y, x
	switch m {
	case 0:
		return (i+j)%2 == 0
	case 1:
		return i%2 == 0
	case 2:
		return j%3 == 0
	case 3:
		return (i+j)%3 == 0
	case 4:
		return (i/2+j/3)%2 == 0
	case 5:
		return i*j%2+i*j%3 == 0
	case 6:
		return (i*j%2+i*j%3)%2 == 0
	}
	return ((i+j)%2+i*j%3)%2 == 0
}

// rawModules counts the data modules of version v (codewords·8 + remainder bits).
func rawModules(v int) int {
	fn := functionMap(v)
	n := 0
	for _, f := range fn {
		if !f {
			n++
		}
	}
	return n
}

// --- mask penalty (ISO 18004 §7.8.3) ---

func penalty(c *Code) int {
	n := c.Size
	score := 0
	// N1: runs of five or more same-coloured modules in a row or column.
	for _, horiz := range []bool{true, false} {
		for a := 0; a < n; a++ {
			run := 0
			var prev bool
			for b := 0; b < n; b++ {
				m := c.Black(b, a)
				if !horiz {
					m = c.Black(a, b)
				}
				if b > 0 && m == prev {
					run++
				} else {
					if run >= 5 {
						score += 3 + run - 5
					}
					run, prev = 1, m
				}
			}
			if run >= 5 {
				score += 3 + run - 5
			}
		}
	}
	// N2: 2×2 blocks of one colour.
	for y := 0; y+1 < n; y++ {
		for x := 0; x+1 < n; x++ {
			m := c.Black(x, y)
			if m == c.Black(x+1, y) && m == c.Black(x, y+1) && m == c.Black(x+1, y+1) {
				score += 3
			}
		}
	}
	score += finderLike(c)
	// N4: 10 points per full 5 % the dark share is away from 50 %.
	dark := 0
	for _, m := range c.mods {
		if m {
			dark++
		}
	}
	total := n * n
	score += abs(dark*2-total) * 10 / total * 10
	return score
}

// finderLike is N3: 1:1:3:1:1 patterns with four light modules on one side.
func finderLike(c *Code) int {
	n := c.Size
	pats := [2][11]bool{
		{true, false, true, true, true, false, true, false, false, false, false},
		{false, false, false, false, true, false, true, true, true, false, true},
	}
	score := 0
	for _, horiz := range []bool{true, false} {
		for a := 0; a < n; a++ {
			for b := 0; b+11 <= n; b++ {
				for _, p := range pats {
					ok := true
					for k := 0; k < 11 && ok; k++ {
						m := c.Black(b+k, a)
						if !horiz {
							m = c.Black(a, b+k)
						}
						ok = m == p[k]
					}
					if ok {
						score += 40
					}
				}
			}
		}
	}
	return score
}

func abs(i int) int {
	if i < 0 {
		return -i
	}
	return i
}
