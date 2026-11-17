package canary

import (
	"context"
	"fmt"
	"io"

	"shunya/internal/backend"
)

// Residue is what a raw scan found.
type Residue struct {
	BytesScanned int64 `json:"bytes_scanned"`
	// Tokens: whole, HMAC-valid canary tokens, at any byte offset.
	Tokens int64 `json:"tokens"`
	// Displaced: valid tokens found somewhere other than the sector they were written to
	// (copied by a file system or the drive); counted in Tokens too.
	Displaced int64 `json:"displaced"`
	// Partial: the run magic without a valid token after it (a token cut by a later
	// write, or at the end of the device). Fragments shorter than the 8-byte magic are
	// not detectable.
	Partial     int64            `json:"partial"`
	FirstOffset int64            `json:"first_offset"` // of any token or partial, -1 if none
	LastOffset  int64            `json:"last_offset"`
	Examples    []int64          `json:"examples,omitempty"` // first few offsets
	Markers     map[string]int64 `json:"markers"`            // planted-file marker → occurrences
}

// Clean reports whether nothing at all was found.
func (r Residue) Clean() bool {
	if r.Tokens > 0 || r.Partial > 0 {
		return false
	}
	for _, n := range r.Markers {
		if n > 0 {
			return false
		}
	}
	return true
}

// MarkerHits is the total number of planted-file marker occurrences.
func (r Residue) MarkerHits() int64 {
	var n int64
	for _, c := range r.Markers {
		n += c
	}
	return n
}

// Scanner searches raw data for this run's canaries and planted-file markers.
type Scanner struct {
	set     *Set
	markers []string
	m       *Matcher
	sector  int
}

// NewScanner builds a scanner for set's magic and the given markers. sectorSize is used
// to tell where a token "belongs" (Displaced).
func NewScanner(set *Set, markers []string, sectorSize int) *Scanner {
	pats := [][]byte{set.Magic()}
	for _, mk := range markers {
		pats = append(pats, []byte(mk))
	}
	return &Scanner{set: set, markers: markers, m: NewMatcher(pats), sector: sectorSize}
}

const keepTail = 64 // bytes of the previous chunk kept so tokens across a boundary validate

// Scan reads [0, size) from r in chunks (each chunk offset and length is a multiple of
// chunk, except the last) and reports every residue found.
func (s *Scanner) Scan(ctx context.Context, r io.ReaderAt, size int64, chunk int) (Residue, error) {
	res := Residue{FirstOffset: -1, LastOffset: -1, Markers: map[string]int64{}}
	for _, mk := range s.markers {
		res.Markers[mk] = 0
	}
	if chunk <= 0 || chunk%s.sector != 0 {
		return res, fmt.Errorf("scan: chunk %d not a multiple of sector %d", chunk, s.sector)
	}
	read := backend.AlignedBuffer(chunk, 4096) // O_DIRECT-capable: see Scan's readers
	win := make([]byte, keepTail+chunk)
	winStart, tail := int64(0), 0 // absolute offset of win[0]; bytes of tail kept
	var pending []int64           // token starts waiting for more data
	st := s.m.Start()
	note := func(off int64) {
		if res.FirstOffset < 0 {
			res.FirstOffset = off
		}
		res.LastOffset = max(res.LastOffset, off)
		if len(res.Examples) < 8 {
			res.Examples = append(res.Examples, off)
		}
	}
	validate := func(start int64) {
		tok := win[start-winStart : start-winStart+TokenSize]
		sector, _, ok := s.set.Validate(tok)
		if !ok {
			res.Partial++
		} else {
			res.Tokens++
			if int64(sector) != start/int64(s.sector) {
				res.Displaced++
			}
		}
		note(start)
	}
	for off := int64(0); off < size; off += int64(chunk) {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		n := int(min(int64(chunk), size-off))
		if _, err := r.ReadAt(read[:n], off); err != nil && err != io.EOF {
			return res, fmt.Errorf("scan: read at %d: %w", off, err)
		}
		copy(win[tail:], read[:n])
		end := off + int64(n)
		st = s.m.Feed(st, read[:n], off, func(p int, e int64) {
			if p == 0 {
				pending = append(pending, e-int64(MagicSize))
			} else {
				res.Markers[s.markers[p-1]]++
			}
		})
		kept := pending[:0]
		for _, start := range pending {
			if start+TokenSize <= end {
				validate(start)
			} else {
				kept = append(kept, start)
			}
		}
		pending = kept
		res.BytesScanned = end
		// Keep the last keepTail bytes for the next chunk.
		total := tail + n
		t := min(keepTail, total)
		copy(win, win[total-t:total])
		winStart, tail = end-int64(t), t
	}
	for _, start := range pending { // token cut off by the end of the device
		res.Partial++
		note(start)
	}
	return res, nil
}
