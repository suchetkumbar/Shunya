package engine

import (
	"bytes"
	"context"
	"fmt"

	"shunya/internal/backend"
)

// VerifyResult is the outcome of a full read-back.
type VerifyResult struct {
	BytesRead  int64 `json:"bytes_read"`
	BadSectors int64 `json:"bad_sectors"`
	FirstBad   int64 `json:"first_bad"` // byte offset of the first mismatching sector, -1 if none
}

// OK reports whether every sector matched.
func (v VerifyResult) OK() bool { return v.BadSectors == 0 && v.FirstBad < 0 }

// Verify reads the whole target back and compares it with pat, sector by sector.
// (Milestone 4 adds sampled verification with an externally supplied seed.)
func Verify(ctx context.Context, t backend.Target, pat Pattern, chunkBytes int) (VerifyResult, error) {
	res := VerifyResult{FirstBad: -1}
	sector := t.SectorSize()
	if chunkBytes <= 0 || chunkBytes%sector != 0 {
		return res, fmt.Errorf("verify: chunk %d not a multiple of sector %d", chunkBytes, sector)
	}
	align := max(chunkAlign, t.PhysicalSectorSize(), sector)
	got := backend.AlignedBuffer(chunkBytes, align)
	want := make([]byte, chunkBytes)
	size := t.Size()
	for off := int64(0); off < size; off += int64(chunkBytes) {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		n := int(min(int64(chunkBytes), size-off))
		if _, err := t.ReadAt(got[:n], off); err != nil {
			return res, fmt.Errorf("verify: read at %d: %w", off, err)
		}
		pat.Fill(want[:n], off)
		res.BytesRead += int64(n)
		if bytes.Equal(got[:n], want[:n]) {
			continue
		}
		for s := 0; s < n; s += sector {
			if !bytes.Equal(got[s:s+sector], want[s:s+sector]) {
				res.BadSectors++
				if res.FirstBad < 0 {
					res.FirstBad = off + int64(s)
				}
			}
		}
	}
	return res, nil
}
