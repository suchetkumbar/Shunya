package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"

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

// Seed sources recorded with a sampled verification.
const (
	// SeedOperator: supplied by the caller (--seed). The station could have chosen it
	// to avoid bad sectors, so it proves less; certificates will say so (M7).
	SeedOperator = "operator"
	// SeedTlog: derived from a transparency-log checkpoint fetched after the wipe (M8).
	SeedTlog = "tlog-checkpoint"
)

// SampleResult is the outcome of a sampled verification.
type SampleResult struct {
	VerifyResult
	Samples    int    `json:"samples"`
	SeedSource string `json:"seed_source"`
	Seed       string `json:"seed"` // hex
	// Bound95 is the unwiped fraction this sample size catches with 95 % probability:
	// if a fraction f of sectors still held old data, all n samples would miss it with
	// probability (1−f)^n, which is ≤ 5 % for f ≥ Bound95 = 1 − 0.05^(1/n).
	Bound95 float64 `json:"bound95"`
}

// SamplePositions picks n distinct sector indices in [0, sectors) from seed and the
// device fingerprint (so one seed gives different positions on different drives). The
// first and last sectors are always included; the result is sorted. ChaCha8 (a
// cryptographic generator) is keyed with SHA-256("shunya-sample-v1" ‖ seed ‖ fp), so
// positions can't be predicted without the seed.
func SamplePositions(seed []byte, fingerprint string, sectors int64, n int) []int64 {
	if sectors <= 0 || n <= 0 {
		return nil
	}
	if int64(n) >= sectors {
		all := make([]int64, sectors)
		for i := range all {
			all[i] = int64(i)
		}
		return all
	}
	h := sha256.New()
	h.Write([]byte("shunya-sample-v1\x00"))
	h.Write(seed)
	h.Write([]byte{0})
	h.Write([]byte(fingerprint))
	var key [32]byte
	copy(key[:], h.Sum(nil))
	r := rand.New(rand.NewChaCha8(key))
	pick := map[int64]bool{0: true, sectors - 1: true}
	for len(pick) < n {
		pick[int64(r.Uint64N(uint64(sectors)))] = true
	}
	out := make([]int64, 0, n)
	for s := range pick {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// VerifySampled reads n sectors chosen by SamplePositions and compares each with pat.
func VerifySampled(ctx context.Context, t backend.Target, pat Pattern, seed []byte, seedSource string, n int) (SampleResult, error) {
	res := SampleResult{VerifyResult: VerifyResult{FirstBad: -1}, SeedSource: seedSource, Seed: hex.EncodeToString(seed)}
	if len(seed) < 16 {
		return res, fmt.Errorf("verify: seed must be at least 16 bytes")
	}
	sector := t.SectorSize()
	pos := SamplePositions(seed, t.Identity().Fingerprint, t.Size()/int64(sector), n)
	align := max(chunkAlign, t.PhysicalSectorSize(), sector)
	got := backend.AlignedBuffer(sector, align)
	want := make([]byte, sector)
	for _, s := range pos {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		off := s * int64(sector)
		if _, err := t.ReadAt(got, off); err != nil {
			return res, fmt.Errorf("verify: read sector %d: %w", s, err)
		}
		pat.Fill(want, off)
		res.BytesRead += int64(sector)
		if !bytes.Equal(got, want) {
			res.BadSectors++
			if res.FirstBad < 0 {
				res.FirstBad = off
			}
		}
	}
	res.Samples = len(pos)
	res.Bound95 = 1 - math.Pow(0.05, 1/float64(max(res.Samples, 1)))
	if int64(res.Samples) == t.Size()/int64(sector) {
		res.Bound95 = 0 // every sector was read
	}
	return res, nil
}
