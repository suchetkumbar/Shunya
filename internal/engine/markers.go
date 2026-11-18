package engine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"shunya/internal/backend"
)

// MarkerResult is the after-erase check of the planted markers.
type MarkerResult struct {
	Checked   int   `json:"checked"`
	Surviving int   `json:"surviving"`
	First     int64 `json:"first_surviving"` // byte offset, -1 if none
}

// markerSet fills a sector with its marker: HMAC-SHA256(key, "shunya-marker-v1" ‖ LBA)
// repeated. Unique per sector and run, unforgeable without the key.
type markerSet struct{ key []byte }

func (s markerSet) FillSector(buf []byte, lba uint64) {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte("shunya-marker-v1"))
	m.Write(binary.BigEndian.AppendUint64(nil, lba))
	sum := m.Sum(nil)
	for i := 0; i < len(buf); i += len(sum) {
		copy(buf[i:], sum)
	}
}

func (m *MarkerPlan) set() (markerSet, []byte, error) {
	seed, err := hex.DecodeString(m.Seed)
	if err != nil {
		return markerSet{}, nil, err
	}
	key, err := hex.DecodeString(m.Key)
	return markerSet{key}, seed, err
}

// PlantMarkers writes the plan's markers into t (before the firmware erase) and syncs.
func PlantMarkers(ctx context.Context, t backend.Target, m *MarkerPlan, fingerprint string) error {
	set, seed, err := m.set()
	if err != nil {
		return err
	}
	ss := t.SectorSize()
	buf := backend.AlignedBuffer(ss, max(4096, ss))
	for _, s := range SamplePositions(seed, fingerprint, t.Size()/int64(ss), m.Count) {
		if err := ctx.Err(); err != nil {
			return err
		}
		set.FillSector(buf, uint64(s))
		if _, err := t.WriteAt(buf, s*int64(ss)); err != nil {
			return fmt.Errorf("marker at sector %d: %w", s, err)
		}
	}
	return t.Sync()
}

// CheckMarkers reads every marker sector back: a sector still holding its marker was
// not changed by the erase.
func CheckMarkers(ctx context.Context, t backend.Target, m *MarkerPlan, fingerprint string) (MarkerResult, error) {
	r := MarkerResult{First: -1}
	set, seed, err := m.set()
	if err != nil {
		return r, err
	}
	ss := t.SectorSize()
	buf := backend.AlignedBuffer(ss, max(4096, ss))
	want := make([]byte, ss)
	for _, s := range SamplePositions(seed, fingerprint, t.Size()/int64(ss), m.Count) {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if _, err := t.ReadAt(buf, s*int64(ss)); err != nil {
			return r, fmt.Errorf("marker at sector %d: %w", s, err)
		}
		set.FillSector(want, uint64(s))
		r.Checked++
		if bytes.Equal(buf, want) {
			if r.Surviving == 0 {
				r.First = s * int64(ss)
			}
			r.Surviving++
		}
	}
	return r, nil
}
