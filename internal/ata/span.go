package ata

import (
	"context"
	"fmt"
	"sync"

	"shunya/internal/backend"
)

// RangeTarget is a backend.Target over the drive sectors [start, end), reached with READ
// DMA EXT / WRITE DMA EXT through pass-through. It is how Shunya writes the sectors an
// HPA hid: after a volatile SET MAX the drive accepts them, but the kernel's block
// device keeps its old size until a rescan, which Shunya does not trigger.
//
// Offsets are relative to start. Only 512-byte logical sectors are supported.
type RangeTarget struct {
	d          Device
	start, end uint64
	id         backend.Identity
	ctx        context.Context
	mu         sync.Mutex
	closed     bool
}

var _ backend.Target = (*RangeTarget)(nil)

// NewRangeTarget returns the target for [start, end). id is the drive's identity (the
// same as the visible block device's).
func NewRangeTarget(ctx context.Context, d Device, start, end uint64, id backend.Identity) (*RangeTarget, error) {
	if end <= start || end-1 > MaxLBA48 {
		return nil, fmt.Errorf("hidden range [%d, %d): empty or beyond 48 bits", start, end)
	}
	return &RangeTarget{d: d, start: start, end: end, id: id, ctx: ctx}, nil
}

func (r *RangeTarget) Size() int64             { return int64(r.end-r.start) * SectorBytes }
func (r *RangeTarget) SectorSize() int         { return SectorBytes }
func (r *RangeTarget) PhysicalSectorSize() int { return SectorBytes }
func (r *RangeTarget) Identity() backend.Identity {
	return r.id
}

func (r *RangeTarget) io(p []byte, off int64, write bool) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, backend.ErrClosed
	}
	n := int64(len(p))
	if off < 0 || off > r.Size() || n > r.Size()-off {
		return 0, fmt.Errorf("%w: [%d,+%d) of the hidden range (%d bytes)", backend.ErrOutOfRange, off, n, r.Size())
	}
	if off%SectorBytes != 0 || n%SectorBytes != 0 {
		return 0, backend.ErrUnaligned
	}
	done := 0
	for done < len(p) {
		secs := min((len(p)-done)/SectorBytes, MaxTransferSectors)
		lba := r.start + uint64(off+int64(done))/SectorBytes
		var c Command
		var err error
		if write {
			c, err = WriteDMAExt(lba, secs)
		} else {
			c, err = ReadDMAExt(lba, secs)
		}
		if err != nil {
			return done, err
		}
		if _, err := r.d.Exec(r.ctx, c, p[done:done+secs*SectorBytes]); err != nil {
			return done, fmt.Errorf("hidden range LBA %d: %w", lba, err)
		}
		done += secs * SectorBytes
	}
	return done, nil
}

func (r *RangeTarget) ReadAt(p []byte, off int64) (int, error)  { return r.io(p, off, false) }
func (r *RangeTarget) WriteAt(p []byte, off int64) (int, error) { return r.io(p, off, true) }

// Sync issues FLUSH CACHE EXT.
func (r *RangeTarget) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return backend.ErrClosed
	}
	_, err := r.d.Exec(r.ctx, FlushCacheExt(), nil)
	return err
}

func (r *RangeTarget) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// Span joins the visible block device and the hidden range after it into one target of
// the drive's native size, so the engine (passes, checkpoints, resume, verification)
// treats the whole drive as one address space.
type Span struct {
	visible backend.Target
	hidden  *RangeTarget
	split   int64
}

var _ backend.Target = (*Span)(nil)

// NewSpan returns visible followed by hidden. The hidden range must start where the
// visible device ends.
func NewSpan(visible backend.Target, hidden *RangeTarget) (*Span, error) {
	if visible.SectorSize() != SectorBytes {
		return nil, fmt.Errorf("hidden-area wipe needs 512-byte logical sectors (device has %d)", visible.SectorSize())
	}
	if uint64(visible.Size())/SectorBytes != hidden.start || visible.Size()%SectorBytes != 0 {
		return nil, fmt.Errorf("hidden range starts at sector %d, visible device ends at %d", hidden.start, visible.Size()/SectorBytes)
	}
	return &Span{visible: visible, hidden: hidden, split: visible.Size()}, nil
}

func (s *Span) Size() int64                { return s.split + s.hidden.Size() }
func (s *Span) SectorSize() int            { return s.visible.SectorSize() }
func (s *Span) PhysicalSectorSize() int    { return s.visible.PhysicalSectorSize() }
func (s *Span) Identity() backend.Identity { return s.visible.Identity() }

// HiddenFrom is the byte offset where the hidden range begins.
func (s *Span) HiddenFrom() int64 { return s.split }

func (s *Span) do(p []byte, off int64, f func(backend.Target, []byte, int64) (int, error)) (int, error) {
	if off < 0 || int64(len(p)) > s.Size()-off {
		return 0, backend.ErrOutOfRange
	}
	done := 0
	if off < s.split {
		n := int(min(int64(len(p)), s.split-off))
		k, err := f(s.visible, p[:n], off)
		done += k
		if err != nil {
			return done, err
		}
	}
	if rest := p[done:]; len(rest) > 0 {
		k, err := f(s.hidden, rest, off+int64(done)-s.split)
		done += k
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

func (s *Span) ReadAt(p []byte, off int64) (int, error) {
	return s.do(p, off, func(t backend.Target, b []byte, o int64) (int, error) { return t.ReadAt(b, o) })
}

func (s *Span) WriteAt(p []byte, off int64) (int, error) {
	return s.do(p, off, func(t backend.Target, b []byte, o int64) (int, error) { return t.WriteAt(b, o) })
}

func (s *Span) Sync() error {
	if err := s.visible.Sync(); err != nil {
		return err
	}
	return s.hidden.Sync()
}

// Recheck forwards the engine's mid-wipe identity re-check to the block device.
func (s *Span) Recheck() error {
	if r, ok := s.visible.(interface{ Recheck() error }); ok {
		return r.Recheck()
	}
	return nil
}

// Close closes the hidden range only; the caller owns the visible device.
func (s *Span) Close() error { return s.hidden.Close() }
