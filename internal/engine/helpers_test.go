package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"shunya/internal/backend"
)

// image creates a regular file of size bytes filled with 0xAA ("old data") and opens it
// with the FileBackend.
func image(t testing.TB, dir string, size int64, sector int) *backend.File {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	p := filepath.Join(dir, fmt.Sprintf("img-%d-%d.img", size, sector))
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	old := bytes.Repeat([]byte{0xaa}, 1<<20)
	for left := size; left > 0; {
		n := min(left, int64(len(old)))
		if _, err := f.Write(old[:n]); err != nil {
			t.Fatal(err)
		}
		left -= n
	}
	f.Close()
	t.Cleanup(func() { os.Remove(p) })
	b, err := backend.OpenFile(p, backend.FileOptions{Options: backend.Options{Execute: true}, SectorSize: sector})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func planFor(t testing.TB, tg backend.Target, chunk int, syncEvery int64, patterns ...string) Plan {
	t.Helper()
	p, err := NewPlan(PlanInput{Target: tg.Identity(), Media: MediaImage, SizeBytes: tg.Size(),
		SectorSize: tg.SectorSize(), Patterns: patterns, ChunkBytes: chunk, SyncEvery: syncEvery})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.GenerateKeys(nil); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustPattern(t testing.TB, ps Pass) Pattern {
	t.Helper()
	p, err := ps.pattern()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// checkRange asserts [from, to) of tg holds pat (or, if pat is nil, the old 0xAA data).
func checkRange(t testing.TB, tg backend.Target, pat Pattern, from, to int64) {
	t.Helper()
	const step = 1 << 20
	got := make([]byte, step)
	want := make([]byte, step)
	for off := from; off < to; off += step {
		n := min(step, to-off)
		if _, err := tg.ReadAt(got[:n], off); err != nil {
			t.Fatal(err)
		}
		if pat == nil {
			for i := range want[:n] {
				want[i] = 0xaa
			}
		} else {
			pat.Fill(want[:n], off)
		}
		if !bytes.Equal(got[:n], want[:n]) {
			i := 0
			for got[i] == want[i] {
				i++
			}
			t.Fatalf("byte %d: got %#x want %#x (pattern %v)", off+int64(i), got[i], want[i], pat)
		}
	}
}

// memRecorder records calls in memory.
type memRecorder struct {
	mu     sync.Mutex
	events []string
	cps    []posData
	stops  []stopData
	failAt int // fail the Nth call (1-based) if > 0
	calls  int
}

func (m *memRecorder) add(ev string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.failAt > 0 && m.calls == m.failAt {
		return errors.New("journal disk full")
	}
	m.events = append(m.events, ev)
	return nil
}
func (m *memRecorder) Checkpoint(pass int, off int64) error {
	if err := m.add(RecCheckpoint); err != nil {
		return err
	}
	m.cps = append(m.cps, posData{pass, off})
	return nil
}
func (m *memRecorder) PassDone(int) error { return m.add(RecPassDone) }
func (m *memRecorder) Interrupted(pass int, off int64, why string) error {
	m.stops = append(m.stops, stopData{pass, off, why})
	return m.add(RecInterrupted)
}
func (m *memRecorder) Failed(pass int, off int64, err error) error {
	m.stops = append(m.stops, stopData{pass, off, err.Error()})
	return m.add(RecError)
}
func (m *memRecorder) Done(int64) error { return m.add(RecDone) }

// hookTarget wraps a Target to inject faults or cancel after some writes.
type hookTarget struct {
	backend.Target
	mu          sync.Mutex
	writes      int
	onWrite     func(n int, off int64) error // called before each write; error fails it
	syncErrFrom int                          // fail Sync calls from this one on (1-based), if > 0
	syncs       int
}

func (h *hookTarget) WriteAt(p []byte, off int64) (int, error) {
	h.mu.Lock()
	h.writes++
	n := h.writes
	h.mu.Unlock()
	if h.onWrite != nil {
		if err := h.onWrite(n, off); err != nil {
			return 0, err
		}
	}
	return h.Target.WriteAt(p, off)
}

func (h *hookTarget) Sync() error {
	h.mu.Lock()
	h.syncs++
	n := h.syncs
	h.mu.Unlock()
	if h.syncErrFrom > 0 && n >= h.syncErrFrom {
		return errors.New("injected sync failure")
	}
	return h.Target.Sync()
}

func run(t testing.TB, ctx context.Context, tg backend.Target, p Plan, rec Recorder, opts RunOptions) (Result, error) {
	t.Helper()
	if ctx == nil {
		ctx = context.Background()
	}
	return Run(ctx, tg, p, rec, opts)
}
