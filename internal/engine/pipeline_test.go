package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"testing"
	"time"

	"shunya/internal/backend"
	"shunya/internal/testutil/leakcheck"
)

const kib = 1024

func TestWipeSizes(t *testing.T) {
	const chunk = 64 * kib
	for _, sector := range []int{512, 4096} {
		s := int64(sector)
		for _, size := range []int64{
			s,                // one sector
			chunk - s,        // just under one chunk
			chunk,            // exactly one chunk
			chunk + s,        // one sector into the second chunk
			3*chunk + 7*s,    // odd multi-chunk size
			13*chunk + 255*s, // larger, not a chunk multiple
		} {
			for _, gens := range []int{1, 3} {
				t.Run(fmt.Sprintf("sector%d/size%d/gen%d", sector, size, gens), func(t *testing.T) {
					leakcheck.Check(t)
					tg := image(t, "", size, sector)
					p := planFor(t, tg, chunk, 2*chunk, PatternRandom)
					rec := &memRecorder{}
					res, err := run(t, nil, tg, p, rec, RunOptions{Generators: gens})
					if err != nil {
						t.Fatal(err)
					}
					if !res.Completed || res.BytesWritten != size {
						t.Fatalf("result %+v", res)
					}
					checkRange(t, tg, mustPattern(t, p.Passes[0]), 0, size)
					if last := rec.cps[len(rec.cps)-1]; last.Offset != size {
						t.Fatalf("last checkpoint %d, size %d", last.Offset, size)
					}
					if !slices.IsSortedFunc(rec.cps, func(a, b posData) int { return int(a.Offset - b.Offset) }) {
						t.Fatalf("checkpoints not monotonic: %v", rec.cps)
					}
					if tail := rec.events[len(rec.events)-2:]; !slices.Equal(tail, []string{RecPassDone, RecDone}) {
						t.Fatalf("events end %v", tail)
					}
				})
			}
		}
	}
}

func TestMultiPassEndsWithLastPattern(t *testing.T) {
	leakcheck.Check(t)
	tg := image(t, "", 5*64*kib+512, 512)
	p := planFor(t, tg, 64*kib, 64*kib, PatternZero, PatternOne, PatternRandom)
	rec := &memRecorder{}
	if _, err := run(t, nil, tg, p, rec, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	checkRange(t, tg, mustPattern(t, p.Passes[2]), 0, tg.Size())
	n := 0
	for _, e := range rec.events {
		if e == RecPassDone {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("%d pass-done records, want 3", n)
	}
}

// Cancel at random points, then resume from the recorded offset: the pattern before the
// synced offset is already correct, and after resuming the whole target is.
func TestCancelThenResume(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	const chunk = 64 * kib
	size := int64(37*chunk + 3*512)
	for trial := range 12 {
		t.Run(fmt.Sprint(trial), func(t *testing.T) {
			leakcheck.Check(t)
			file := image(t, "", size, 512)
			p := planFor(t, file, chunk, int64(1+r.IntN(4))*chunk, PatternZero, PatternRandom)
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			stopAfter := 1 + r.IntN(70) // writes, across both passes
			tg := &hookTarget{Target: file, onWrite: func(n int, _ int64) error {
				if n == stopAfter {
					cancel(errors.New("operator pressed Ctrl-C"))
				}
				return nil
			}}
			rec := &memRecorder{}
			res, err := run(t, ctx, tg, p, rec, RunOptions{Generators: 2})
			if !errors.Is(err, ErrInterrupted) {
				t.Fatalf("err = %v, want ErrInterrupted", err)
			}
			if len(rec.stops) != 1 || rec.stops[0].Offset != res.Offset || rec.stops[0].Pass != res.Pass {
				t.Fatalf("stop records %+v, result %+v", rec.stops, res)
			}
			if rec.stops[0].Reason != "operator pressed Ctrl-C" {
				t.Fatalf("reason %q", rec.stops[0].Reason)
			}
			// Well-defined state: [0, offset) has this pass's pattern; after it, the
			// previous pass's (or the old data).
			checkRange(t, file, mustPattern(t, p.Passes[res.Pass]), 0, res.Offset)
			var before Pattern
			if res.Pass > 0 {
				before = mustPattern(t, p.Passes[res.Pass-1])
			}
			// interrupt() syncs before recording, so the recorded offset is exact.
			checkRange(t, file, before, res.Offset, size)

			rec2 := &memRecorder{}
			res2, err := run(t, nil, file, p, rec2, RunOptions{StartPass: res.Pass, StartOffset: res.Offset})
			if err != nil || !res2.Completed {
				t.Fatalf("resume: %v %+v", err, res2)
			}
			checkRange(t, file, mustPattern(t, p.Passes[1]), 0, size)
		})
	}
}

func TestCancelledBeforeStart(t *testing.T) {
	leakcheck.Check(t)
	tg := image(t, "", 8*64*kib, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := &memRecorder{}
	res, err := run(t, ctx, tg, p, rec, RunOptions{})
	if !errors.Is(err, ErrInterrupted) || !errors.Is(err, context.Canceled) || res.Offset != 0 || res.BytesWritten != 0 {
		t.Fatalf("err %v res %+v", err, res)
	}
	checkRange(t, tg, nil, 0, tg.Size())
}

func TestWriteFailureRecorded(t *testing.T) {
	leakcheck.Check(t)
	file := image(t, "", 20*64*kib, 512)
	p := planFor(t, file, 64*kib, 4*64*kib)
	tg := &hookTarget{Target: file, onWrite: func(n int, off int64) error {
		if n == 10 {
			return fmt.Errorf("EIO at %d", off)
		}
		return nil
	}}
	rec := &memRecorder{}
	res, err := run(t, nil, tg, p, rec, RunOptions{Generators: 3, Buffers: 3})
	if err == nil || res.Completed {
		t.Fatal("write error not reported")
	}
	if len(rec.stops) != 1 || rec.events[len(rec.events)-1] != RecError {
		t.Fatalf("events %v", rec.events)
	}
	if got := rec.stops[0].Offset; got != 8*64*kib {
		t.Fatalf("failure recorded at synced offset %d, want %d", got, 8*64*kib)
	}
}

func TestSyncFailureRecorded(t *testing.T) {
	leakcheck.Check(t)
	file := image(t, "", 20*64*kib, 512)
	p := planFor(t, file, 64*kib, 4*64*kib)
	tg := &hookTarget{Target: file, syncErrFrom: 2}
	rec := &memRecorder{}
	_, err := run(t, nil, tg, p, rec, RunOptions{})
	if err == nil {
		t.Fatal("sync error not reported")
	}
	// The second sync failed: only the first one's 256 KiB may be claimed.
	if rec.stops[0].Offset != 4*64*kib || rec.cps[len(rec.cps)-1].Offset != 4*64*kib {
		t.Fatalf("claimed %+v / %+v", rec.stops, rec.cps)
	}
}

func TestJournalFailureStopsWipe(t *testing.T) {
	leakcheck.Check(t)
	tg := image(t, "", 20*64*kib, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	rec := &memRecorder{failAt: 3}
	if _, err := run(t, nil, tg, p, rec, RunOptions{}); err == nil {
		t.Fatal("wipe continued although progress could not be recorded")
	}
	if len(rec.cps) != 2 {
		t.Fatalf("%d checkpoints", len(rec.cps))
	}
}

func TestRefusesOtherTarget(t *testing.T) {
	a := image(t, "", 64*kib, 512)
	b := image(t, t.TempDir(), 64*kib, 512)
	p := planFor(t, a, 64*kib, 64*kib)
	if _, err := run(t, nil, b, p, &memRecorder{}, RunOptions{}); !errors.Is(err, backend.ErrIdentityChanged) {
		t.Fatalf("err = %v", err)
	}
	p.SizeBytes += 512
	if _, err := run(t, nil, a, p, &memRecorder{}, RunOptions{}); !errors.Is(err, backend.ErrIdentityChanged) {
		t.Fatalf("size change: err = %v", err)
	}
}

func TestBadResumePosition(t *testing.T) {
	tg := image(t, "", 64*kib, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	for _, o := range []RunOptions{{StartPass: -1}, {StartPass: 2}, {StartOffset: 100}, {StartOffset: 128 * kib},
		{StartPass: 1, StartOffset: 512}} {
		if _, err := run(t, nil, tg, p, &memRecorder{}, o); err == nil {
			t.Errorf("accepted %+v", o)
		}
	}
}

func TestDryRunTargetFailsCleanly(t *testing.T) {
	leakcheck.Check(t)
	dir := t.TempDir()
	rw := image(t, dir, 4*64*kib, 512)
	ro, err := backend.OpenFile(rw.Identity().Path, backend.FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	p := planFor(t, ro, 64*kib, 64*kib)
	if _, err := run(t, nil, ro, p, &memRecorder{}, RunOptions{}); !errors.Is(err, backend.ErrDryRun) {
		t.Fatalf("err = %v", err)
	}
}

func TestProgress(t *testing.T) {
	leakcheck.Check(t)
	tg := image(t, "", 40*64*kib, 512)
	p := planFor(t, tg, 64*kib, 64*kib, PatternZero, PatternRandom)
	ch := make(chan Progress, 1000)
	clock := time.Unix(0, 0)
	res, err := Run(context.Background(), tg, p, &memRecorder{}, RunOptions{Progress: ch,
		now: func() time.Time { clock = clock.Add(time.Millisecond); return clock }})
	if err != nil {
		t.Fatal(err)
	}
	var got []Progress
	for pr := range ch { // Run closed the channel
		got = append(got, pr)
	}
	if len(got) != 80 {
		t.Fatalf("%d reports, want 80", len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i].Done <= got[i-1].Done {
			t.Fatal("progress not increasing")
		}
	}
	last := got[len(got)-1]
	if last.Done != last.Total || last.ETA != 0 || last.BytesPerSec <= 0 || res.Last != last {
		t.Fatalf("last %+v res %+v", last, res.Last)
	}
	if got[40].Pass != 1 || got[40].Pattern != PatternRandom {
		t.Fatalf("pass 2 report %+v", got[40])
	}
}

// A slow consumer must never stall the writer: reports are dropped, not queued.
func TestProgressNeverBlocks(t *testing.T) {
	leakcheck.Check(t)
	tg := image(t, "", 40*64*kib, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	ch := make(chan Progress) // unbuffered and never read until the end
	done := make(chan error)
	go func() {
		_, err := Run(context.Background(), tg, p, &memRecorder{}, RunOptions{Progress: ch})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writer blocked on the progress channel")
	}
	if _, ok := <-ch; ok {
		t.Fatal("channel not closed")
	}
}

// TestBigOddImage is the Milestone 3 acceptance check: a 1 GiB + 4095-sector image,
// wiped and then verified byte by byte. It needs 1+ GiB of disk, so it runs only
// under `make test-big` (which sets SHUNYA_BIG_DIR to the repo's tmp/).
func TestBigOddImage(t *testing.T) {
	dir := os.Getenv("SHUNYA_BIG_DIR")
	if dir == "" {
		t.Skip("SKIPPED: 1 GiB test; run `make test-big`")
	}
	leakcheck.Check(t)
	size := int64(1<<30 + 4095*512)
	tg := image(t, dir, size, 512)
	p := planFor(t, tg, DefaultChunk, DefaultSyncEvery)
	start := time.Now()
	res, err := run(t, nil, tg, p, &memRecorder{}, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wiped %d bytes in %v (%.0f MB/s)", res.BytesWritten, res.Elapsed, float64(size)/time.Since(start).Seconds()/1e6)
	v, err := Verify(context.Background(), tg, mustPattern(t, p.Passes[0]), DefaultChunk)
	if err != nil || !v.OK() || v.BytesRead != size {
		t.Fatalf("verify %+v %v", v, err)
	}
	t.Logf("verified %d bytes: every byte matches the AES-CTR pattern", v.BytesRead)
}

func BenchmarkWipeFile(b *testing.B) {
	dir := os.Getenv("SHUNYA_BIG_DIR")
	if dir == "" {
		dir = b.TempDir()
	}
	const size = 256 << 20
	tg := image(b, dir, size, 512)
	for _, pat := range []string{PatternZero, PatternRandom} {
		for _, chunk := range []int{1 << 20, 4 << 20, 16 << 20} {
			b.Run(fmt.Sprintf("%s/chunk=%dMiB", pat, chunk>>20), func(b *testing.B) {
				p := planFor(b, tg, chunk, DefaultSyncEvery, pat)
				b.SetBytes(size)
				for b.Loop() {
					if _, err := Run(context.Background(), tg, p, &memRecorder{}, RunOptions{}); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// recheckTarget fails its Nth Recheck, as backend.Block does after a drive swap.
type recheckTarget struct {
	backend.Target
	calls, failAt int
}

func (r *recheckTarget) Recheck() error {
	r.calls++
	if r.calls >= r.failAt {
		return backend.ErrIdentityChanged
	}
	return nil
}

func TestRecheckBeforePassAndAtCheckpoints(t *testing.T) {
	leakcheck.Check(t)
	file := image(t, "", 16*64*kib, 512)
	p := planFor(t, file, 64*kib, 4*64*kib, PatternZero, PatternRandom)
	ok := &recheckTarget{Target: file, failAt: 1 << 30}
	if _, err := run(t, nil, ok, p, &memRecorder{}, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	// 2 passes × (1 before the pass + 4 checkpoints).
	if ok.calls != 10 {
		t.Fatalf("%d rechecks, want 10", ok.calls)
	}
	for _, failAt := range []int{1, 3, 6} {
		tg := &recheckTarget{Target: file, failAt: failAt}
		rec := &memRecorder{}
		res, err := run(t, nil, tg, p, rec, RunOptions{})
		if !errors.Is(err, backend.ErrIdentityChanged) || res.Completed {
			t.Fatalf("failAt %d: err %v", failAt, err)
		}
		if rec.events[len(rec.events)-1] != RecError {
			t.Fatalf("failAt %d: identity change not journalled: %v", failAt, rec.events)
		}
	}
}
