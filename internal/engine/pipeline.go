package engine

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"shunya/internal/backend"
)

// Recorder receives the wipe's durable progress. Every call happens after the data it
// describes has been synced to the target; a Recorder error stops the wipe (progress
// that can't be recorded can't be resumed or certified).
type Recorder interface {
	// Checkpoint: bytes [0, offset) of pass are on the medium.
	Checkpoint(pass int, offset int64) error
	PassDone(pass int) error
	// Interrupted: cancelled cleanly; [0, offset) of pass is synced.
	Interrupted(pass int, offset int64, reason string) error
	// Failed: an I/O error stopped the wipe; [0, offset) of pass is known synced.
	Failed(pass int, offset int64, err error) error
	Done(bytesWritten int64) error
}

// Progress is a point-in-time report for the UI.
type Progress struct {
	Pass        int           `json:"pass"` // 0-based
	Passes      int           `json:"passes"`
	Pattern     string        `json:"pattern"`
	PassDone    int64         `json:"pass_done"`
	PassTotal   int64         `json:"pass_total"`
	Done        int64         `json:"done"` // across all passes
	Total       int64         `json:"total"`
	BytesPerSec float64       `json:"bytes_per_sec"` // average over this run
	ETA         time.Duration `json:"eta"`
}

// RunOptions tunes a run. The zero value starts a fresh wipe with default concurrency.
type RunOptions struct {
	StartPass   int   // resume: pass to continue
	StartOffset int64 // resume: synced offset within StartPass
	// Generators is the number of pattern goroutines (default min(2, GOMAXPROCS));
	// Buffers the buffers each owns (default 2). Memory = Generators×Buffers×chunk.
	Generators, Buffers int
	// Progress, if set, receives reports without ever blocking the writer (a report is
	// dropped if the channel is full). Run closes it when it returns.
	Progress chan<- Progress
	now      func() time.Time
}

// Result is the outcome of Run.
type Result struct {
	Completed    bool
	Pass         int   // pass reached
	Offset       int64 // synced offset within Pass
	BytesWritten int64 // bytes written by this run
	Elapsed      time.Duration
	Last         Progress
}

// ErrInterrupted is returned (wrapping the context's cause) when Run was cancelled.
var ErrInterrupted = errors.New("wipe interrupted")

// Run executes plan on t, from opts.StartPass/StartOffset, recording durable progress
// in rec.
//
// Pipeline per pass: G generator goroutines fill chunks (generator g takes chunks
// g, g+G, …) into buffers from its own free list and hand them over in order on its
// own channel; the single writer takes chunk i from generator i mod G, writes it, gives
// the buffer back and calls Sync every plan.SyncEveryBytes and at the end of the pass,
// recording a checkpoint after each Sync. Per-generator free lists mean no generator can
// starve another of buffers (which with a shared pool could deadlock the in-order writer).
//
// On cancellation the writer stops before the next write, syncs, records the synced
// offset and returns ErrInterrupted: everything before that offset has the pass's
// pattern, everything after has the previous pass's (or the original data). No
// goroutine outlives Run.
func Run(ctx context.Context, t backend.Target, plan Plan, rec Recorder, opts RunOptions) (res Result, err error) {
	if opts.Progress != nil {
		defer close(opts.Progress)
	}
	if err := plan.Validate(); err != nil {
		return res, err
	}
	if err := checkTarget(t, plan); err != nil {
		return res, err
	}
	patterns := make([]Pattern, len(plan.Passes))
	for i, ps := range plan.Passes {
		if patterns[i], err = ps.pattern(); err != nil {
			return res, err
		}
	}
	if opts.StartPass < 0 || opts.StartPass > len(plan.Passes) || opts.StartOffset < 0 || opts.StartOffset > plan.SizeBytes ||
		opts.StartOffset%int64(plan.SectorSize) != 0 || (opts.StartPass == len(plan.Passes) && opts.StartOffset != 0) {
		return res, fmt.Errorf("bad resume position pass %d offset %d", opts.StartPass, opts.StartOffset)
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	g := opts.Generators
	if g <= 0 {
		g = min(2, runtime.GOMAXPROCS(0))
	}
	nb := opts.Buffers
	if nb <= 0 {
		nb = 2
	}
	align := max(chunkAlign, t.PhysicalSectorSize(), t.SectorSize())
	free := make([]chan []byte, g)
	for i := range free {
		free[i] = make(chan []byte, nb)
		for range nb {
			free[i] <- backend.AlignedBuffer(plan.ChunkBytes, align)
		}
	}

	r := &runner{t: t, plan: plan, rec: rec, opts: opts, free: free, start: opts.now()}
	r.total = plan.SizeBytes * int64(len(plan.Passes))
	r.doneBefore = int64(opts.StartPass)*plan.SizeBytes + opts.StartOffset
	res.Pass, res.Offset = opts.StartPass, opts.StartOffset
	defer func() {
		res.BytesWritten = r.written
		res.Elapsed = opts.now().Sub(r.start)
		res.Last = r.last
	}()

	for pass := opts.StartPass; pass < len(plan.Passes); pass++ {
		from := int64(0)
		if pass == opts.StartPass {
			from = opts.StartOffset
		}
		synced, err := r.pass(ctx, pass, patterns[pass], from)
		res.Pass, res.Offset = pass, synced
		if err != nil {
			return res, err
		}
		if err := rec.PassDone(pass); err != nil {
			return res, fmt.Errorf("journal: %w", err)
		}
		res.Pass, res.Offset = pass+1, 0
	}
	if err := rec.Done(r.written); err != nil {
		return res, fmt.Errorf("journal: %w", err)
	}
	res.Completed = true
	return res, nil
}

// checkTarget: the target must be the device the plan was made for.
func checkTarget(t backend.Target, p Plan) error {
	id := t.Identity()
	switch {
	case id.Fingerprint != p.Target.Fingerprint:
		return fmt.Errorf("%w: fingerprint %s, plan is for %s", backend.ErrIdentityChanged, id.Fingerprint, p.Target.Fingerprint)
	case t.Size() != p.SizeBytes:
		return fmt.Errorf("%w: size %d, plan is for %d", backend.ErrIdentityChanged, t.Size(), p.SizeBytes)
	case t.SectorSize() != p.SectorSize:
		return fmt.Errorf("%w: sector size %d, plan is for %d", backend.ErrIdentityChanged, t.SectorSize(), p.SectorSize)
	}
	return nil
}

type runner struct {
	t          backend.Target
	plan       Plan
	rec        Recorder
	opts       RunOptions
	free       []chan []byte
	start      time.Time
	total      int64 // bytes across all passes
	doneBefore int64 // bytes already done when this run started
	written    int64 // bytes written by this run
	last       Progress
}

// Rechecker is implemented by targets that can confirm, mid-wipe, that they are still
// the selected drive (backend.Block re-enumerates sysfs). Run calls it before each pass
// and after every checkpoint; a failure stops the wipe and is journalled.
type Rechecker interface {
	Recheck() error
}

func recheck(t backend.Target) error {
	if rc, ok := t.(Rechecker); ok {
		if err := rc.Recheck(); err != nil {
			return fmt.Errorf("identity re-check: %w", err)
		}
	}
	return nil
}

type chunk struct {
	off int64
	buf []byte
}

// pass writes [from, size) of one pass and returns the synced offset.
func (r *runner) pass(ctx context.Context, pass int, pat Pattern, from int64) (synced int64, err error) {
	size, cs := r.plan.SizeBytes, int64(r.plan.ChunkBytes)
	n := int((size - from + cs - 1) / cs)
	g := len(r.free)

	// Generators are stopped by the writer (stop), never by ctx directly: the writer
	// alone decides where the pass ends, so the synced offset is exact.
	genCtx, stop := context.WithCancel(context.Background())
	out := make([]chan chunk, g)
	var wg sync.WaitGroup
	for k := range g {
		out[k] = make(chan chunk, cap(r.free[k]))
		wg.Go(func() {
			for i := k; i < n; i += g {
				var buf []byte
				select {
				case buf = <-r.free[k]:
				case <-genCtx.Done():
					return
				}
				off := from + int64(i)*cs
				b := buf[:min(cs, size-off)]
				pat.Fill(b, off)
				select {
				case out[k] <- chunk{off, b}:
				case <-genCtx.Done():
					r.free[k] <- buf
					return
				}
			}
		})
	}
	defer func() {
		stop()
		wg.Wait()
		for k := range out { // return undelivered buffers for the next pass
			for len(out[k]) > 0 {
				c := <-out[k]
				r.free[k] <- c.buf[:cap(c.buf)]
			}
		}
	}()

	written, synced := from, from
	var sinceSync int64
	doSync := func() error {
		if err := r.t.Sync(); err != nil {
			return err
		}
		synced, sinceSync = written, 0
		return nil
	}
	fail := func(ioErr error) (int64, error) {
		if jerr := r.rec.Failed(pass, synced, ioErr); jerr != nil {
			return synced, errors.Join(ioErr, fmt.Errorf("journal: %w", jerr))
		}
		return synced, ioErr
	}
	interrupt := func() (int64, error) {
		if err := doSync(); err != nil {
			return fail(fmt.Errorf("sync after cancel: %w", err))
		}
		cause := context.Cause(ctx)
		if err := r.rec.Interrupted(pass, synced, cause.Error()); err != nil {
			return synced, fmt.Errorf("journal: %w", err)
		}
		return synced, fmt.Errorf("%w at pass %d offset %d: %w", ErrInterrupted, pass+1, synced, cause)
	}

	// Before each pass (and each resume): still the same drive?
	if err := recheck(r.t); err != nil {
		return fail(err)
	}

	for i := range n {
		if ctx.Err() != nil {
			return interrupt()
		}
		var c chunk
		select {
		case c = <-out[i%g]:
		case <-ctx.Done():
			return interrupt()
		}
		w := c.buf
		if brokenTailPercent > 0 { // constant false outside the brokenwipe test build
			if from := brokenSkipFrom(size, r.plan.SectorSize); c.off+int64(len(w)) > from {
				w = w[:max(0, from-c.off)]
			}
		}
		var err error
		if len(w) > 0 {
			_, err = r.t.WriteAt(w, c.off)
		}
		r.free[i%g] <- c.buf[:cap(c.buf)]
		if err != nil {
			return fail(fmt.Errorf("write at %d: %w", c.off, err))
		}
		written += int64(len(c.buf))
		sinceSync += int64(len(c.buf))
		r.written += int64(len(c.buf))
		if sinceSync >= r.plan.SyncEveryBytes || written == size {
			if err := doSync(); err != nil {
				return fail(fmt.Errorf("sync at %d: %w", written, err))
			}
			if err := r.rec.Checkpoint(pass, synced); err != nil {
				return synced, fmt.Errorf("journal: %w", err)
			}
			if err := recheck(r.t); err != nil {
				return fail(err)
			}
		}
		r.report(pass, pat.Name(), written)
	}
	return synced, nil
}

func (r *runner) report(pass int, pattern string, passDone int64) {
	elapsed := r.opts.now().Sub(r.start).Seconds()
	p := Progress{
		Pass: pass, Passes: len(r.plan.Passes), Pattern: pattern,
		PassDone: passDone, PassTotal: r.plan.SizeBytes,
		Done: int64(pass)*r.plan.SizeBytes + passDone, Total: r.total,
	}
	if elapsed > 0 {
		p.BytesPerSec = float64(r.written) / elapsed
		if p.BytesPerSec > 0 {
			p.ETA = time.Duration(float64(p.Total-p.Done) / p.BytesPerSec * float64(time.Second))
		}
	}
	r.last = p
	if r.opts.Progress != nil {
		select {
		case r.opts.Progress <- p:
		default:
		}
	}
}

// brokenSkipFrom is where the brokenwipe test build stops writing: the last
// brokenTailPercent of the target, rounded down to whole sectors.
func brokenSkipFrom(size int64, sector int) int64 {
	return size - size*brokenTailPercent/100/int64(sector)*int64(sector)
}
