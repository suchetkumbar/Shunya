// Package sanitize runs a firmware sanitize operation (NVMe Sanitize, ATA SANITIZE
// DEVICE) to completion: start it, poll the drive's status until it finishes, journal
// progress, and resume correctly after a crash or power loss. The drive-specific parts
// are behind Operation; internal/nvme and internal/ata implement it.
//
// A sanitize runs inside the drive. Once started it continues without the host and
// survives power loss (the drive resumes it at power-on), and the drive refuses normal
// I/O until it completes. A failed sanitize leaves the drive in a failure state that
// only another successful sanitize clears.
package sanitize

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Phase of the drive's most recent sanitize.
type Phase string

const (
	Idle       Phase = "idle"        // never sanitized (or no status)
	InProgress Phase = "in-progress" //
	Completed  Phase = "completed"   // most recent sanitize completed successfully
	Failed     Phase = "failed"      // most recent sanitize failed: drive in failure mode
)

// Status is what the drive reports.
type Status struct {
	Phase    Phase   `json:"phase"`
	Progress float64 `json:"progress"` // 0..1 while in progress
	// Attested: the drive states that no user data has been written since its most
	// recent successful sanitize, and that sanitize used the requested action (NVMe:
	// Global Data Erased + SCDW10). Only then may a resume skip re-running it.
	Attested bool   `json:"attested"`
	Detail   string `json:"detail,omitempty"`
}

// Operation is one drive's sanitize.
type Operation interface {
	Name() string
	Status(ctx context.Context) (Status, error)
	Start(ctx context.Context) error
}

// Journal events.
const (
	EvStarted   = "sanitize-started"   // journaled before the start command is sent
	EvProgress  = "sanitize-progress"  // periodic
	EvWaiting   = "sanitize-waiting"   // resume: the drive is still sanitizing
	EvAttested  = "sanitize-attested"  // resume: already complete, attested by the drive
	EvCompleted = "sanitize-completed" //
	EvFailed    = "sanitize-failed"    //
)

// Event is one journaled step.
type Event struct {
	Event    string  `json:"event"`
	Action   string  `json:"action,omitempty"`
	Progress float64 `json:"progress,omitempty"`
	Seconds  float64 `json:"seconds,omitempty"`
	Note     string  `json:"note,omitempty"`
}

// Options configures Run.
type Options struct {
	// Resume: the journal shows this sanitize was started (EvStarted) by an earlier run.
	Resume bool
	Record func(Event) error
	// Poll is the status interval (default 5 s); progress is journaled at most every
	// 10 % or ProgressEvery (default 5 min).
	Poll, ProgressEvery time.Duration
	// MaxWait bounds the whole wait (default 48 h).
	MaxWait    time.Duration
	OnProgress func(Status)
	Sleep      func(context.Context, time.Duration) error
	Now        func() time.Time
}

// Errors.
var (
	ErrFailed     = errors.New("the drive reports the sanitize FAILED; it stays in sanitize failure mode until a sanitize succeeds")
	ErrForeign    = errors.New("a sanitize this journal did not start is in progress; wait for it to finish, then run Shunya again")
	ErrNotStarted = errors.New("the drive accepted the sanitize command but its status never showed it running or complete")
	ErrTimeout    = errors.New("the sanitize did not finish within the time limit; it continues inside the drive, resume to keep waiting")
)

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run starts (or, on resume, waits for) the sanitize and returns the final status.
//
// Resume rules: if the drive is still sanitizing, wait for it. If it is done and the
// drive attests (Status.Attested) that nothing was written since a successful
// sanitize of this kind, record that and stop. Otherwise start again: a "completed"
// status alone may belong to an earlier sanitize.
func Run(ctx context.Context, op Operation, o Options) (Status, error) {
	if o.Poll == 0 {
		o.Poll = 5 * time.Second
	}
	if o.ProgressEvery == 0 {
		o.ProgressEvery = 5 * time.Minute
	}
	if o.MaxWait == 0 {
		o.MaxWait = 48 * time.Hour
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	rec := func(e Event) error {
		e.Action = op.Name()
		if err := o.Record(e); err != nil {
			return fmt.Errorf("journal: %w", err)
		}
		return nil
	}
	st, err := op.Status(ctx)
	if err != nil {
		return st, err
	}
	start := o.Now()
	switch {
	case st.Phase == InProgress && !o.Resume:
		return st, ErrForeign
	case st.Phase == InProgress:
		if err := rec(Event{Event: EvWaiting, Progress: st.Progress}); err != nil {
			return st, err
		}
	case o.Resume && st.Phase == Completed && st.Attested:
		return st, rec(Event{Event: EvAttested, Note: "the drive reports a completed sanitize of this kind and no user data written since"})
	default:
		note := ""
		if st.Phase == Failed {
			note = "the drive was in sanitize failure mode; a successful sanitize clears it"
		}
		if err := rec(Event{Event: EvStarted, Note: note}); err != nil {
			return st, err
		}
		if err := op.Start(ctx); err != nil {
			return st, err
		}
	}
	lastRec, lastProg := o.Now(), st.Progress
	idlePolls := 0
	for {
		if o.Now().Sub(start) > o.MaxWait {
			return st, ErrTimeout
		}
		if st, err = op.Status(ctx); err != nil {
			return st, err
		}
		if o.OnProgress != nil {
			o.OnProgress(st)
		}
		switch st.Phase {
		case Completed:
			return st, rec(Event{Event: EvCompleted, Seconds: o.Now().Sub(start).Seconds(), Note: st.Detail})
		case Failed:
			if err := rec(Event{Event: EvFailed, Note: st.Detail}); err != nil {
				return st, err
			}
			return st, ErrFailed
		case Idle:
			if idlePolls++; idlePolls > 3 {
				return st, ErrNotStarted
			}
		case InProgress:
			if st.Progress-lastProg >= 0.1 || o.Now().Sub(lastRec) >= o.ProgressEvery {
				if err := rec(Event{Event: EvProgress, Progress: st.Progress}); err != nil {
					return st, err
				}
				lastRec, lastProg = o.Now(), st.Progress
			}
		}
		if err := o.Sleep(ctx, o.Poll); err != nil {
			return st, err
		}
	}
}
