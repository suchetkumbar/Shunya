package sanitize

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// scripted is an Operation whose status follows a script, one entry per Status call.
type scripted struct {
	script  []Status
	i       int
	started int
	startEr error
}

func (s *scripted) Name() string { return "test" }
func (s *scripted) Status(context.Context) (Status, error) {
	st := s.script[min(s.i, len(s.script)-1)]
	s.i++
	return st, nil
}
func (s *scripted) Start(context.Context) error { s.started++; return s.startEr }

type events []Event

func (e *events) rec(ev Event) error { *e = append(*e, ev); return nil }
func (e events) names() []string {
	var n []string
	for _, x := range e {
		n = append(n, x.Event)
	}
	return n
}

// opts uses a fake clock: every sleep advances it a minute.
func opts(e *events) Options {
	t := time.Unix(0, 0)
	return Options{Record: e.rec, Poll: time.Second, ProgressEvery: time.Hour,
		Sleep: func(context.Context, time.Duration) error { t = t.Add(time.Minute); return nil },
		Now:   func() time.Time { return t }}
}

func TestRunFresh(t *testing.T) {
	op := &scripted{script: []Status{{Phase: Completed}, {Phase: InProgress, Progress: 0.05}, {Phase: InProgress, Progress: 0.2},
		{Phase: InProgress, Progress: 0.25}, {Phase: Completed}}}
	var e events
	st, err := Run(context.Background(), op, opts(&e))
	if err != nil || st.Phase != Completed || op.started != 1 {
		t.Fatalf("%v %+v", err, st)
	}
	// A "completed" status before the start (an earlier sanitize) does not stop a fresh
	// run; progress is journaled when it moves by 10 %.
	if !slices.Equal(e.names(), []string{EvStarted, EvProgress, EvCompleted}) || e[1].Progress != 0.2 || e[0].Action != "test" {
		t.Fatalf("%v", e)
	}
}

func TestRunForeignInProgress(t *testing.T) {
	op := &scripted{script: []Status{{Phase: InProgress}}}
	var e events
	if _, err := Run(context.Background(), op, opts(&e)); !errors.Is(err, ErrForeign) || op.started != 0 || len(e) != 0 {
		t.Fatalf("%v", err)
	}
}

func TestRunResume(t *testing.T) {
	// Still running after a crash: wait, don't start again.
	op := &scripted{script: []Status{{Phase: InProgress, Progress: 0.4}, {Phase: InProgress, Progress: 0.6}, {Phase: Completed}}}
	var e events
	o := opts(&e)
	o.Resume = true
	if _, err := Run(context.Background(), op, o); err != nil || op.started != 0 || !slices.Equal(e.names(), []string{EvWaiting, EvProgress, EvCompleted}) {
		t.Fatalf("%v %v", err, e.names())
	}
	// Completed and attested by the drive: record and stop.
	op = &scripted{script: []Status{{Phase: Completed, Attested: true}}}
	e = nil
	if _, err := Run(context.Background(), op, o); err != nil || op.started != 0 || !slices.Equal(e.names(), []string{EvAttested}) {
		t.Fatalf("%v %v", err, e.names())
	}
	// Completed but not attested (could be an earlier sanitize): run again.
	op = &scripted{script: []Status{{Phase: Completed}, {Phase: InProgress}, {Phase: Completed}}}
	e = nil
	if _, err := Run(context.Background(), op, o); err != nil || op.started != 1 {
		t.Fatalf("%v started %d", err, op.started)
	}
	// An attestation on a fresh request (no resume) still sanitizes.
	op = &scripted{script: []Status{{Phase: Completed, Attested: true}, {Phase: InProgress}, {Phase: Completed}}}
	e = nil
	o.Resume = false
	if _, err := Run(context.Background(), op, o); err != nil || op.started != 1 {
		t.Fatalf("%v", err)
	}
}

func TestRunFailures(t *testing.T) {
	op := &scripted{script: []Status{{Phase: Idle}, {Phase: InProgress}, {Phase: Failed, Detail: "x"}}}
	var e events
	if _, err := Run(context.Background(), op, opts(&e)); !errors.Is(err, ErrFailed) || e[len(e)-1].Event != EvFailed {
		t.Fatalf("%v %v", err, e)
	}
	// From failure mode a new sanitize is started, and the journal says why.
	op = &scripted{script: []Status{{Phase: Failed}, {Phase: Completed}}}
	e = nil
	if _, err := Run(context.Background(), op, opts(&e)); err != nil || e[0].Note == "" {
		t.Fatalf("%v %v", err, e)
	}
	op = &scripted{script: []Status{{Phase: Idle}}}
	e = nil
	if _, err := Run(context.Background(), op, opts(&e)); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("%v", err)
	}
	op = &scripted{script: []Status{{Phase: Idle}, {Phase: InProgress}}}
	e = nil
	o := opts(&e)
	o.MaxWait = 10 * time.Minute
	if _, err := Run(context.Background(), op, o); !errors.Is(err, ErrTimeout) {
		t.Fatalf("%v", err)
	}
	op = &scripted{script: []Status{{Phase: Idle}}, startEr: errors.New("refused")}
	if _, err := Run(context.Background(), op, opts(&e)); err == nil || err.Error() != "refused" {
		t.Fatalf("%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	op = &scripted{script: []Status{{Phase: Idle}, {Phase: InProgress}}}
	o = opts(&e)
	o.Sleep = sleepCtx
	if _, err := Run(ctx, op, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}
