package engine

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"shunya/internal/journal"
)

// Journal record types written by the engine.
const (
	RecStart       = "start"
	RecCheckpoint  = "checkpoint"
	RecPassDone    = "pass-done"
	RecInterrupted = "interrupted"
	RecError       = "error"
	RecResumed     = "resumed"
	RecDone        = "done"
)

// StartData is the first record: the wipe's identity and full plan (with pattern keys,
// so a resumed or verifying run regenerates exactly the same bytes).
type StartData struct {
	WipeID string `json:"wipe_id"`
	Tool   string `json:"tool"`
	Plan   Plan   `json:"plan"`
}

type posData struct {
	Pass   int   `json:"pass"`
	Offset int64 `json:"offset"`
}

type stopData struct {
	Pass   int    `json:"pass"`
	Offset int64  `json:"offset"`
	Reason string `json:"reason"`
}

// ResumeData records how a run picked up again.
type ResumeData struct {
	Pass      int    `json:"pass"`
	Offset    int64  `json:"offset"`
	After     string `json:"after"` // StopInterrupted, StopError or StopUnclean
	TornBytes int    `json:"torn_bytes,omitempty"`
}

type doneData struct {
	BytesWritten int64 `json:"bytes_written_last_run"`
}

// How a run ended before a resume.
const (
	StopInterrupted = "interrupted"  // cancelled cleanly (signal, operator)
	StopError       = "error"        // I/O error
	StopUnclean     = "unclean-stop" // no stop record: crash, kill -9, power loss
)

// NewWipeID returns a random 128-bit wipe identifier.
func NewWipeID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// JournalRecorder records engine progress in a signed journal.
type JournalRecorder struct{ W *journal.Writer }

var _ Recorder = JournalRecorder{}

// Start writes the start record. The plan must be complete (keys generated).
func (j JournalRecorder) Start(wipeID, tool string, p Plan) error {
	if err := p.Validate(); err != nil {
		return err
	}
	_, err := j.W.Append(RecStart, StartData{WipeID: wipeID, Tool: tool, Plan: p})
	return err
}

// Resumed records that a run continues at st's position.
func (j JournalRecorder) Resumed(st State, tornBytes int) error {
	after := StopUnclean
	if st.Stopped != "" {
		after = st.Stopped
	}
	_, err := j.W.Append(RecResumed, ResumeData{Pass: st.Pass, Offset: st.Offset, After: after, TornBytes: tornBytes})
	return err
}

func (j JournalRecorder) Checkpoint(pass int, off int64) error {
	_, err := j.W.Append(RecCheckpoint, posData{pass, off})
	return err
}
func (j JournalRecorder) PassDone(pass int) error {
	_, err := j.W.Append(RecPassDone, posData{Pass: pass})
	return err
}
func (j JournalRecorder) Interrupted(pass int, off int64, reason string) error {
	_, err := j.W.Append(RecInterrupted, stopData{pass, off, reason})
	return err
}
func (j JournalRecorder) Failed(pass int, off int64, e error) error {
	_, err := j.W.Append(RecError, stopData{pass, off, e.Error()})
	return err
}
func (j JournalRecorder) Done(n int64) error {
	_, err := j.W.Append(RecDone, doneData{n})
	return err
}

// Interruption is one stop-and-resume, as the certificate will report it.
type Interruption struct {
	Kind      string    `json:"kind"` // StopInterrupted, StopError, StopUnclean
	Reason    string    `json:"reason,omitempty"`
	Pass      int       `json:"pass"`
	Offset    int64     `json:"offset"`               // synced position the run resumed from
	StoppedAt time.Time `json:"stopped_at,omitzero"`  // time of the stop record (or last record if unclean)
	ResumedAt time.Time `json:"resumed_at,omitzero"`  // zero if not resumed (yet)
	TornBytes int       `json:"torn_bytes,omitempty"` // incomplete journal line found at resume
}

// State is a journal replayed: where the wipe stands.
type State struct {
	WipeID        string
	Tool          string
	Plan          Plan
	Pass          int   // next pass to write (len(Plan.Passes) when all are done)
	Offset        int64 // synced offset within Pass
	Done          bool
	Stopped       string // StopInterrupted or StopError if the last run ended with a stop record
	StopReason    string
	Started       time.Time
	Finished      time.Time
	LastRecord    time.Time
	Interruptions []Interruption
}

// Replay rebuilds the wipe state from a verified journal and checks that the records
// form a consistent history (positions only move forward, passes complete in order).
func Replay(log *journal.Log) (State, error) {
	var st State
	bad := func(i int, f string, a ...any) (State, error) {
		return State{}, fmt.Errorf("journal record %d: %s", i+1, fmt.Sprintf(f, a...))
	}
	if len(log.Records) == 0 {
		return st, errors.New("journal is empty")
	}
	for i, r := range log.Records {
		if i == 0 {
			if r.Type != RecStart {
				return bad(i, "first record is %q, want start", r.Type)
			}
			var sd StartData
			if err := r.Decode(&sd); err != nil {
				return bad(i, "%v", err)
			}
			if err := sd.Plan.Validate(); err != nil {
				return bad(i, "plan: %v", err)
			}
			st.WipeID, st.Tool, st.Plan, st.Started = sd.WipeID, sd.Tool, sd.Plan, r.At()
			st.LastRecord = r.At()
			continue
		}
		if st.Done {
			return bad(i, "%q after done", r.Type)
		}
		if st.Stopped != "" && r.Type != RecResumed {
			return bad(i, "%q after a stop without resume", r.Type)
		}
		switch r.Type {
		case RecCheckpoint, RecPassDone, RecResumed:
			var p posData
			if err := r.Decode(&p); err != nil {
				return bad(i, "%v", err)
			}
			if p.Pass != st.Pass {
				return bad(i, "%s for pass %d while at pass %d", r.Type, p.Pass+1, st.Pass+1)
			}
			switch r.Type {
			case RecCheckpoint:
				if p.Offset < st.Offset || p.Offset > st.Plan.SizeBytes {
					return bad(i, "checkpoint offset %d out of order (at %d)", p.Offset, st.Offset)
				}
				st.Offset = p.Offset
			case RecPassDone:
				if st.Offset != st.Plan.SizeBytes {
					return bad(i, "pass %d done at offset %d of %d", p.Pass+1, st.Offset, st.Plan.SizeBytes)
				}
				st.Pass, st.Offset = st.Pass+1, 0
			case RecResumed:
				var rd ResumeData
				if err := r.Decode(&rd); err != nil {
					return bad(i, "%v", err)
				}
				if rd.Offset != st.Offset {
					return bad(i, "resumed at %d, journal says %d", rd.Offset, st.Offset)
				}
				want := StopUnclean
				if st.Stopped != "" {
					want = st.Stopped
				}
				if rd.After != want {
					return bad(i, "resume says it follows %q, journal shows %q", rd.After, want)
				}
				in := Interruption{Kind: want, Reason: st.StopReason, Pass: st.Pass, Offset: st.Offset,
					StoppedAt: st.LastRecord, ResumedAt: r.At(), TornBytes: rd.TornBytes}
				st.Interruptions = append(st.Interruptions, in)
				st.Stopped, st.StopReason = "", ""
			}
		case RecInterrupted, RecError:
			var s stopData
			if err := r.Decode(&s); err != nil {
				return bad(i, "%v", err)
			}
			if s.Pass != st.Pass || s.Offset < st.Offset || s.Offset > st.Plan.SizeBytes {
				return bad(i, "%s at pass %d offset %d inconsistent with pass %d offset %d",
					r.Type, s.Pass+1, s.Offset, st.Pass+1, st.Offset)
			}
			st.Offset = s.Offset
			st.Stopped, st.StopReason = StopInterrupted, s.Reason
			if r.Type == RecError {
				st.Stopped = StopError
			}
		case RecDone:
			if st.Pass != len(st.Plan.Passes) {
				return bad(i, "done after %d of %d passes", st.Pass, len(st.Plan.Passes))
			}
			st.Done, st.Finished = true, r.At()
		default:
			return bad(i, "unknown record type %q", r.Type)
		}
		st.LastRecord = r.At()
	}
	return st, nil
}

// Pending reports how the journal's last run ended if it has not been resumed:
// StopInterrupted, StopError, StopUnclean, or "" if the wipe is done.
func (st State) Pending() string {
	switch {
	case st.Done:
		return ""
	case st.Stopped != "":
		return st.Stopped
	}
	return StopUnclean
}
