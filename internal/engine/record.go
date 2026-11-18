package engine

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"shunya/internal/ata"
	"shunya/internal/journal"
	"shunya/internal/sanitize"
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
	RecVerified    = "verified" // only after done; may repeat
	// RecHidden records a change of hidden-area state (HPA removed, restored, …); it may
	// follow done, because the HPA is restored after the final verification.
	RecHidden = "hidden-area"
	// RecSecurity is one ATA Security Erase step, written before the step runs.
	RecSecurity = "security"
)

// Hidden-area events.
const (
	HiddenRemoved       = "hpa-removed"         // volatile SET MAX to the native size
	HiddenRestored      = "hpa-restored"        // volatile SET MAX back to the original size
	HiddenLeftRemoved   = "hpa-left-removed"    // policy leave-removed: nothing done
	HiddenRestoreFailed = "hpa-restore-failed"  // the drive refused; the HPA returns at power-off
	HiddenAlreadyGone   = "hpa-already-removed" // resume: still removed from the earlier run
)

// HiddenEvent is a RecHidden record.
type HiddenEvent struct {
	Event string         `json:"event"`
	State ata.HiddenArea `json:"state"` // after the event, re-read from the drive
	Note  string         `json:"note,omitempty"`
}

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

// VerifiedData records one read-back of the finished wipe.
type VerifiedData struct {
	Mode       string  `json:"mode"`    // "full" or "sampled"
	Pattern    string  `json:"pattern"` // the last pass's pattern, which was checked
	OK         bool    `json:"ok"`
	BytesRead  int64   `json:"bytes_read"`
	BadSectors int64   `json:"bad_sectors"`
	FirstBad   int64   `json:"first_bad"`
	Samples    int     `json:"samples,omitempty"`
	SeedSource string  `json:"seed_source,omitempty"`
	Seed       string  `json:"seed,omitempty"`
	Bound95    float64 `json:"bound95,omitempty"`
	// Scope is empty when the whole planned range was covered; otherwise it says what
	// was left out (e.g. the hidden range after the HPA was restored).
	Scope string `json:"scope,omitempty"`
}

// ExpectedPattern is the pattern a read-back checks: VerifyPattern, or the last pass
// for journals written before Milestone 5 (no verify_pattern field). "" means the
// method's result can't be checked.
func (p Plan) ExpectedPattern() (name, key string) {
	if p.Method == MethodOverwrite && len(p.Passes) > 0 {
		last := p.Passes[len(p.Passes)-1]
		return last.Pattern, last.Key
	}
	return p.VerifyPattern, ""
}

// Verified records a verification result.
func (j JournalRecorder) Verified(v VerifiedData) error {
	_, err := j.W.Append(RecVerified, v)
	return err
}

// Hidden records a hidden-area event.
func (j JournalRecorder) Hidden(e HiddenEvent) error {
	_, err := j.W.Append(RecHidden, e)
	return err
}

// Security records an ATA Security Erase step (before it runs).
func (j JournalRecorder) Security(s ata.Step) error {
	_, err := j.W.Append(RecSecurity, s)
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
	Verifications []VerifiedData
	HiddenEvents  []HiddenEvent
	// Security Erase: every step, the furthest one reached, and the temporary password.
	SecuritySteps []ata.Step
	SecurityStep  string
	Password      string
	// Firmware erases (Milestone 6).
	FirmwareEvents  []sanitize.Event
	MarkersPlanted  bool
	FirmwareStarted bool
	FirmwareDone    bool
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
		if st.Done && r.Type != RecVerified && r.Type != RecHidden {
			return bad(i, "%q after done", r.Type)
		}
		if st.Stopped != "" && r.Type != RecResumed && r.Type != RecHidden {
			return bad(i, "%q after a stop without resume", r.Type)
		}
		erase := st.Plan.Method != MethodOverwrite
		switch r.Type {
		case RecCheckpoint, RecPassDone, RecResumed:
			if erase && r.Type != RecResumed {
				return bad(i, "%s in a %s journal", r.Type, st.Plan.Method)
			}
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
		case RecVerified:
			if !st.Done {
				return bad(i, "verified before the wipe is done")
			}
			var v VerifiedData
			if err := r.Decode(&v); err != nil {
				return bad(i, "%v", err)
			}
			st.Verifications = append(st.Verifications, v)
		case RecHidden:
			var e HiddenEvent
			if err := r.Decode(&e); err != nil {
				return bad(i, "%v", err)
			}
			if st.Plan.Hidden == nil || !st.Plan.Hidden.RemoveHPA {
				return bad(i, "hidden-area event %q in a plan without HPA removal", e.Event)
			}
			st.HiddenEvents = append(st.HiddenEvents, e)
		case RecSecurity:
			if st.Plan.Method != MethodATAErase && st.Plan.Method != MethodATAEnhancedErase {
				return bad(i, "security step in a %s journal", st.Plan.Method)
			}
			var s ata.Step
			if err := r.Decode(&s); err != nil {
				return bad(i, "%v", err)
			}
			if _, ok := ata.StepOrder[s.Step]; !ok {
				return bad(i, "unknown security step %q", s.Step)
			}
			if s.Step == ata.StepSetPassword {
				if s.Password == "" {
					return bad(i, "set-password without the password")
				}
				st.Password = s.Password
			} else if st.Password == "" {
				return bad(i, "security step %q before set-password", s.Step)
			}
			if ata.StepOrder[s.Step] > ata.StepOrder[st.SecurityStep] {
				st.SecurityStep = s.Step
			}
			st.SecuritySteps = append(st.SecuritySteps, s)
		case RecFirmware:
			var e sanitize.Event
			if err := r.Decode(&e); err != nil {
				return bad(i, "%v", err)
			}
			if err := st.replayFirmware(e); err != nil {
				return bad(i, "%v", err)
			}
		case RecDone:
			if st.Pass != len(st.Plan.Passes) {
				return bad(i, "done after %d of %d passes", st.Pass, len(st.Plan.Passes))
			}
			if IsFirmware(st.Plan.Method) && st.Plan.Markers != nil && !st.MarkersPlanted {
				return bad(i, "done without the markers planted")
			}
			if (IsSanitize(st.Plan.Method) || strings.HasPrefix(st.Plan.Method, "nvme-format")) && !st.FirmwareDone {
				return bad(i, "done before the drive reported the erase complete")
			}
			se := st.Plan.Method == MethodATAErase || st.Plan.Method == MethodATAEnhancedErase
			if se && st.SecurityStep != ata.StepChecked {
				return bad(i, "done before the security state was checked (last step %q)", st.SecurityStep)
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

// RecFirmware records a firmware-erase step (sanitize.Event): markers planted, format or
// sanitize started, progress, completion.
const RecFirmware = "firmware"

// Firmware events besides internal/sanitize's.
const (
	EvMarkersPlanted  = "markers-planted"
	EvFormatStarted   = "format-started"
	EvFormatCompleted = "format-completed"
)

// Firmware records a firmware-erase step.
func (j JournalRecorder) Firmware(e sanitize.Event) error {
	_, err := j.W.Append(RecFirmware, e)
	return err
}

// replayFirmware applies one firmware record to the state.
func (st *State) replayFirmware(e sanitize.Event) error {
	if !IsFirmware(st.Plan.Method) {
		return fmt.Errorf("firmware event %q in a %s journal", e.Event, st.Plan.Method)
	}
	se := st.Plan.Method == MethodATAErase || st.Plan.Method == MethodATAEnhancedErase
	switch e.Event {
	case EvMarkersPlanted:
		if st.Plan.Markers == nil {
			return fmt.Errorf("markers planted but the plan has none")
		}
		st.MarkersPlanted = true
	case sanitize.EvStarted, sanitize.EvWaiting, sanitize.EvProgress, EvFormatStarted:
		if se || (e.Event == EvFormatStarted) == IsSanitize(st.Plan.Method) {
			return fmt.Errorf("event %q does not belong to %s", e.Event, st.Plan.Method)
		}
		if st.Plan.Markers != nil && !st.MarkersPlanted {
			return fmt.Errorf("%q before the markers were planted", e.Event)
		}
		st.FirmwareStarted = true
	case sanitize.EvCompleted, sanitize.EvAttested, EvFormatCompleted:
		if se || !st.FirmwareStarted && e.Event != sanitize.EvAttested {
			return fmt.Errorf("%q before the erase started", e.Event)
		}
		st.FirmwareDone = true
	case sanitize.EvFailed:
		st.FirmwareDone = false
	default:
		return fmt.Errorf("unknown firmware event %q", e.Event)
	}
	st.FirmwareEvents = append(st.FirmwareEvents, e)
	return nil
}
