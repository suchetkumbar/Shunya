package ata

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// FrozenHelp explains the frozen state and the usual workarounds. Shunya never applies
// them itself: both act on the whole machine.
const FrozenHelp = "The drive is in Security FROZEN mode: the firmware (BIOS/UEFI) sent SECURITY FREEZE LOCK at boot, " +
	"and the drive refuses every Security command until its next power cycle. Workarounds an operator may apply: " +
	"(1) suspend the machine to RAM and resume it (the drive is powered off and comes back unfrozen, e.g. `echo mem > /sys/power/state`); " +
	"(2) on a SATA port that supports hot-plug, unplug and reconnect the drive's power while the system runs; " +
	"(3) use a machine or BIOS setting that does not freeze drives. Then run Shunya again."

// ErrFrozen: the drive is in Security FROZEN mode (the error text includes FrozenHelp).
var ErrFrozen = errors.New("drive security is frozen")

// FrozenError is ErrFrozen with the workaround explained.
func FrozenError() error { return fmt.Errorf("%w: %s", ErrFrozen, FrozenHelp) }

// EraseRefusal lists why an erase (Security Erase by default, or What) can't start.
type EraseRefusal struct {
	What    string
	Reasons []string
}

func (e *EraseRefusal) Error() string {
	w := e.What
	if w == "" {
		w = "ATA Security Erase"
	}
	return w + " refused: " + strings.Join(e.Reasons, "; ")
}

// CheckErase reports whether a Security Erase of mode can start on a drive in state id.
// ourPassword: the drive's password was set by this wipe (a resume after a crash), so an
// enabled or locked drive is expected.
func CheckErase(id *Identify, enhanced, ourPassword bool) error {
	s := id.Security
	var why []string
	if !s.Supported {
		why = append(why, "the drive does not support the ATA Security feature set")
	} else {
		if s.Frozen {
			why = append(why, FrozenHelp)
		}
		if s.CountExpired {
			why = append(why, "the password attempt counter has expired (5 wrong passwords); power-cycle the drive first")
		}
		if s.Enabled && !ourPassword {
			why = append(why, "a user password is already set (by someone else); Shunya will not guess or override it")
		}
		if s.Locked && !ourPassword {
			why = append(why, "the drive is locked with an unknown password")
		}
		if enhanced && !s.EnhancedSupported {
			why = append(why, "enhanced erase requested but not supported (IDENTIFY word 128 bit 5)")
		}
	}
	if len(why) > 0 {
		return &EraseRefusal{Reasons: why}
	}
	return nil
}

// NewPassword returns a temporary user password: "shunya-" and 20 random base32
// characters (100 bits). It is printable so an operator can also use it with hdparm
// (--security-unlock / --security-disable) if Shunya's recovery is unavailable.
func NewPassword(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, 13)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return "shunya-" + base32.StdEncoding.EncodeToString(b)[:20], nil
}

// EraseTimeout is how long ERASE UNIT may run: twice the drive's own estimate plus 30
// minutes, or 24 hours when it gives none (or "longer than the field can express").
func EraseTimeout(id *Identify, enhanced bool) time.Duration {
	m := id.Security.NormalEraseMinutes
	if enhanced {
		m = id.Security.EnhancedEraseMinutes
	}
	if m <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(2*m)*time.Minute + 30*time.Minute
}

// Erase steps, journaled before each is attempted (so a crash leaves the password and
// the furthest step that may have happened on record).
const (
	StepSetPassword  = "set-password"
	StepUnlock       = "unlock"
	StepErasePrepare = "erase-prepare"
	StepEraseUnit    = "erase-unit"
	StepEraseDone    = "erase-done"
	StepDisable      = "disable-password"
	StepChecked      = "security-checked"
)

// StepOrder ranks steps; resume logic compares positions.
var StepOrder = map[string]int{StepSetPassword: 1, StepUnlock: 2, StepErasePrepare: 3, StepEraseUnit: 4, StepEraseDone: 5, StepDisable: 6, StepChecked: 7}

// Step is one journaled step.
type Step struct {
	Step     string   `json:"step"`
	Password string   `json:"password,omitempty"` // set-password only: the temporary password
	Mode     string   `json:"mode,omitempty"`     // "normal" or "enhanced"
	Timeout  float64  `json:"timeout_seconds,omitempty"`
	Seconds  float64  `json:"seconds,omitempty"` // erase-done: how long ERASE UNIT took
	After    Security `json:"after,omitzero"`    // security-checked: state at the end
}

// EraseOptions configures SecureErase.
type EraseOptions struct {
	Enhanced bool
	Password string
	// Resume: the furthest step the journal shows ("" for a fresh erase).
	Resume string
	Record func(Step) error
	now    func() time.Time
}

// ModeName is "enhanced" or "normal".
func ModeName(enhanced bool) string {
	if enhanced {
		return "enhanced"
	}
	return "normal"
}

// ErrStillEnabled: the erase finished but the drive still has the temporary password.
var ErrStillEnabled = errors.New("the drive still has Shunya's temporary user password set; run `shunya ata unlock` with the journal")

// SecureErase runs (or resumes) an ATA Security Erase:
//
//	IDENTIFY → [SET PASSWORD] → [UNLOCK if locked] → ERASE PREPARE → ERASE UNIT →
//	IDENTIFY → [DISABLE PASSWORD if still enabled] → IDENTIFY
//
// Every step is recorded before it is attempted. On resume (o.Resume != ""):
//   - security enabled (with the journaled password): unlock if locked, erase again;
//   - security not enabled: start again from SET PASSWORD. This holds even when the
//     journal shows ERASE UNIT was sent: a successful erase clears the password, but so
//     does an operator running SECURITY DISABLE PASSWORD on an interrupted drive, so a
//     missing password is no proof of a completed erase. Erasing twice costs time;
//     inferring completion could certify a drive that was never erased.
func SecureErase(ctx context.Context, d Device, o EraseOptions) (Security, error) {
	if o.now == nil {
		o.now = time.Now
	}
	rec := func(s Step) error {
		if err := o.Record(s); err != nil {
			return fmt.Errorf("journal: %w", err)
		}
		return nil
	}
	mode := ModeName(o.Enhanced)
	id, _, err := d.Identify(ctx)
	if err != nil {
		return Security{}, err
	}
	ours := o.Resume != "" && StepOrder[o.Resume] >= StepOrder[StepSetPassword]
	s := id.Security
	if err := CheckErase(id, o.Enhanced, ours && s.Enabled); err != nil {
		return s, err
	}
	if !s.Enabled {
		if err := rec(Step{Step: StepSetPassword, Password: o.Password}); err != nil {
			return s, err
		}
		c, data, err := SecuritySetUserPassword(o.Password)
		if err != nil {
			return s, err
		}
		if _, err := d.Exec(ctx, c, data); err != nil {
			return s, err
		}
		if id, _, err = d.Identify(ctx); err != nil {
			return s, err
		}
		if !id.Security.Enabled {
			return id.Security, errors.New("SECURITY SET PASSWORD completed but IDENTIFY does not show security enabled")
		}
	} else if s.Locked {
		if err := rec(Step{Step: StepUnlock}); err != nil {
			return s, err
		}
		c, data, err := SecurityUnlockUser(o.Password)
		if err != nil {
			return s, err
		}
		if _, err := d.Exec(ctx, c, data); err != nil {
			return s, fmt.Errorf("unlock with the journaled password: %w", err)
		}
	}
	timeout := EraseTimeout(id, o.Enhanced)
	if err := rec(Step{Step: StepErasePrepare}); err != nil {
		return s, err
	}
	if _, err := d.Exec(ctx, SecurityErasePrepare(), nil); err != nil {
		return s, err
	}
	if err := rec(Step{Step: StepEraseUnit, Mode: mode, Timeout: timeout.Seconds()}); err != nil {
		return s, err
	}
	c, data, err := SecurityEraseUnit(o.Password, o.Enhanced, timeout)
	if err != nil {
		return s, err
	}
	start := o.now()
	if _, err := d.Exec(ctx, c, data); err != nil {
		return s, err
	}
	if err := rec(Step{Step: StepEraseDone, Mode: mode, Seconds: o.now().Sub(start).Seconds()}); err != nil {
		return s, err
	}
	return finish(ctx, d, o, rec)
}

// finish checks the state after the erase and removes the password if it is still set.
func finish(ctx context.Context, d Device, o EraseOptions, rec func(Step) error) (Security, error) {
	id, _, err := d.Identify(ctx)
	if err != nil {
		return Security{}, err
	}
	if id.Security.Enabled {
		if err := rec(Step{Step: StepDisable}); err != nil {
			return id.Security, err
		}
		if id.Security.Locked {
			c, data, _ := SecurityUnlockUser(o.Password)
			if _, err := d.Exec(ctx, c, data); err != nil {
				return id.Security, err
			}
		}
		c, data, err := SecurityDisableUserPassword(o.Password)
		if err != nil {
			return id.Security, err
		}
		if _, err := d.Exec(ctx, c, data); err != nil {
			return id.Security, err
		}
		if id, _, err = d.Identify(ctx); err != nil {
			return Security{}, err
		}
	}
	after := id.Security
	if after.Enabled || after.Locked {
		return after, ErrStillEnabled
	}
	return after, rec(Step{Step: StepChecked, After: after})
}

// Unlock is the recovery path for a drive left with the temporary password (crash
// between SET PASSWORD and the end of the erase): unlock if locked, then disable.
func Unlock(ctx context.Context, d Device, pw string) (Security, error) {
	id, _, err := d.Identify(ctx)
	if err != nil {
		return Security{}, err
	}
	s := id.Security
	if !s.Enabled {
		return s, nil
	}
	if s.Frozen {
		return s, FrozenError()
	}
	if s.Locked {
		c, data, err := SecurityUnlockUser(pw)
		if err != nil {
			return s, err
		}
		if _, err := d.Exec(ctx, c, data); err != nil {
			return s, fmt.Errorf("unlock: %w", err)
		}
	}
	c, data, err := SecurityDisableUserPassword(pw)
	if err != nil {
		return s, err
	}
	if _, err := d.Exec(ctx, c, data); err != nil {
		return s, fmt.Errorf("disable password: %w", err)
	}
	if id, _, err = d.Identify(ctx); err != nil {
		return Security{}, err
	}
	if id.Security.Enabled {
		return id.Security, ErrStillEnabled
	}
	return id.Security, nil
}
