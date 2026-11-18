package ata

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Transport carries one ATA PASS-THROUGH(16) CDB to a drive (the data direction and
// length follow from the CDB; data must match them) and returns the sense data
// (empty when the command completed without CHECK CONDITION). An error means the
// command could not be delivered or the host adapter failed it; an ATA-level failure is
// reported in the sense data instead.
type Transport interface {
	PassThrough(ctx context.Context, cdb [16]byte, data []byte, timeout time.Duration) (sense []byte, err error)
}

// Device sends ATA commands over a Transport and interprets the result.
type Device struct{ T Transport }

// Errors from Exec.
var (
	// ErrNoPassThrough: the SCSI layer refused ATA PASS-THROUGH itself (typical for USB
	// bridges without SAT and for non-ATA devices).
	ErrNoPassThrough = errors.New("ATA pass-through not supported by this device or bridge")
	// ErrNoRegisters: a command whose answer is in the registers returned none.
	ErrNoRegisters = errors.New("ATA registers not returned (pass-through incomplete)")
)

// CommandError is an ATA command the drive failed (ERR or DF status).
type CommandError struct {
	Cmd    string
	Result Result
}

func (e *CommandError) Error() string {
	why := "failed"
	if e.Result.Aborted() {
		why = "aborted by the drive"
	} else if e.Result.Error&ErrorIDNF != 0 {
		why = "address not found (IDNF)"
	}
	return fmt.Sprintf("%s %s (%s)", e.Cmd, why, e.Result)
}

// Aborted reports whether err is a command the drive aborted.
func Aborted(err error) bool {
	var ce *CommandError
	return errors.As(err, &ce) && ce.Result.Aborted()
}

// Exec runs one command. data must be exactly c.DataBytes() long (nil for non-data).
func (d Device) Exec(ctx context.Context, c Command, data []byte) (Result, error) {
	if len(data) != c.DataBytes() {
		return Result{}, fmt.Errorf("%s: data buffer %d bytes, command transfers %d", c.Name, len(data), c.DataBytes())
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	sb, err := d.T.PassThrough(ctx, c.CDB(), data, c.Timeout)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", c.Name, err)
	}
	s, err := ParseSense(sb)
	if err != nil {
		return Result{}, fmt.Errorf("%s: %w", c.Name, err)
	}
	r := s.Regs
	switch {
	case r.Failed():
		return r, &CommandError{Cmd: c.Name, Result: r}
	case !r.HaveRegs && s.Key == SenseIllegalRequest:
		return r, fmt.Errorf("%s: %w (sense %02x/%02x/%02x)", c.Name, ErrNoPassThrough, s.Key, s.ASC, s.ASCQ)
	case !r.HaveRegs && len(sb) > 0 && s.Key != SenseNoSense && s.Key != SenseRecovered:
		return r, fmt.Errorf("%s: SCSI sense %02x/%02x/%02x", c.Name, s.Key, s.ASC, s.ASCQ)
	case c.Dir == DirNone && !r.HaveRegs:
		return r, fmt.Errorf("%s: %w", c.Name, ErrNoRegisters)
	case r.LBAPartial && c.TF.Command == CmdReadNativeMaxExt:
		return r, fmt.Errorf("%s: fixed-format sense truncated the LBA; descriptor sense needed", c.Name)
	}
	return r, nil
}

// Identify reads and parses IDENTIFY DEVICE. The raw 512 bytes are returned too, for
// recording.
func (d Device) Identify(ctx context.Context) (*Identify, []byte, error) {
	buf := make([]byte, SectorBytes)
	if _, err := d.Exec(ctx, IdentifyCmd(), buf); err != nil {
		return nil, nil, err
	}
	id, err := ParseIdentify(buf)
	return id, buf, err
}
