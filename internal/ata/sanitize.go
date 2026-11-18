package ata

import (
	"context"
	"fmt"

	"shunya/internal/sanitize"
)

// SANITIZE STATUS EXT output: COUNT bits (ACS-3 Table 109).
const (
	sanCompleted  = 1 << 15 // SANITIZE OPERATION COMPLETED WITHOUT ERROR
	sanInProgress = 1 << 14 // SANITIZE IN PROGRESS
	sanFrozen     = 1 << 13 // SANITIZE DEVICE IN FROZEN STATE
)

// Sanitize methods, as they appear in method names.
const (
	SanitizeMethodCrypto    = "crypto-scramble"
	SanitizeMethodBlock     = "block-erase"
	SanitizeMethodOverwrite = "overwrite"
)

// SanitizeOp is an ATA SANITIZE DEVICE as a sanitize.Operation.
type SanitizeOp struct {
	D       Device
	Method  string
	Passes  int    // overwrite
	Pattern uint32 // overwrite
}

var _ sanitize.Operation = SanitizeOp{}

func (o SanitizeOp) Name() string { return "ata-sanitize-" + o.Method }

// Status reads SANITIZE STATUS EXT. ATA has no "nothing written since" attestation, so a
// completed status is never Attested: a resume always sanitizes again.
func (o SanitizeOp) Status(ctx context.Context) (sanitize.Status, error) {
	r, err := o.D.Exec(ctx, SanitizeStatus(), nil)
	switch {
	case Aborted(err):
		// ACS-3: the status command completes with ABRT when the last sanitize failed.
		return sanitize.Status{Phase: sanitize.Failed, Detail: fmt.Sprintf("SANITIZE STATUS EXT aborted, reason %#02x", r.LBA&0xff)}, nil
	case err != nil:
		return sanitize.Status{}, err
	case r.Count&sanInProgress != 0:
		return sanitize.Status{Phase: sanitize.InProgress, Progress: float64(r.LBA&0xffff) / 65536}, nil
	case r.Count&sanCompleted != 0:
		return sanitize.Status{Phase: sanitize.Completed, Detail: "completed without error"}, nil
	}
	return sanitize.Status{Phase: sanitize.Idle}, nil
}

// Start sends the erase subcommand.
func (o SanitizeOp) Start(ctx context.Context) error {
	var c Command
	switch o.Method {
	case SanitizeMethodCrypto:
		c = SanitizeCryptoScramble()
	case SanitizeMethodBlock:
		c = SanitizeBlockErase()
	case SanitizeMethodOverwrite:
		var err error
		if c, err = SanitizeOverwrite(o.Passes, o.Pattern); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown ATA sanitize method %q", o.Method)
	}
	_, err := o.D.Exec(ctx, c, nil)
	return err
}

// SanitizeFrozenHelp explains a sanitize freeze lock.
const SanitizeFrozenHelp = "The drive is in Sanitize FROZEN state: the firmware sent SANITIZE FREEZE LOCK EXT at boot, which lasts until the drive's next power cycle. As with the Security freeze, suspend/resume or a SATA hot-plug clears it; Shunya does not do this itself."

// CheckSanitize reports whether an ATA sanitize of method can start. The frozen state
// needs SANITIZE STATUS EXT, which only reads.
func CheckSanitize(ctx context.Context, d Device, id *Identify, method string) error {
	s := id.Sanitize
	var why []string
	switch {
	case !s.Supported:
		why = append(why, "the drive does not support the Sanitize feature set (IDENTIFY word 59 bit 12)")
	case method == SanitizeMethodCrypto && !s.CryptoScramble:
		why = append(why, "CRYPTO SCRAMBLE not supported (word 59 bit 13)")
	case method == SanitizeMethodBlock && !s.BlockErase:
		why = append(why, "BLOCK ERASE not supported (word 59 bit 15)")
	case method == SanitizeMethodOverwrite && !s.Overwrite:
		why = append(why, "OVERWRITE not supported (word 59 bit 14)")
	}
	if id.Security.Locked {
		why = append(why, "the drive is security-locked")
	}
	if len(why) == 0 {
		r, err := d.Exec(ctx, SanitizeStatus(), nil)
		switch {
		case err != nil && !Aborted(err):
			return err
		case err == nil && r.Count&sanFrozen != 0:
			why = append(why, SanitizeFrozenHelp)
		case err == nil && r.Count&sanInProgress != 0:
			why = append(why, "a sanitize is already in progress")
		}
	}
	if len(why) > 0 {
		return &EraseRefusal{What: "ATA sanitize", Reasons: why}
	}
	return nil
}
