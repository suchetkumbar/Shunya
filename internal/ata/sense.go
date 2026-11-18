package ata

import (
	"errors"
	"fmt"
)

// ATA status and error register bits (ACS-4 §6.1, §6.2).
const (
	StatusERR  = 0x01
	StatusDRQ  = 0x08
	StatusDF   = 0x20
	StatusDRDY = 0x40
	StatusBSY  = 0x80

	ErrorABRT = 0x04
	ErrorIDNF = 0x10
)

// Result is the drive's register set after a command, as SAT returned it.
type Result struct {
	HaveRegs bool // registers were returned (sense descriptor or fixed-format ATA info)
	Status   uint8
	Error    uint8
	Count    uint16
	LBA      uint64
	Device   uint8
	// LBAPartial: fixed-format sense carries only LBA 23:0; the upper bits were non-zero.
	LBAPartial bool
}

// Failed reports the ERR or DF status bit.
func (r Result) Failed() bool { return r.HaveRegs && r.Status&(StatusERR|StatusDF) != 0 }

// Aborted reports a command the drive aborted (ERR with ABRT): unsupported, or not
// allowed in the drive's current state (frozen, wrong password, …).
func (r Result) Aborted() bool { return r.Failed() && r.Error&ErrorABRT != 0 }

func (r Result) String() string {
	if !r.HaveRegs {
		return "no registers returned"
	}
	return fmt.Sprintf("status %#02x error %#02x count %#x lba %#x", r.Status, r.Error, r.Count, r.LBA)
}

// Sense is decoded SCSI sense data.
type Sense struct {
	Key       uint8
	ASC, ASCQ uint8
	Regs      Result
}

// SCSI sense keys used here.
const (
	SenseNoSense        = 0x00
	SenseRecovered      = 0x01
	SenseIllegalRequest = 0x05
	SenseAborted        = 0x0b
)

// ErrSense: the sense buffer could not be decoded.
var ErrSense = errors.New("malformed sense data")

// ParseSense decodes descriptor-format (response code 0x72/0x73) or fixed-format
// (0x70/0x71) sense data and the ATA registers in it (SAT-4 §12.2.5, §12.2.6):
//
//   - descriptor format: ATA Status Return descriptor, type 0x09, 12 bytes:
//     [2] EXTEND, [3] error, [4,5] count 15:8, 7:0, [6..11] LBA pairs (47:40, 23:16 …
//     in ext/low order), [12] device, [13] status;
//   - fixed format: INFORMATION bytes 3..6 are error, status, device, count 7:0; byte 8
//     flags EXTEND (7), upper count non-zero (6), upper LBA non-zero (5); bytes 9..11 are
//     LBA 7:0, 15:8, 23:16.
//
// An empty buffer returns a zero Sense with no registers and no error.
func ParseSense(b []byte) (Sense, error) {
	var s Sense
	if len(b) == 0 {
		return s, nil
	}
	switch b[0] & 0x7f {
	case 0x72, 0x73:
		if len(b) < 8 {
			return s, fmt.Errorf("%w: %d-byte descriptor sense", ErrSense, len(b))
		}
		s.Key, s.ASC, s.ASCQ = b[1]&0x0f, b[2], b[3]
		end := min(len(b), 8+int(b[7]))
		for i := 8; i+2 <= end; {
			typ, l := b[i], int(b[i+1])
			if i+2+l > end {
				return s, fmt.Errorf("%w: descriptor runs past the end", ErrSense)
			}
			if typ == 0x09 && l >= 12 {
				d := b[i : i+14]
				r := &s.Regs
				r.HaveRegs = true
				r.Error, r.Count = d[3], uint16(d[5])
				r.LBA = uint64(d[7]) | uint64(d[9])<<8 | uint64(d[11])<<16
				if d[2]&1 != 0 {
					r.Count |= uint16(d[4]) << 8
					r.LBA |= uint64(d[6])<<24 | uint64(d[8])<<32 | uint64(d[10])<<40
				}
				r.Device, r.Status = d[12], d[13]
			}
			i += 2 + l
		}
	case 0x70, 0x71:
		if len(b) < 14 {
			return s, fmt.Errorf("%w: %d-byte fixed sense", ErrSense, len(b))
		}
		s.Key, s.ASC, s.ASCQ = b[2]&0x0f, b[12], b[13]
		// SAT puts the ATA registers in fixed sense when it answers an ATA pass-through
		// command: ASC/ASCQ 00/1D ("ATA pass-through information available") on
		// success, or 00/00 with ABORTED COMMAND when the drive reported an error (as
		// libata does). Other sense (ILLEGAL REQUEST: invalid field in CDB, …) is the
		// translation layer refusing the command; its INFORMATION bytes are not registers.
		if s.Key == SenseIllegalRequest || s.ASC != 0 || (s.ASCQ != 0 && s.ASCQ != 0x1d) {
			break
		}
		r := &s.Regs
		r.HaveRegs = true
		r.Error, r.Status, r.Device, r.Count = b[3], b[4], b[5], uint16(b[6])
		r.LBA = uint64(b[9]) | uint64(b[10])<<8 | uint64(b[11])<<16
		r.LBAPartial = b[8]&0x60 != 0
	default:
		return s, fmt.Errorf("%w: response code %#02x", ErrSense, b[0])
	}
	return s, nil
}
