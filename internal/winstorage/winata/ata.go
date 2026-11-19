// Package winata translates Shunya's ATA PASS-THROUGH(16) CDBs to and from Windows'
// IOCTL_ATA_PASS_THROUGH buffers (ATA_PASS_THROUGH_EX, 64-bit layout). It is separate
// from winstorage so the device package can use winstorage without importing ata.
package winata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var le = binary.LittleEndian

// ErrShort: the driver's output is shorter than the request.
var ErrShort = errors.New("winata: output truncated")

// ATA_PASS_THROUGH_EX flags (ntddscsi.h).
const (
	ataFlagsDRDYRequired = 0x01
	ataFlagsDataIn       = 0x02
	ataFlagsDataOut      = 0x04
	ataFlags48Bit        = 0x08
	ataFlagsUseDMA       = 0x10

	// HeaderSize is sizeof(ATA_PASS_THROUGH_EX) on 64-bit Windows: Length, AtaFlags,
	// PathId, TargetId, Lun, Reserved, DataTransferLength, TimeOutValue, ReservedAsUlong,
	// padding, DataBufferOffset (ULONG_PTR), PreviousTaskFile[8], CurrentTaskFile[8].
	HeaderSize = 48
)

// Request is one ATA command for IOCTL_ATA_PASS_THROUGH, translated from the SAT
// ATA PASS-THROUGH(16) CDB the rest of Shunya builds (so the allowlist, CheckATA, sees
// exactly the same command on Linux and Windows).
type Request struct {
	Flags   uint16
	Prev    [8]byte // high-order bytes of a 48-bit command
	Curr    [8]byte // Features, Count, LBA low/mid/high, Device, Command, reserved
	DataLen int
	DataIn  bool
	Ext     bool
	Command uint8
}

// SAT ATA PASS-THROUGH(16) fields (SAT-4 §12.2.2). This package cannot import ata (ata
// imports backend, which imports this), so it reads the few fields it needs itself. The
// tests check it against ata.DecodeCDB for every command Shunya builds, and backend's
// allowlist (CheckATA) has validated the CDB before it gets here.
const (
	opATAPassThrough16 = 0x85
	protoNonData       = 3
	protoPIOIn         = 4
	protoPIOOut        = 5
	protoDMA           = 6
	cdb2TDirIn         = 0x08
	cdb2BytBlok        = 0x04
	sectorBytes        = 512

	statusERR      = 0x01
	statusDF       = 0x20
	senseRecovered = 0x01
	senseAborted   = 0x0b
)

// FromCDB translates a pass-through CDB built by ata.Command.CDB.
func FromCDB(b [16]byte) (Request, error) {
	if b[0] != opATAPassThrough16 {
		return Request{}, fmt.Errorf("winata: operation code %#02x is not ATA PASS-THROUGH(16)", b[0])
	}
	if b[1]>>5 != 0 || b[2]&0xc0 != 0 || b[2]&0x10 != 0 || b[15] != 0 {
		return Request{}, fmt.Errorf("winata: multiple count, off-line, T_TYPE or control set")
	}
	proto, ext, tlen := b[1]>>1&0x0f, b[1]&1 != 0, b[2]&3
	r := Request{Ext: ext, Command: b[14], Flags: ataFlagsDRDYRequired}
	r.Curr = [8]byte{b[4], b[6], b[8], b[10], b[12], b[13], b[14], 0}
	if ext {
		r.Flags |= ataFlags48Bit
		r.Prev = [8]byte{b[3], b[5], b[7], b[9], b[11], 0, 0, 0}
	} else if b[3]|b[5]|b[7]|b[9]|b[11] != 0 {
		return Request{}, fmt.Errorf("winata: upper register bytes set on a 28-bit command")
	}
	switch {
	case tlen == 0 && proto == protoNonData && b[2]&(cdb2TDirIn|cdb2BytBlok) == 0:
	case tlen == 2 && b[2]&cdb2BytBlok != 0 && (proto == protoPIOIn || proto == protoPIOOut || proto == protoDMA):
		count := int(b[6])
		if ext {
			count |= int(b[5]) << 8
		}
		if count == 0 {
			count = 256
			if ext {
				count = 65536
			}
		}
		r.DataLen = count * sectorBytes
		r.DataIn = b[2]&cdb2TDirIn != 0
		if proto == protoPIOIn && !r.DataIn || proto == protoPIOOut && r.DataIn {
			return Request{}, fmt.Errorf("winata: protocol %d with the wrong direction", proto)
		}
		if r.DataIn {
			r.Flags |= ataFlagsDataIn
		} else {
			r.Flags |= ataFlagsDataOut
		}
		if proto == protoDMA {
			r.Flags |= ataFlagsUseDMA
		}
	default:
		return Request{}, fmt.Errorf("winata: protocol %d with transfer length field %d", proto, tlen)
	}
	return r, nil
}

// Encode builds the double-buffered IOCTL_ATA_PASS_THROUGH buffer: the header, then
// the data (copied in for a write; room for it on a read). The same buffer is the output.
func Encode(r Request, data []byte, timeout time.Duration) ([]byte, error) {
	if len(data) != r.DataLen {
		return nil, fmt.Errorf("winata: ATA data buffer %d bytes, command transfers %d", len(data), r.DataLen)
	}
	b := make([]byte, HeaderSize+r.DataLen)
	le.PutUint16(b[0:], HeaderSize)
	le.PutUint16(b[2:], r.Flags)
	le.PutUint32(b[8:], uint32(r.DataLen))
	secs := (timeout + time.Second - 1) / time.Second
	le.PutUint32(b[12:], uint32(min(max(secs, 1), 1<<32-1)))
	if r.DataLen > 0 {
		le.PutUint64(b[24:], HeaderSize)
	}
	copy(b[32:40], r.Prev[:])
	copy(b[40:48], r.Curr[:])
	if !r.DataIn {
		copy(b[HeaderSize:], data)
	}
	return b, nil
}

// Decode reads the output of IOCTL_ATA_PASS_THROUGH: it copies read data into data
// and returns the drive's registers as SAT descriptor-format sense with an ATA Status
// Return descriptor, the form ata.ParseSense decodes on Linux. Windows returns the
// registers for every command, so they are always present.
func Decode(r Request, out []byte, data []byte) ([]byte, error) {
	if len(out) < HeaderSize+r.DataLen {
		return nil, fmt.Errorf("%w: ATA_PASS_THROUGH_EX output is %d bytes", ErrShort, len(out))
	}
	if n := le.Uint16(out); n != HeaderSize {
		return nil, fmt.Errorf("winata: ATA_PASS_THROUGH_EX length %d, want %d", n, HeaderSize)
	}
	if r.DataIn {
		if got := le.Uint32(out[8:]); got != uint32(r.DataLen) {
			return nil, fmt.Errorf("winata: ATA read returned %d bytes, want %d", got, r.DataLen)
		}
		copy(data, out[HeaderSize:HeaderSize+r.DataLen])
	}
	prev, cur := out[32:40], out[40:48]
	// cur: Error, Count, LBA low, mid, high, Device, Status, reserved.
	status, errReg := cur[6], cur[0]
	sense := make([]byte, 8+14)
	sense[0] = 0x72
	if status&(statusERR|statusDF) != 0 {
		sense[1] = senseAborted // ABORTED COMMAND, 00/00: the drive reported an error
	} else {
		sense[1], sense[3] = senseRecovered, 0x1d // ATA PASS-THROUGH INFORMATION AVAILABLE
	}
	sense[7] = 14
	d := sense[8:]
	d[0], d[1] = 0x09, 0x0c
	d[3] = errReg
	d[5], d[7], d[9], d[11] = cur[1], cur[2], cur[3], cur[4]
	if r.Ext {
		d[2] = 1
		d[4], d[6], d[8], d[10] = prev[1], prev[2], prev[3], prev[4]
	}
	d[12], d[13] = cur[5], status
	return sense, nil
}
