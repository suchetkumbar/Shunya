// Package ata speaks ATA to SATA drives through SCSI/ATA Translation (SAT): every ATA
// command travels inside an ATA PASS-THROUGH(16) SCSI command block, and the drive's
// registers come back in the sense data.
//
// The package is OS-neutral. A Transport moves CDBs to a drive: on Linux the guarded
// backend.Block sends them with the SG_IO ioctl; tests use the simulated drive in
// internal/ata/atafake, which decodes the very bytes built here.
//
// Only the commands Shunya needs can be built (see commands.go): IDENTIFY DEVICE, the
// HPA commands in their volatile form, DEVICE CONFIGURATION IDENTIFY, the Security
// feature set, and reads/writes. Nothing here can build a command that changes a drive
// permanently outside its user data (DCO SET/RESTORE, a non-volatile SET MAX, firmware
// download); backend.Block enforces the same allowlist on the bytes again.
package ata

import (
	"errors"
	"fmt"
	"time"
)

// OpATAPassThrough16 is the SCSI operation code of ATA PASS-THROUGH(16) (SAT-4 §12.2.2).
const OpATAPassThrough16 = 0x85

// SectorBytes is the ATA data block for IDENTIFY, DCO, Security and (on 512-byte
// logical-sector drives) reads and writes.
const SectorBytes = 512

// Protocol is the ATA protocol field of the pass-through CDB (SAT-4 table 167).
type Protocol uint8

const (
	ProtoNonData Protocol = 3
	ProtoPIOIn   Protocol = 4
	ProtoPIOOut  Protocol = 5
	ProtoDMA     Protocol = 6
)

// Dir is the data direction.
type Dir int

const (
	DirNone Dir = iota
	DirIn       // device to host
	DirOut      // host to device
)

func (d Dir) String() string {
	return [...]string{"none", "in", "out"}[d]
}

// Taskfile is the ATA register set of one command. For 28-bit commands only the low
// byte of Feature and Count and the low 28 bits of LBA are used.
type Taskfile struct {
	Feature uint16
	Count   uint16
	LBA     uint64 // 48 bits
	Device  uint8
	Command uint8
}

// Command is one ATA command ready to be wrapped in a CDB.
type Command struct {
	Name    string
	TF      Taskfile
	Proto   Protocol
	Dir     Dir
	Ext     bool          // 48-bit command: the "extend" bit, upper register bytes valid
	Sectors int           // 512-byte blocks transferred (0 for non-data)
	Timeout time.Duration // how long the drive may take
}

// DataBytes is the length of the data buffer the command transfers.
func (c Command) DataBytes() int { return c.Sectors * SectorBytes }

// Pass-through CDB byte 2 bits (SAT-4 table 166).
const (
	cdb2CkCond  = 0x20 // return the ATA registers in sense data even on success
	cdb2TDirIn  = 0x08 // T_DIR: 1 = from the device
	cdb2BytBlok = 0x04 // transfer length in blocks
	cdb2TLenCnt = 0x02 // T_LENGTH: the transfer length is in the COUNT field
)

// CDB builds the ATA PASS-THROUGH(16) command block:
//
//	0      0x85
//	1      MULTIPLE_COUNT(7:5) PROTOCOL(4:1) EXTEND(0)
//	2      OFF_LINE(7:6) CK_COND(5) T_TYPE(4) T_DIR(3) BYT_BLOK(2) T_LENGTH(1:0)
//	3, 4   FEATURE 15:8, 7:0
//	5, 6   COUNT 15:8, 7:0
//	7, 8   LBA 31:24, 7:0
//	9, 10  LBA 39:32, 15:8
//	11, 12 LBA 47:40, 23:16
//	13     DEVICE
//	14     COMMAND
//	15     CONTROL
//
// Non-data commands set CK_COND so the drive's registers (the native max address, for
// instance) come back in the sense data. Data commands give the transfer length in
// 512-byte blocks in the COUNT field, as hdparm and sg3_utils do.
func (c Command) CDB() [16]byte {
	var b [16]byte
	tf := c.TF
	b[0] = OpATAPassThrough16
	b[1] = byte(c.Proto) << 1
	if c.Ext {
		b[1] |= 1
	}
	switch c.Dir {
	case DirNone:
		b[2] = cdb2CkCond
	case DirIn:
		b[2] = cdb2TDirIn | cdb2BytBlok | cdb2TLenCnt
	case DirOut:
		b[2] = cdb2BytBlok | cdb2TLenCnt
	}
	b[4] = byte(tf.Feature)
	b[6] = byte(tf.Count)
	b[8] = byte(tf.LBA)
	b[10] = byte(tf.LBA >> 8)
	b[12] = byte(tf.LBA >> 16)
	if c.Ext {
		b[3] = byte(tf.Feature >> 8)
		b[5] = byte(tf.Count >> 8)
		b[7] = byte(tf.LBA >> 24)
		b[9] = byte(tf.LBA >> 32)
		b[11] = byte(tf.LBA >> 40)
	}
	b[13] = tf.Device
	b[14] = tf.Command
	return b
}

// Decoded is a pass-through CDB taken apart again (used by the simulated drive and by
// backend's allowlist).
type Decoded struct {
	TF      Taskfile
	Proto   Protocol
	Dir     Dir
	Ext     bool
	CkCond  bool
	Sectors int // transfer length in 512-byte blocks, from COUNT
}

// ErrBadCDB: the bytes are not an ATA PASS-THROUGH(16) block this package would build.
var ErrBadCDB = errors.New("not a supported ATA PASS-THROUGH(16) CDB")

// DecodeCDB parses a CDB built by Command.CDB.
func DecodeCDB(b [16]byte) (Decoded, error) {
	var d Decoded
	if b[0] != OpATAPassThrough16 {
		return d, fmt.Errorf("%w: operation code %#02x", ErrBadCDB, b[0])
	}
	if b[1]>>5 != 0 || b[2]&0xc0 != 0 || b[2]&0x10 != 0 || b[15] != 0 {
		return d, fmt.Errorf("%w: multiple count, off-line, T_TYPE or control set", ErrBadCDB)
	}
	d.Proto = Protocol(b[1] >> 1 & 0x0f)
	d.Ext = b[1]&1 != 0
	d.CkCond = b[2]&cdb2CkCond != 0
	tf := &d.TF
	tf.Feature = uint16(b[4])
	tf.Count = uint16(b[6])
	tf.LBA = uint64(b[8]) | uint64(b[10])<<8 | uint64(b[12])<<16
	if d.Ext {
		tf.Feature |= uint16(b[3]) << 8
		tf.Count |= uint16(b[5]) << 8
		tf.LBA |= uint64(b[7])<<24 | uint64(b[9])<<32 | uint64(b[11])<<40
	} else if b[3]|b[5]|b[7]|b[9]|b[11] != 0 {
		return d, fmt.Errorf("%w: upper register bytes set on a 28-bit command", ErrBadCDB)
	}
	tf.Device, tf.Command = b[13], b[14]
	tlen := b[2] & 3
	switch {
	case tlen == 0 && d.Proto == ProtoNonData && b[2]&(cdb2TDirIn|cdb2BytBlok) == 0:
		d.Dir = DirNone
	case tlen == 2 && b[2]&cdb2BytBlok != 0 && d.Proto != ProtoNonData:
		d.Dir = DirOut
		if b[2]&cdb2TDirIn != 0 {
			d.Dir = DirIn
		}
		d.Sectors = int(tf.Count)
		if d.Sectors == 0 && d.Ext {
			d.Sectors = 65536
		} else if d.Sectors == 0 {
			d.Sectors = 256
		}
	default:
		return d, fmt.Errorf("%w: protocol %d with transfer length field %d", ErrBadCDB, d.Proto, tlen)
	}
	switch {
	case d.Proto == ProtoPIOIn && d.Dir != DirIn, d.Proto == ProtoPIOOut && d.Dir != DirOut:
		return d, fmt.Errorf("%w: protocol %d with direction %s", ErrBadCDB, d.Proto, d.Dir)
	case d.Proto != ProtoNonData && d.Proto != ProtoPIOIn && d.Proto != ProtoPIOOut && d.Proto != ProtoDMA:
		return d, fmt.Errorf("%w: protocol %d", ErrBadCDB, d.Proto)
	}
	return d, nil
}
