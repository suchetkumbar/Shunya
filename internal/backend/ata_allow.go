package backend

import (
	"errors"
	"fmt"

	"shunya/internal/device"
)

// ATATransports are the transports whose drives take ATA commands through SAT: SATA
// (libata) and USB bridges, which may or may not translate them.
var ATATransports = map[device.Transport]bool{device.TransportSATA: true, device.TransportUSB: true}

// ErrATARefused: an ATA pass-through CDB outside Shunya's allowlist.
var ErrATARefused = errors.New("ATA command refused by the backend allowlist")

// ATACommand is an allowed pass-through command, as the backend sees it.
type ATACommand struct {
	Name     string
	Mutating bool // changes the drive (data, max address, security state): needs --execute
	dir      int  // 0 none, 1 in (device to host), -1 out
	blocks   int  // 512-byte blocks transferred
}

// ataRule is what an allowed command must look like.
type ataRule struct {
	name     string
	ext      bool
	proto    byte // ATA protocol field
	dir      int
	oneBlock bool // exactly one data block (IDENTIFY, DCO, Security)
	mutating bool
}

// ataAllow is the complete list of ATA commands Block will pass through. It mirrors
// internal/ata/commands.go, checked independently on the raw bytes so a bug or misuse
// above this layer cannot send anything else. Absent on purpose: DCO SET, RESTORE and
// FREEZE LOCK (permanent), the non-volatile SET MAX, SECURITY FREEZE LOCK, setting the
// master password or security level Maximum, DOWNLOAD MICROCODE, SANITIZE (not
// implemented yet) and every vendor-specific command.
var ataAllow = map[byte]ataRule{
	0xec: {name: "IDENTIFY DEVICE", proto: 4, dir: 1, oneBlock: true},
	0xb1: {name: "DEVICE CONFIGURATION IDENTIFY", proto: 4, dir: 1, oneBlock: true},
	0x27: {name: "READ NATIVE MAX ADDRESS EXT", ext: true, proto: 3},
	0xea: {name: "FLUSH CACHE EXT", ext: true, proto: 3},
	0x25: {name: "READ DMA EXT", ext: true, proto: 6, dir: 1},
	0x35: {name: "WRITE DMA EXT", ext: true, proto: 6, dir: -1, mutating: true},
	0x37: {name: "SET MAX ADDRESS EXT (volatile)", ext: true, proto: 3, mutating: true},
	0xf1: {name: "SECURITY SET PASSWORD", proto: 5, dir: -1, oneBlock: true, mutating: true},
	0xf2: {name: "SECURITY UNLOCK", proto: 5, dir: -1, oneBlock: true, mutating: true},
	0xf3: {name: "SECURITY ERASE PREPARE", proto: 3, mutating: true},
	0xf4: {name: "SECURITY ERASE UNIT", proto: 5, dir: -1, oneBlock: true, mutating: true},
	0xf6: {name: "SECURITY DISABLE PASSWORD", proto: 5, dir: -1, oneBlock: true, mutating: true},
	0xb4: {name: "SANITIZE DEVICE", ext: true, proto: 3},
}

// CheckATA checks one ATA PASS-THROUGH(16) CDB and its data buffer against the
// allowlist.
func CheckATA(cdb [16]byte, data []byte) (ATACommand, error) {
	refuse := func(f string, a ...any) (ATACommand, error) {
		return ATACommand{}, fmt.Errorf("%w: %s", ErrATARefused, fmt.Sprintf(f, a...))
	}
	if cdb[0] != 0x85 {
		return refuse("not ATA PASS-THROUGH(16) (opcode %#02x)", cdb[0])
	}
	cmd := cdb[14]
	r, ok := ataAllow[cmd]
	if !ok {
		return refuse("ATA command %#02x is not on the allowlist", cmd)
	}
	ext := cdb[1]&1 != 0
	proto := cdb[1] >> 1 & 0x0f
	if cdb[1]>>5 != 0 || cdb[2]&0xd0 != 0 || cdb[15] != 0 {
		return refuse("%s: multiple count, off-line, T_TYPE or control set", r.name)
	}
	if ext != r.ext || proto != r.proto {
		return refuse("%s: extend %v protocol %d, want %v/%d", r.name, ext, proto, r.ext, r.proto)
	}
	if !ext && cdb[3]|cdb[5]|cdb[7]|cdb[9]|cdb[11] != 0 {
		return refuse("%s: upper register bytes set on a 28-bit command", r.name)
	}
	c := ATACommand{Name: r.name, Mutating: r.mutating}
	switch tl := cdb[2] & 3; {
	case r.dir == 0 && tl == 0 && cdb[2]&0x0c == 0:
	case r.dir != 0 && tl == 2 && cdb[2]&0x04 != 0:
		c.dir = -1
		if cdb[2]&0x08 != 0 {
			c.dir = 1
		}
		c.blocks = int(cdb[6])
		if ext {
			c.blocks |= int(cdb[5]) << 8
		}
		if c.blocks == 0 {
			return refuse("%s: transfer length 0", r.name)
		}
	default:
		return refuse("%s: transfer-length field %d does not match the command", r.name, tl)
	}
	switch {
	case c.dir != r.dir:
		return refuse("%s: data direction %d, want %d", r.name, c.dir, r.dir)
	case r.oneBlock && c.blocks != 1:
		return refuse("%s: %d blocks, want 1", r.name, c.blocks)
	case len(data) != c.blocks*512:
		return refuse("%s: data buffer %d bytes, CDB transfers %d", r.name, len(data), c.blocks*512)
	}
	switch cmd {
	case 0xb1:
		if cdb[4] != 0xc2 || cdb[3] != 0 {
			return refuse("DEVICE CONFIGURATION subcommand %#02x (only IDENTIFY, C2h, is allowed; SET/RESTORE/FREEZE LOCK change the drive permanently)", cdb[4])
		}
	case 0x37:
		if cdb[6]&1 != 0 {
			return refuse("non-volatile SET MAX ADDRESS (the Value Volatile bit must be clear: Shunya never changes a drive's size permanently)")
		}
	case 0xb4:
		feat := uint16(cdb[3])<<8 | uint16(cdb[4])
		lba := uint64(cdb[8]) | uint64(cdb[10])<<8 | uint64(cdb[12])<<16 | uint64(cdb[7])<<24 | uint64(cdb[9])<<32 | uint64(cdb[11])<<40
		switch {
		case feat == 0x0000 && cdb[6]&1 == 0:
			c.Name = "SANITIZE STATUS EXT"
		case feat == 0x0011 && lba == 0x43727970, feat == 0x0012 && lba == 0x426b4572, feat == 0x0014 && lba>>32 == 0x4f57:
			if cdb[6]&0x10 != 0 {
				return refuse("SANITIZE with the failure-mode bit")
			}
			c.Name, c.Mutating = fmt.Sprintf("SANITIZE %04X", feat), true
		default:
			return refuse("SANITIZE subcommand %#04x (freeze lock, antifreeze, wrong key or status with clear-failure are not allowed)", feat)
		}
	case 0xf1:
		if data[0]&1 != 0 {
			return refuse("SECURITY SET PASSWORD for the master password")
		}
		if data[1]&1 != 0 {
			return refuse("SECURITY SET PASSWORD with security level Maximum")
		}
	}
	return c, nil
}
