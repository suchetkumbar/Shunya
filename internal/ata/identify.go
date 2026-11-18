package ata

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// IdentifyWords is the length of IDENTIFY DEVICE data in 16-bit words.
const IdentifyWords = 256

// Identify is the parsed IDENTIFY DEVICE data (ACS-4 §7.13.7). Word numbers below are
// from that table.
type Identify struct {
	Model    string `json:"model"`         // words 27–46
	Serial   string `json:"serial"`        // words 10–19
	Firmware string `json:"firmware"`      // words 23–26
	WWN      string `json:"wwn,omitempty"` // words 108–111, "5…" NAA hex, if word 84/87 bit 8

	LBA28Sectors uint64 `json:"lba28_sectors"`  // words 60–61
	LBA48Sectors uint64 `json:"lba48_sectors"`  // words 100–103 (0 without 48-bit support)
	Supports48   bool   `json:"supports_48bit"` // word 83 bit 10

	LogicalSectorBytes  int `json:"logical_sector_bytes"`  // word 106 bit 12 → words 117–118, else 512
	PhysicalSectorBytes int `json:"physical_sector_bytes"` // word 106 bit 13, bits 3:0

	HPASupported bool `json:"hpa_supported"` // word 82 bit 10 (Host Protected Area feature set)
	DCOSupported bool `json:"dco_supported"` // word 83 bit 11 (Device Configuration Overlay)

	Security Security `json:"security"`

	TRIM        bool     `json:"trim"`         // word 169 bit 0
	RotationRPM int      `json:"rotation_rpm"` // word 217: 1 = non-rotating (solid state), 0 = not reported
	Sanitize    Sanitize `json:"sanitize"`     // word 59 bits 12–15
	Checksum    string   `json:"checksum"`     // "valid", or "absent" (word 255 signature not 0xA5)
	ATAPI       bool     `json:"atapi"`        // word 0 bit 15: a packet device, not ATA
	RawWords    []uint16 `json:"-"`
}

// Security is the Security feature set state (word 128) and erase-time estimates
// (words 89, 90).
type Security struct {
	Supported         bool `json:"supported"`          // bit 0
	Enabled           bool `json:"enabled"`            // bit 1: a user password is set
	Locked            bool `json:"locked"`             // bit 2
	Frozen            bool `json:"frozen"`             // bit 3: SECURITY FREEZE LOCK received (usually from the BIOS)
	CountExpired      bool `json:"count_expired"`      // bit 4: too many wrong passwords; power-cycle needed
	EnhancedSupported bool `json:"enhanced_supported"` // bit 5
	LevelMaximum      bool `json:"level_maximum"`      // bit 8
	// Estimated erase times in minutes: 0 = not reported; -1 = longer than the field
	// can express (508 min, or 65 532 min in the extended format).
	NormalEraseMinutes   int `json:"normal_erase_minutes"`
	EnhancedEraseMinutes int `json:"enhanced_erase_minutes"`
}

// Sanitize is the ATA Sanitize feature set support (word 59). Shunya reports it; the
// ATA SANITIZE commands themselves are not implemented yet.
type Sanitize struct {
	Supported      bool `json:"supported"`       // bit 12
	CryptoScramble bool `json:"crypto_scramble"` // bit 13
	Overwrite      bool `json:"overwrite"`       // bit 14
	BlockErase     bool `json:"block_erase"`     // bit 15
}

// Sectors is the user-addressable capacity IDENTIFY reports, in logical sectors: the
// 48-bit count if supported, else the 28-bit one. With an HPA this is the reduced size.
func (id *Identify) Sectors() uint64 {
	if id.Supports48 && id.LBA48Sectors != 0 {
		return id.LBA48Sectors
	}
	return id.LBA28Sectors
}

// SolidState reports word 217 = 1.
func (id *Identify) SolidState() bool { return id.RotationRPM == 1 }

// Parse errors.
var (
	ErrIdentifyLength   = errors.New("IDENTIFY data must be 512 bytes")
	ErrIdentifyChecksum = errors.New("IDENTIFY integrity word checksum mismatch")
	// ErrNotATA: the data is not from an ATA device: all zeros (a USB bridge without
	// SAT returns that), an ATAPI device, or invalid word-validity signatures.
	ErrNotATA = errors.New("not ATA IDENTIFY DEVICE data")
)

// ParseIdentify decodes 512 bytes of IDENTIFY DEVICE data, as the drive sent them
// (little-endian words). The integrity word (255) is checked when present.
func ParseIdentify(b []byte) (*Identify, error) {
	if len(b) != IdentifyWords*2 {
		return nil, fmt.Errorf("%w (got %d)", ErrIdentifyLength, len(b))
	}
	w := make([]uint16, IdentifyWords)
	zero := true
	for i := range w {
		w[i] = binary.LittleEndian.Uint16(b[2*i:])
		zero = zero && w[i] == 0
	}
	if zero {
		return nil, fmt.Errorf("%w: all zeros (a USB bridge without ATA pass-through returns this)", ErrNotATA)
	}
	id := &Identify{RawWords: w, Checksum: "absent"}
	if w[255]&0xff == 0xa5 {
		var sum byte
		for _, c := range b {
			sum += c
		}
		if sum != 0 {
			return nil, fmt.Errorf("%w (sum %#02x)", ErrIdentifyChecksum, sum)
		}
		id.Checksum = "valid"
	}
	if w[0]&0x8000 != 0 {
		id.ATAPI = true
		return id, fmt.Errorf("%w: word 0 bit 15 set (ATAPI packet device)", ErrNotATA)
	}
	id.Serial = ataString(w[10:20])
	id.Firmware = ataString(w[23:27])
	id.Model = ataString(w[27:47])

	id.LBA28Sectors = uint64(w[60]) | uint64(w[61])<<16
	// Words 82–84 and 85–87 are valid only if bits 15:14 of words 83/84 and 86/87 are 01.
	cmdValid := w[83]&0xc000 == 0x4000
	if cmdValid {
		id.Supports48 = w[83]&(1<<10) != 0
		id.DCOSupported = w[83]&(1<<11) != 0
		id.HPASupported = w[82]&(1<<10) != 0
		id.Security.Supported = w[82]&(1<<1) != 0
	}
	if id.Supports48 {
		id.LBA48Sectors = uint64(w[100]) | uint64(w[101])<<16 | uint64(w[102])<<32 | uint64(w[103])<<48
		if id.LBA48Sectors > 1<<48 {
			return nil, fmt.Errorf("%w: 48-bit capacity %d beyond 2^48 sectors", ErrNotATA, id.LBA48Sectors)
		}
	}
	if (w[84]&0xc000 == 0x4000 && w[84]&(1<<8) != 0) || (w[87]&0xc000 == 0x4000 && w[87]&(1<<8) != 0) {
		if wwn := uint64(w[108])<<48 | uint64(w[109])<<32 | uint64(w[110])<<16 | uint64(w[111]); wwn != 0 {
			id.WWN = fmt.Sprintf("%016x", wwn)
		}
	}

	id.LogicalSectorBytes, id.PhysicalSectorBytes = 512, 512
	if w[106]&0xc000 == 0x4000 {
		if w[106]&(1<<12) != 0 {
			if n := (uint64(w[117]) | uint64(w[118])<<16) * 2; n >= 512 && n <= 1<<24 {
				id.LogicalSectorBytes = int(n)
			}
		}
		if w[106]&(1<<13) != 0 {
			id.PhysicalSectorBytes = id.LogicalSectorBytes << (w[106] & 0x0f)
		} else {
			id.PhysicalSectorBytes = id.LogicalSectorBytes
		}
	}

	if s := w[128]; s&1 != 0 || id.Security.Supported {
		sec := &id.Security
		sec.Supported = s&1 != 0
		sec.Enabled = s&(1<<1) != 0
		sec.Locked = s&(1<<2) != 0
		sec.Frozen = s&(1<<3) != 0
		sec.CountExpired = s&(1<<4) != 0
		sec.EnhancedSupported = s&(1<<5) != 0
		sec.LevelMaximum = s&(1<<8) != 0
		sec.NormalEraseMinutes = eraseMinutes(w[89])
		sec.EnhancedEraseMinutes = eraseMinutes(w[90])
	}
	id.TRIM = w[169]&1 != 0
	if r := w[217]; r == 1 || (r >= 0x401 && r <= 0xfffe) {
		id.RotationRPM = int(r)
	}
	id.Sanitize = Sanitize{
		Supported:      w[59]&(1<<12) != 0,
		CryptoScramble: w[59]&(1<<13) != 0,
		Overwrite:      w[59]&(1<<14) != 0,
		BlockErase:     w[59]&(1<<15) != 0,
	}
	return id, nil
}

// eraseMinutes decodes words 89/90: bit 15 selects the extended format (bits 14:0 × 2
// minutes, 32 767 = longer); otherwise bits 7:0 × 2 minutes, 255 = longer than 508 min.
func eraseMinutes(v uint16) int {
	if v&0x8000 != 0 {
		n := int(v & 0x7fff)
		if n == 0x7fff {
			return -1
		}
		return 2 * n
	}
	n := int(v & 0xff)
	if n == 0xff {
		return -1
	}
	return 2 * n
}

// ataString decodes an ATA string field: each word holds two characters, the first in
// the high byte ("byte-swapped" relative to memory order); padding is spaces.
func ataString(w []uint16) string {
	b := make([]byte, 0, 2*len(w))
	for _, x := range w {
		b = append(b, byte(x>>8), byte(x))
	}
	b = bytes.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, b)
	return strings.TrimSpace(string(b))
}

// ParseHdparmDump reads IDENTIFY data in the text form of `hdparm --Istdout` (and
// sg_sat_identify -HHH): 256 four-digit hex words, any whitespace. Lines starting with
// '#' and a leading "/dev/NAME:" line are ignored. It returns the 512 bytes in drive
// (little-endian) order, for ParseIdentify.
func ParseHdparmDump(text []byte) ([]byte, error) {
	out := make([]byte, 0, IdentifyWords*2)
	sc := bufio.NewScanner(bytes.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || (strings.HasPrefix(line, "/dev/") && strings.HasSuffix(line, ":")) {
			continue
		}
		for _, f := range strings.Fields(line) {
			if len(f) != 4 {
				return nil, fmt.Errorf("hdparm dump: %q is not a 4-digit hex word", f)
			}
			v, err := strconv.ParseUint(f, 16, 16)
			if err != nil {
				return nil, fmt.Errorf("hdparm dump: %q: %w", f, err)
			}
			if len(out) == IdentifyWords*2 {
				return nil, errors.New("hdparm dump: more than 256 words")
			}
			out = binary.LittleEndian.AppendUint16(out, uint16(v))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) != IdentifyWords*2 {
		return nil, fmt.Errorf("hdparm dump: %d words, want 256", len(out)/2)
	}
	return out, nil
}

// FormatHdparmDump writes 512 bytes of IDENTIFY data in `hdparm --Istdout` form, so
// dumps Shunya records can be read by hdparm --Istdin and vice versa.
func FormatHdparmDump(b []byte) string {
	var s strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		s.WriteString(hex.EncodeToString([]byte{b[i+1], b[i]}))
		if (i/2)%8 == 7 {
			s.WriteByte('\n')
		} else {
			s.WriteByte(' ')
		}
	}
	return s.String()
}

// DCO is the DEVICE CONFIGURATION IDENTIFY data (ACS-3 §7.6.4). Only the fields Shunya
// relies on are decoded: the factory maximum LBA and the checksum.
type DCO struct {
	Revision   uint16 `json:"revision"`    // word 0
	MaxSectors uint64 `json:"max_sectors"` // words 3–6: maximum LBA + 1
	Checksum   string `json:"checksum"`    // "valid" or "absent"
}

// ParseDCO decodes 512 bytes of DCO IDENTIFY data.
func ParseDCO(b []byte) (*DCO, error) {
	if len(b) != 512 {
		return nil, fmt.Errorf("DCO data must be 512 bytes (got %d)", len(b))
	}
	w := func(i int) uint64 { return uint64(binary.LittleEndian.Uint16(b[2*i:])) }
	d := &DCO{Revision: uint16(w(0)), Checksum: "absent"}
	if w(255)&0xff == 0xa5 {
		var sum byte
		for _, c := range b {
			sum += c
		}
		if sum != 0 {
			return nil, fmt.Errorf("DCO data checksum mismatch (sum %#02x)", sum)
		}
		d.Checksum = "valid"
	}
	max := w(3) | w(4)<<16 | w(5)<<32 | w(6)<<48
	if max == 0 {
		return nil, errors.New("DCO data reports maximum LBA 0")
	}
	d.MaxSectors = max + 1
	return d, nil
}
