package nvme

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strings"
)

// Controller is the parsed Identify Controller data structure (byte offsets from
// NVMe Base 2.0 Figure 312, matching libnvme struct nvme_id_ctrl).
type Controller struct {
	VID      uint16 `json:"vid"`      // 0
	SSVID    uint16 `json:"ssvid"`    // 2
	Serial   string `json:"serial"`   // 4–23
	Model    string `json:"model"`    // 24–63
	Firmware string `json:"firmware"` // 64–71
	IEEE     string `json:"ieee_oui"` // 73–75 (little-endian OUI)
	CMIC     uint8  `json:"cmic"`     // 76: bit 1 multiple controllers
	MDTS     uint8  `json:"mdts"`     // 77
	CNTLID   uint16 `json:"cntlid"`   // 78
	Version  string `json:"version"`  // 80–83
	// OACS (256): bit 1 Format NVM supported, bit 3 namespace management.
	OACS            uint16 `json:"oacs"`
	FormatSupported bool   `json:"format_supported"`
	// TNVMCAP (280–295): total NVM capacity in bytes (low 64 bits).
	TotalCapacity uint64  `json:"total_capacity_bytes"`
	Sanicap       Sanicap `json:"sanicap"` // 328
	NN            uint32  `json:"nn"`      // 516: maximum namespace ID
	FNA           FNA     `json:"fna"`     // 524
	SubNQN        string  `json:"subnqn"`  // 768–1023
}

// Sanicap is SANICAP (Identify Controller bytes 328–331).
type Sanicap struct {
	Raw       uint32 `json:"raw"`
	Crypto    bool   `json:"crypto_erase"` // bit 0
	Block     bool   `json:"block_erase"`  // bit 1
	Overwrite bool   `json:"overwrite"`    // bit 2
	// NDI: No-Deallocate Inhibited (bit 29); NODMMAS (bits 31:30).
	NDI     bool  `json:"ndi"`
	NODMMAS uint8 `json:"nodmmas"`
}

// Any reports support for at least one sanitize action.
func (s Sanicap) Any() bool { return s.Crypto || s.Block || s.Overwrite }

// FNA is the Format NVM Attributes (byte 524).
type FNA struct {
	Raw uint8 `json:"raw"`
	// FormatAllNamespaces (bit 0): a format of one namespace formats all of them.
	FormatAllNamespaces bool `json:"format_all_namespaces"`
	// SecureEraseAllNamespaces (bit 1): a secure erase of one namespace erases all.
	SecureEraseAllNamespaces bool `json:"secure_erase_all_namespaces"`
	// CryptoErase (bit 2): cryptographic erase is supported (SES = 2).
	CryptoErase bool `json:"crypto_erase"`
	// NoBroadcast (bit 3): format with NSID FFFFFFFFh is not supported.
	NoBroadcast bool `json:"no_broadcast_format"`
}

// LBAFormat is one LBA Format descriptor.
type LBAFormat struct {
	MetadataBytes int `json:"metadata_bytes"`
	DataBytes     int `json:"data_bytes"`
	RelPerf       int `json:"relative_performance"`
}

// Namespace is the parsed Identify Namespace data structure (NVM command set).
type Namespace struct {
	NSID        uint32 `json:"nsid"`
	Size        uint64 `json:"nsze"`         // 0: in logical blocks
	Capacity    uint64 `json:"ncap"`         // 8
	Utilization uint64 `json:"nuse"`         // 16
	NLBAF       int    `json:"nlbaf"`        // 25 (zero-based count)
	LBAF        int    `json:"current_lbaf"` // 26: FLBAS bits 3:0 and 6:5
	// MetadataExtended: FLBAS bit 4, metadata transferred at the end of each LBA.
	MetadataExtended bool `json:"metadata_extended"`
	PIType           int  `json:"pi_type"`  // 29: DPS bits 2:0
	PIFirst          bool `json:"pi_first"` // DPS bit 3
	Shared           bool `json:"shared"`   // 30: NMIC bit 0
	// FormatProgress (32: FPI bit 7): the namespace reports format progress.
	FormatProgress bool `json:"format_progress_supported"`
	// DeallocRead (33: DLFEAT bits 2:0): what a deallocated block reads as: 0 not
	// reported, 1 all zeros, 2 all ones.
	DeallocRead int         `json:"dealloc_read"`
	NGUID       string      `json:"nguid,omitempty"` // 104–119
	EUI64       string      `json:"eui64,omitempty"` // 120–127
	Formats     []LBAFormat `json:"lba_formats"`     // 128 + 4·i
}

// BlockBytes is the current logical block size.
func (n *Namespace) BlockBytes() int { return n.Formats[n.LBAF].DataBytes }

// SizeBytes is the namespace size in bytes.
func (n *Namespace) SizeBytes() uint64 { return n.Size * uint64(n.BlockBytes()) }

// Errors.
var (
	ErrLength  = errors.New("NVMe data structure has the wrong length")
	ErrInvalid = errors.New("invalid NVMe Identify data")
)

func str(b []byte) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, string(b)))
}

func nonZeroHex(b []byte) string {
	for _, c := range b {
		if c != 0 {
			return hex.EncodeToString(b)
		}
	}
	return ""
}

// ParseController decodes Identify Controller data.
func ParseController(b []byte) (*Controller, error) {
	if len(b) != IdentifyBytes {
		return nil, fmt.Errorf("%w: controller %d bytes", ErrLength, len(b))
	}
	le16 := func(o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
	le32 := func(o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
	c := &Controller{VID: le16(0), SSVID: le16(2), Serial: str(b[4:24]), Model: str(b[24:64]), Firmware: str(b[64:72]),
		IEEE: fmt.Sprintf("%02x%02x%02x", b[75], b[74], b[73]), CMIC: b[76], MDTS: b[77], CNTLID: le16(78)}
	if c.Serial == "" && c.Model == "" && c.VID == 0 {
		return nil, fmt.Errorf("%w: empty controller data", ErrInvalid)
	}
	v := le32(80)
	c.Version = fmt.Sprintf("%d.%d.%d", v>>16, v>>8&0xff, v&0xff)
	c.OACS = le16(256)
	c.FormatSupported = c.OACS&(1<<1) != 0
	if binary.LittleEndian.Uint64(b[288:]) == 0 {
		c.TotalCapacity = binary.LittleEndian.Uint64(b[280:])
	}
	s := le32(328)
	c.Sanicap = Sanicap{Raw: s, Crypto: s&1 != 0, Block: s&2 != 0, Overwrite: s&4 != 0, NDI: s&(1<<29) != 0, NODMMAS: uint8(s >> 30)}
	c.NN = le32(516)
	f := b[524]
	c.FNA = FNA{Raw: f, FormatAllNamespaces: f&1 != 0, SecureEraseAllNamespaces: f&2 != 0, CryptoErase: f&4 != 0, NoBroadcast: f&8 != 0}
	c.SubNQN = str(b[768:1024])
	return c, nil
}

// ParseNamespace decodes Identify Namespace data for nsid.
func ParseNamespace(nsid uint32, b []byte) (*Namespace, error) {
	if len(b) != IdentifyBytes {
		return nil, fmt.Errorf("%w: namespace %d bytes", ErrLength, len(b))
	}
	le64 := func(o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }
	n := &Namespace{NSID: nsid, Size: le64(0), Capacity: le64(8), Utilization: le64(16), NLBAF: int(b[25])}
	if n.Size == 0 {
		return nil, fmt.Errorf("%w: namespace %d is inactive (size 0)", ErrInvalid, nsid)
	}
	fl := b[26]
	n.LBAF = int(fl&0xf) | int(fl>>5&3)<<4
	n.MetadataExtended = fl&0x10 != 0
	n.PIType, n.PIFirst = int(b[29]&7), b[29]&8 != 0
	n.Shared = b[30]&1 != 0
	n.FormatProgress = b[32]&0x80 != 0
	n.DeallocRead = int(b[33] & 7)
	n.NGUID, n.EUI64 = nonZeroHex(b[104:120]), nonZeroHex(b[120:128])
	if n.NLBAF > 63 || n.LBAF > n.NLBAF {
		return nil, fmt.Errorf("%w: current LBA format %d of %d", ErrInvalid, n.LBAF, n.NLBAF+1)
	}
	for i := 0; i <= n.NLBAF; i++ {
		d := binary.LittleEndian.Uint32(b[128+4*i:])
		lbads := int(d >> 16 & 0xff)
		f := LBAFormat{MetadataBytes: int(d & 0xffff), RelPerf: int(d >> 24 & 3)}
		if lbads >= 9 && lbads <= 30 {
			f.DataBytes = 1 << lbads
		}
		n.Formats = append(n.Formats, f)
	}
	if n.Formats[n.LBAF].DataBytes == 0 {
		return nil, fmt.Errorf("%w: current LBA format has data size 2^%d", ErrInvalid, b[128+4*n.LBAF+2])
	}
	if n.Size > 1<<63/uint64(n.BlockBytes()) || n.Capacity > n.Size || bits.Len64(n.Size) > 63 {
		return nil, fmt.Errorf("%w: size %d blocks, capacity %d", ErrInvalid, n.Size, n.Capacity)
	}
	return n, nil
}

// ParseNamespaceList decodes an active namespace ID list (Identify CNS 02h).
func ParseNamespaceList(b []byte) ([]uint32, error) {
	if len(b) != IdentifyBytes {
		return nil, fmt.Errorf("%w: namespace list %d bytes", ErrLength, len(b))
	}
	var ids []uint32
	for i := 0; i < len(b); i += 4 {
		id := binary.LittleEndian.Uint32(b[i:])
		if id == 0 {
			break
		}
		if len(ids) > 0 && id <= ids[len(ids)-1] || id == NSIDAll {
			return nil, fmt.Errorf("%w: namespace list not increasing at %d", ErrInvalid, id)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Sanitize status (SSTAT bits 2:0).
const (
	SanitizeNever           = 0
	SanitizeCompleted       = 1
	SanitizeInProgress      = 2
	SanitizeFailed          = 3
	SanitizeCompletedNoDeal = 4 // completed, no-deallocate
)

// SanitizeLog is the Sanitize Status log page (81h).
type SanitizeLog struct {
	Progress float64 `json:"progress"` // SPROG / 65536 (meaningful while in progress)
	Status   int     `json:"status"`   // SSTAT 2:0
	Passes   int     `json:"overwrite_passes_completed"`
	// GlobalDataErased (SSTAT bit 8): no user data has been written since the most
	// recent successful sanitize (or since manufacture).
	GlobalDataErased bool   `json:"global_data_erased"`
	CDW10            uint32 `json:"scdw10"` // CDW10 of the most recent sanitize
	// Estimated times in seconds (-1: not reported): overwrite, block erase, crypto erase.
	EstOverwrite, EstBlock, EstCrypto int64
}

// Action is the sanitize action of the most recent sanitize.
func (l SanitizeLog) Action() int { return int(l.CDW10 & 7) }

// ParseSanitizeLog decodes the 512-byte Sanitize Status log page.
func ParseSanitizeLog(b []byte) (SanitizeLog, error) {
	if len(b) != SanitizeLogBytes {
		return SanitizeLog{}, fmt.Errorf("%w: sanitize log %d bytes", ErrLength, len(b))
	}
	est := func(o int) int64 {
		if v := binary.LittleEndian.Uint32(b[o:]); v != 0xffffffff {
			return int64(v)
		}
		return -1
	}
	ss := binary.LittleEndian.Uint16(b[2:])
	l := SanitizeLog{Progress: float64(binary.LittleEndian.Uint16(b[0:])) / 65536, Status: int(ss & 7), Passes: int(ss >> 3 & 0x1f),
		GlobalDataErased: ss&(1<<8) != 0, CDW10: binary.LittleEndian.Uint32(b[4:]), EstOverwrite: est(8), EstBlock: est(12), EstCrypto: est(16)}
	if l.Status > SanitizeCompletedNoDeal {
		return l, fmt.Errorf("%w: sanitize status %d", ErrInvalid, l.Status)
	}
	return l, nil
}
