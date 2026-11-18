package engine

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"shunya/internal/ata"
	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/nvme"
)

// Firmware methods (Milestone 6), besides the ATA Security Erase pair.
const (
	MethodATASanitizeCrypto     = "ata-sanitize-crypto-scramble"
	MethodATASanitizeBlock      = "ata-sanitize-block-erase"
	MethodATASanitizeOverwrite  = "ata-sanitize-overwrite"
	MethodNVMeSanitizeCrypto    = "nvme-sanitize-crypto-erase"
	MethodNVMeSanitizeBlock     = "nvme-sanitize-block-erase"
	MethodNVMeSanitizeOverwrite = "nvme-sanitize-overwrite"
	MethodNVMeFormatCrypto      = "nvme-format-crypto-erase"
	MethodNVMeFormatUserData    = "nvme-format-user-data-erase"
)

// Methods lists every method name, overwrite first.
var Methods = []string{MethodOverwrite, MethodATAErase, MethodATAEnhancedErase,
	MethodATASanitizeCrypto, MethodATASanitizeBlock, MethodATASanitizeOverwrite,
	MethodNVMeSanitizeCrypto, MethodNVMeSanitizeBlock, MethodNVMeSanitizeOverwrite,
	MethodNVMeFormatCrypto, MethodNVMeFormatUserData}

// IsFirmware: the drive erases itself (no host writes of a pattern).
func IsFirmware(m string) bool { return m != MethodOverwrite && validMethod(m) }

func validMethod(m string) bool {
	for _, x := range Methods {
		if x == m {
			return true
		}
	}
	return false
}

// IsATA / IsNVMe: which command set the method uses.
func IsATA(m string) bool  { return strings.HasPrefix(m, "ata-") }
func IsNVMe(m string) bool { return strings.HasPrefix(m, "nvme-") }

// IsSanitize: the method runs through internal/sanitize (polled, resumable inside the drive).
func IsSanitize(m string) bool { return strings.Contains(m, "-sanitize-") }

// ATASanitizeMethod / NVMeSanitizeAction / NVMeFormatSES map a method to its command.
func ATASanitizeMethod(m string) string {
	return map[string]string{MethodATASanitizeCrypto: ata.SanitizeMethodCrypto, MethodATASanitizeBlock: ata.SanitizeMethodBlock,
		MethodATASanitizeOverwrite: ata.SanitizeMethodOverwrite}[m]
}

func NVMeSanitizeAction(m string) int {
	return map[string]int{MethodNVMeSanitizeCrypto: nvme.SanactCryptoErase, MethodNVMeSanitizeBlock: nvme.SanactBlockErase,
		MethodNVMeSanitizeOverwrite: nvme.SanactOverwrite}[m]
}

func NVMeFormatSES(m string) int {
	return map[string]int{MethodNVMeFormatCrypto: nvme.SESCryptoErs, MethodNVMeFormatUserData: nvme.SESUserData}[m]
}

// NVMePlan is what Identify said about an NVMe target at planning.
type NVMePlan struct {
	Controller nvme.Controller `json:"controller"`
	Namespace  nvme.Namespace  `json:"namespace"`
	Active     []uint32        `json:"active_namespaces"`
}

// MarkerPlan: before a firmware erase, Count sectors (positions from Seed and the
// drive's fingerprint, as for sampled verification) are overwritten with HMAC canaries
// under Key; afterwards none may still read back. This shows the erase changed what the
// host could read, even when the result pattern is vendor-defined (crypto erase).
type MarkerPlan struct {
	Count int    `json:"count"`
	Seed  string `json:"seed"`
	Key   string `json:"key"`
}

// DefaultMarkers is the marker count for firmware methods.
const DefaultMarkers = 1024

// NewMarkerPlan draws a seed and key from r (crypto/rand when nil).
func NewMarkerPlan(n int, r io.Reader) (*MarkerPlan, error) {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, 48)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return &MarkerPlan{Count: n, Seed: hex.EncodeToString(b[:16]), Key: hex.EncodeToString(b[16:])}, nil
}

func (m *MarkerPlan) validate() error {
	if m == nil {
		return nil
	}
	s, err1 := hex.DecodeString(m.Seed)
	k, err2 := hex.DecodeString(m.Key)
	if m.Count < 1 || m.Count > 1<<20 || err1 != nil || err2 != nil || len(s) != 16 || len(k) != 32 {
		return fmt.Errorf("bad marker plan (count %d, seed %d bytes, key %d bytes)", m.Count, len(s), len(k))
	}
	return nil
}

// firmwareLevel is the SP 800-88 level of a firmware method on this target. Every
// method here is offered only when the drive advertises it (checked by supported).
func firmwareLevel(method string, media device.MediaType, virtual bool, h *HiddenPlan) Level {
	switch {
	case virtual:
		return LevelClear
	case method == MethodATAErase || method == MethodATAEnhancedErase:
		if media == device.MediaHDD && h != nil && !h.SolidState {
			return LevelPurge
		}
		return LevelClear
	}
	// Sanitize (ATA, NVMe) acts on all physical storage, spare and cache included, by
	// definition; NVMe Format with a secure erase setting is Purge in SP 800-88 Rev. 1
	// (NVMe SSDs), with the caveat recorded in the notes.
	return LevelPurge
}

// expectedPattern is what a read-back must find after the method ("" = indeterminate).
func expectedPattern(method string, nv *NVMePlan) string {
	switch method {
	case MethodATAErase, MethodATASanitizeOverwrite, MethodNVMeSanitizeOverwrite:
		return PatternZero // normal erase writes zeros; overwrites use pattern 0
	case MethodNVMeSanitizeBlock, MethodNVMeFormatUserData:
		if nv != nil {
			switch nv.Namespace.DeallocRead {
			case 1:
				return PatternZero
			case 2:
				return PatternOne
			}
		}
	}
	return ""
}

// supported checks the method against the capabilities recorded in the plan.
func supported(p Plan) error {
	m := p.Method
	switch {
	case IsATA(m):
		if p.Hidden == nil || !p.Hidden.Before.Checked {
			return fmt.Errorf("%s needs the drive's IDENTIFY state", m)
		}
		if IsSanitize(m) {
			s := p.Hidden.Sanitize
			ok := s != nil && s.Supported && map[string]bool{MethodATASanitizeCrypto: s.CryptoScramble,
				MethodATASanitizeBlock: s.BlockErase, MethodATASanitizeOverwrite: s.Overwrite}[m]
			if !ok {
				return fmt.Errorf("%s: the drive's IDENTIFY does not advertise it", m)
			}
		}
	case IsNVMe(m):
		nv := p.NVMe
		if nv == nil {
			return fmt.Errorf("%s needs the controller's Identify data", m)
		}
		var err error
		if IsSanitize(m) {
			err = nvme.CheckSanitize(&nv.Controller, nv.Active, NVMeSanitizeAction(m))
		} else {
			err = nvme.CheckFormat(&nv.Controller, &nv.Namespace, nv.Active, NVMeFormatSES(m))
		}
		if err != nil {
			return fmt.Errorf("%s: %w", m, err)
		}
		if got := int64(nv.Namespace.SizeBytes()); got != p.SizeBytes || nv.Namespace.BlockBytes() != p.SectorSize {
			return fmt.Errorf("namespace is %d bytes in %d-byte blocks, plan says %d / %d", got, nv.Namespace.BlockBytes(), p.SizeBytes, p.SectorSize)
		}
	}
	return nil
}

// FirmwareInput describes a firmware-erase request.
type FirmwareInput struct {
	Target     backend.Identity
	Media      device.MediaType
	Virtual    bool
	SizeBytes  int64 // what the erase covers (ATA: native size when the HPA is removed first)
	SectorSize int
	Method     string
	Hidden     *HiddenPlan // ATA
	NVMe       *NVMePlan   // NVMe
	ChunkBytes int
}

// ErrNotFirmware: NewFirmwarePlan was given the overwrite method or an unknown one.
var ErrNotFirmware = errors.New("not a firmware erase method")

// NewFirmwarePlan builds the plan for a firmware erase. Marker keys are generated at
// execution (GenerateKeys), like overwrite pattern keys.
func NewFirmwarePlan(in FirmwareInput) (Plan, error) {
	if !IsFirmware(in.Method) {
		return Plan{}, fmt.Errorf("%w: %q", ErrNotFirmware, in.Method)
	}
	if in.ChunkBytes == 0 {
		in.ChunkBytes = DefaultChunk
	}
	p := Plan{Version: 1, Target: in.Target, Media: in.Media, Virtual: in.Virtual, Method: in.Method,
		SizeBytes: in.SizeBytes, SectorSize: in.SectorSize, ChunkBytes: in.ChunkBytes, SyncEveryBytes: DefaultSyncEvery,
		Hidden: in.Hidden, NVMe: in.NVMe, VerifyPattern: expectedPattern(in.Method, in.NVMe),
		Markers: &MarkerPlan{Count: DefaultMarkers}}
	p.Level = firmwareLevel(p.Method, p.Media, p.Virtual, p.Hidden)
	if err := p.validate(false); err != nil {
		return Plan{}, err
	}
	p.EstimateSeconds = firmwareEstimate(p)
	p.Notes = firmwareNotes(p)
	return p, nil
}

func firmwareEstimate(p Plan) float64 {
	if p.Hidden != nil && p.Hidden.Security != nil && (p.Method == MethodATAErase || p.Method == MethodATAEnhancedErase) {
		m := p.Hidden.Security.NormalEraseMinutes
		if p.Method == MethodATAEnhancedErase {
			m = p.Hidden.Security.EnhancedEraseMinutes
		}
		if m > 0 {
			return float64(m * 60)
		}
	}
	switch p.Method {
	case MethodNVMeSanitizeCrypto, MethodATASanitizeCrypto, MethodNVMeFormatCrypto:
		return 60
	case MethodNVMeSanitizeOverwrite, MethodATASanitizeOverwrite:
		return float64(p.SizeBytes) / assumedRate(p.Media)
	}
	return max(60, float64(p.SizeBytes)/(4*assumedRate(p.Media)))
}

var methodText = map[string]string{
	MethodATASanitizeCrypto:     "ATA SANITIZE CRYPTO SCRAMBLE: the drive changes its internal encryption key, so all user data (spare and cached blocks included) becomes unreadable",
	MethodATASanitizeBlock:      "ATA SANITIZE BLOCK ERASE: the drive erases every physical block, spare and retired blocks included",
	MethodATASanitizeOverwrite:  "ATA SANITIZE OVERWRITE: the drive overwrites every physical location with a zero pattern",
	MethodNVMeSanitizeCrypto:    "NVMe Sanitize, crypto erase: the controller changes the media encryption key for all user data in the subsystem",
	MethodNVMeSanitizeBlock:     "NVMe Sanitize, block erase: the controller erases every physical block, spare and over-provisioned ones included",
	MethodNVMeSanitizeOverwrite: "NVMe Sanitize, overwrite: the controller overwrites every physical location with a zero pattern (slow, and wears flash)",
	MethodNVMeFormatCrypto:      "NVMe Format NVM, cryptographic erase (SES 2): the controller replaces the namespace's encryption key",
	MethodNVMeFormatUserData:    "NVMe Format NVM, user data erase (SES 1): the controller erases all user data of the namespace",
}

func firmwareNotes(p Plan) []string {
	if p.Method == MethodATAErase || p.Method == MethodATAEnhancedErase {
		n := eraseNotes(p)
		return append(n[:len(n)-1], markerNote(p), n[len(n)-1])
	}
	var n []string
	if p.Level == LevelPurge {
		n = append(n, "NIST SP 800-88 Rev. 1 level: Purge. "+methodText[p.Method]+".")
	} else {
		n = append(n, "NIST SP 800-88 Rev. 1 level: Clear. "+methodText[p.Method]+", but the drive is virtual: the command reaches the hypervisor's emulation, not a physical medium.")
	}
	if IsSanitize(p.Method) {
		n = append(n, "A sanitize runs inside the drive: it continues across power loss, normal I/O is refused until it ends, and a failure leaves the drive in sanitize failure mode until another sanitize succeeds. Shunya polls the drive's status and journals progress; a resume waits for it.")
	}
	if p.Method == MethodNVMeFormatUserData {
		n = append(n, "Caveat: NVMe leaves the scope of a user data erase to the controller (whether over-provisioned blocks are included is vendor-defined). NVMe Sanitize, where supported, is the stronger choice.")
	}
	if p.Method == MethodNVMeFormatCrypto {
		n = append(n, "Offered only because the controller advertises cryptographic erase (FNA bit 2); a controller without it may still complete the command (QEMU does).")
	}
	if p.VerifyPattern != "" {
		n = append(n, fmt.Sprintf("Afterwards every block should read as the %s pattern; --verify and --sample check it.", p.VerifyPattern))
	} else {
		n = append(n, "Afterwards the content is indeterminate (vendor pattern or undecryptable data): there is no pattern to verify, so --verify is refused.")
	}
	n = append(n, markerNote(p))
	if p.NVMe != nil && IsSanitize(p.Method) {
		n = append(n, "A sanitize acts on the whole NVM subsystem; Shunya checked that the target is its only active namespace on a single-controller subsystem.")
	}
	n = append(n, p.Hidden.notes(p.Media)...)
	n = append(n, "Estimated time: "+time.Duration(p.EstimateSeconds*float64(time.Second)).Round(time.Second).String()+" (rough).")
	return n
}

func markerNote(p Plan) string {
	if p.Markers == nil {
		return ""
	}
	return fmt.Sprintf("Before the erase, %d sectors at positions the operator can't choose are overwritten with HMAC-tagged markers; afterwards none may read back (checked automatically).", p.Markers.Count)
}
