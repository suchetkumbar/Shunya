package engine

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"shunya/internal/backend"
	"shunya/internal/device"
)

// Level is a NIST SP 800-88 sanitisation level. An overwrite is only ever Clear.
type Level string

const (
	LevelClear Level = "clear"
	// LevelPurge is produced only by firmware erase commands, and only where SP 800-88
	// accepts them for the media (see methodLevel).
	LevelPurge Level = "purge"
)

// MediaImage marks a regular image file target (FileBackend).
const MediaImage device.MediaType = "image-file"

// Methods.
const (
	MethodOverwrite        = "overwrite"
	MethodATAErase         = "ata-secure-erase"
	MethodATAEnhancedErase = "ata-enhanced-secure-erase"
)

// Limits on plan parameters.
const (
	DefaultChunk     = 4 << 20
	DefaultSyncEvery = 64 << 20
	MaxChunk         = 64 << 20
	MaxPasses        = 16
	chunkAlign       = 4096 // chunks stay 4 KiB-aligned for O_DIRECT on 4Kn devices
)

// Pass is one overwrite pass. Key is the hex AES-256 key of a random pass; it is
// generated at execution time (GenerateKeys), not when planning.
type Pass struct {
	Pattern string `json:"pattern"`
	Key     string `json:"key,omitempty"`
}

// Pattern builds the pass's pattern generator.
func (p Pass) pattern() (Pattern, error) {
	var key []byte
	if p.Pattern == PatternRandom {
		k, err := hex.DecodeString(p.Key)
		if err != nil || len(k) != RandomKeySize {
			return nil, fmt.Errorf("random pass needs a %d-byte hex key", RandomKeySize)
		}
		key = k
	} else if p.Key != "" {
		return nil, fmt.Errorf("pattern %q takes no key", p.Pattern)
	}
	return NewPattern(p.Pattern, key)
}

// Plan is everything an overwrite wipe will do. It is printed in dry-run mode, stored
// in the journal's start record, and checked again before a resume.
type Plan struct {
	Version         int              `json:"version"`
	Target          backend.Identity `json:"target"`
	Media           device.MediaType `json:"media"`
	Virtual         bool             `json:"virtual,omitempty"`
	Method          string           `json:"method"`
	Level           Level            `json:"nist_level"`
	SizeBytes       int64            `json:"size_bytes"`
	SectorSize      int              `json:"sector_size"`
	Passes          []Pass           `json:"passes"`
	ChunkBytes      int              `json:"chunk_bytes"`
	SyncEveryBytes  int64            `json:"sync_every_bytes"`
	EstimateSeconds float64          `json:"estimate_seconds"`
	// VerifyPattern is what a read-back must find after the method: the last pass for an
	// overwrite, "zero" after a normal Security Erase (ACS: binary zeros), "" when the
	// result is vendor-defined (enhanced erase) and cannot be checked.
	VerifyPattern string      `json:"verify_pattern,omitempty"`
	Hidden        *HiddenPlan `json:"hidden,omitempty"`
	Notes         []string    `json:"notes"`
}

// PlanInput describes the target and what the operator asked for.
type PlanInput struct {
	Target     backend.Identity
	Media      device.MediaType
	Virtual    bool
	SizeBytes  int64
	SectorSize int
	Patterns   []string // default: one random pass
	ChunkBytes int      // default DefaultChunk
	SyncEvery  int64    // default DefaultSyncEvery
	// Hidden is the hidden-area state and handling (block devices). With
	// Hidden.RemoveHPA, SizeBytes must be the native size: the HPA is part of the wipe.
	Hidden *HiddenPlan
}

// NewPlan validates the input and builds an overwrite plan (without pattern keys).
func NewPlan(in PlanInput) (Plan, error) {
	if len(in.Patterns) == 0 {
		in.Patterns = []string{PatternRandom}
	}
	if in.ChunkBytes == 0 {
		in.ChunkBytes = DefaultChunk
	}
	if in.SyncEvery == 0 {
		in.SyncEvery = DefaultSyncEvery
	}
	p := Plan{
		Version: 1, Target: in.Target, Media: in.Media, Virtual: in.Virtual,
		Method: MethodOverwrite, Level: LevelClear,
		SizeBytes: in.SizeBytes, SectorSize: in.SectorSize,
		ChunkBytes: in.ChunkBytes, SyncEveryBytes: in.SyncEvery, Hidden: in.Hidden,
	}
	for _, name := range in.Patterns {
		p.Passes = append(p.Passes, Pass{Pattern: name})
	}
	if err := p.validate(false); err != nil {
		return Plan{}, err
	}
	p.EstimateSeconds = float64(p.SizeBytes) * float64(len(p.Passes)) / assumedRate(p.Media)
	p.VerifyPattern = p.Passes[len(p.Passes)-1].Pattern
	p.Notes = notes(p)
	return p, nil
}

// GenerateKeys draws a fresh AES-256 key for every random pass from r (crypto/rand.Reader
// when nil).
func (p *Plan) GenerateKeys(r io.Reader) error {
	if r == nil {
		r = rand.Reader
	}
	for i := range p.Passes {
		if p.Passes[i].Pattern != PatternRandom {
			continue
		}
		k := make([]byte, RandomKeySize)
		if _, err := io.ReadFull(r, k); err != nil {
			return fmt.Errorf("pattern key: %w", err)
		}
		p.Passes[i].Key = hex.EncodeToString(k)
	}
	return nil
}

// Validate checks a plan that is about to run (keys must be present).
func (p Plan) Validate() error { return p.validate(true) }

func (p Plan) validate(needKeys bool) error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if p.Version != 1 {
		bad("unsupported plan version %d", p.Version)
	}
	switch p.Method {
	case MethodOverwrite:
		if p.Level != LevelClear {
			bad("an overwrite is only ever Clear (got %q)", p.Level)
		}
		if len(p.Passes) == 0 || len(p.Passes) > MaxPasses {
			bad("need 1 to %d passes, got %d", MaxPasses, len(p.Passes))
		}
		if len(p.Passes) > 0 && p.VerifyPattern != "" && p.VerifyPattern != p.Passes[len(p.Passes)-1].Pattern {
			bad("verify pattern %q is not the last pass", p.VerifyPattern)
		}
	case MethodATAErase, MethodATAEnhancedErase:
		if len(p.Passes) != 0 {
			bad("%s takes no overwrite passes", p.Method)
		}
		if want := methodLevel(p.Method, p.Media, p.Virtual, p.Hidden); p.Level != want {
			bad("%s on %s media is %s, not %s", p.Method, p.Media, want, p.Level)
		}
		wantVP := PatternZero
		if p.Method == MethodATAEnhancedErase {
			wantVP = ""
		}
		if p.VerifyPattern != wantVP {
			bad("%s: verify pattern %q, want %q", p.Method, p.VerifyPattern, wantVP)
		}
		if p.Hidden == nil || !p.Hidden.Before.Checked {
			bad("%s needs the hidden-area state from IDENTIFY", p.Method)
		}
	default:
		bad("unknown method %q", p.Method)
	}
	if err := p.Hidden.validate(p.SizeBytes, p.SectorSize); err != nil {
		bad("hidden areas: %v", err)
	}
	if p.SectorSize < 512 || p.SectorSize&(p.SectorSize-1) != 0 {
		bad("bad sector size %d", p.SectorSize)
	} else {
		if p.SizeBytes <= 0 || p.SizeBytes%int64(p.SectorSize) != 0 {
			bad("size %d is not a positive multiple of the %d-byte sector", p.SizeBytes, p.SectorSize)
		}
		if p.ChunkBytes <= 0 || p.ChunkBytes > MaxChunk || p.ChunkBytes%chunkAlign != 0 || p.ChunkBytes%p.SectorSize != 0 {
			bad("chunk %d must be a multiple of 4 KiB and of the sector size, at most %d", p.ChunkBytes, MaxChunk)
		}
	}
	if p.SyncEveryBytes <= 0 {
		bad("sync interval must be positive")
	}
	if p.Target.Fingerprint == "" {
		bad("target has no fingerprint")
	}
	for i, ps := range p.Passes {
		switch {
		case ps.Pattern != PatternZero && ps.Pattern != PatternOne && ps.Pattern != PatternRandom:
			bad("pass %d: unknown pattern %q (want zero, one or random)", i+1, ps.Pattern)
		case needKeys || ps.Key != "":
			if _, err := ps.pattern(); err != nil {
				bad("pass %d: %v", i+1, err)
			}
		}
	}
	return errors.Join(errs...)
}

// assumedRate is a rough sequential write rate per media type, for the estimate only.
func assumedRate(m device.MediaType) float64 {
	const mb = 1e6
	switch m {
	case device.MediaHDD, device.MediaUSBDisk:
		return 150 * mb
	case device.MediaSSD:
		return 400 * mb
	case device.MediaNVMeSSD:
		return 1500 * mb
	case device.MediaUSBFlash, device.MediaSDCard:
		return 20 * mb
	case device.MediaEMMC:
		return 60 * mb
	case MediaImage:
		return 800 * mb
	}
	return 200 * mb
}

func isFlash(m device.MediaType) bool {
	switch m {
	case device.MediaSSD, device.MediaNVMeSSD, device.MediaUSBFlash, device.MediaEMMC, device.MediaSDCard:
		return true
	}
	return false
}

// notes are the plan's honest disclosures: what this method reaches and what it doesn't.
func notes(p Plan) []string {
	n := []string{
		"NIST SP 800-88 Rev. 1 level: Clear. An overwrite of every user-addressable sector; it is never reported as Purge.",
	}
	switch {
	case p.Media == MediaImage:
		n = append(n, "Image file: the host file system may still hold earlier copies of these blocks (copy-on-write, snapshots, its own journal); only the file's current contents are overwritten.")
	case isFlash(p.Media):
		n = append(n, "Flash media: over-provisioned, retired and remapped blocks are not user-addressable, so an overwrite cannot reach them and data may remain there. Purge needs the drive's own sanitize or secure-erase command (Milestones 5–6).")
	case p.Media == device.MediaHDD || p.Media == device.MediaUSBDisk:
		n = append(n, "Magnetic disk: sectors the drive has reallocated (grown defects) are no longer addressable and are not overwritten.")
	default:
		n = append(n, "Media type "+string(p.Media)+": the physical medium is unknown, so what an overwrite reaches below the block interface is unknown.")
	}
	if p.Virtual {
		n = append(n, "Virtual disk: the overwrite reaches the disk as the hypervisor presents it; host-side copies, snapshots and thin-provisioning are out of reach.")
	}
	n = append(n, p.Hidden.notes(p.Media)...)
	if len(p.Passes) > 1 {
		n = append(n, fmt.Sprintf("%d passes requested. NIST SP 800-88 Rev. 1 treats a single overwrite pass as sufficient for Clear on modern media; extra passes add time, not assurance (see design/NIST_MAPPING.md).", len(p.Passes)))
	}
	n = append(n, "Estimated time is a rough figure from the media type ("+time.Duration(p.EstimateSeconds*float64(time.Second)).Round(time.Second).String()+").")
	return n
}

// EraseInput describes an ATA Security Erase request.
type EraseInput struct {
	Target     backend.Identity
	Media      device.MediaType
	Virtual    bool
	SizeBytes  int64 // what the erase covers: the native size when the HPA is removed first
	SectorSize int
	Enhanced   bool
	Hidden     *HiddenPlan // required: IDENTIFY state (Security, SolidState, hidden areas)
	ChunkBytes int         // for the read-back of a normal erase; default DefaultChunk
}

// NewErasePlan builds an ATA Security Erase plan. Whether the drive is in a state that
// allows it (supported, not frozen, …) is checked by ata.CheckErase when it runs; the
// plan records the state found at planning.
func NewErasePlan(in EraseInput) (Plan, error) {
	if in.ChunkBytes == 0 {
		in.ChunkBytes = DefaultChunk
	}
	p := Plan{Version: 1, Target: in.Target, Media: in.Media, Virtual: in.Virtual, Method: MethodATAErase,
		SizeBytes: in.SizeBytes, SectorSize: in.SectorSize, ChunkBytes: in.ChunkBytes, SyncEveryBytes: DefaultSyncEvery,
		Hidden: in.Hidden, VerifyPattern: PatternZero}
	if in.Enhanced {
		p.Method, p.VerifyPattern = MethodATAEnhancedErase, ""
	}
	p.Level = methodLevel(p.Method, p.Media, p.Virtual, p.Hidden)
	if err := p.validate(false); err != nil {
		return Plan{}, err
	}
	if s := in.Hidden.Security; s != nil {
		m := s.NormalEraseMinutes
		if in.Enhanced {
			m = s.EnhancedEraseMinutes
		}
		if m > 0 {
			p.EstimateSeconds = float64(m * 60)
		}
	}
	if p.EstimateSeconds == 0 {
		p.EstimateSeconds = float64(p.SizeBytes) / assumedRate(p.Media)
	}
	p.Notes = eraseNotes(p)
	return p, nil
}

func eraseNotes(p Plan) []string {
	mode := "normal"
	if p.Method == MethodATAEnhancedErase {
		mode = "enhanced"
	}
	var n []string
	switch {
	case p.Level == LevelPurge:
		n = append(n, "NIST SP 800-88 Rev. 1 level: Purge. ATA SECURITY ERASE UNIT on a magnetic disk is a Purge method (Appendix A, ATA hard disk drives): the drive's firmware erases every user data sector, including ones the host can no longer address.")
	case p.Virtual:
		n = append(n, "NIST SP 800-88 Rev. 1 level: Clear. The drive is virtual: the erase command reaches the hypervisor's emulation, not a physical medium, so nothing beyond Clear of the virtual disk can be claimed.")
	default:
		n = append(n, "NIST SP 800-88 Rev. 1 level: Clear. On flash media the effect of ATA Security Erase is vendor-defined (whether spare and retired blocks are erased, or a media key is replaced) and cannot be checked from the host; SP 800-88 relies on ATA SANITIZE (block erase, crypto scramble) or a verified cryptographic erase for SSD Purge, which Shunya does not implement yet.")
	}
	if mode == "normal" {
		n = append(n, "Normal erase: the drive writes binary zeros to all user data (ACS-3 §7.45); Shunya can read the result back and check for zeros (--verify, --sample).")
	} else {
		n = append(n, "Enhanced erase: the drive writes a vendor-specific pattern (or changes its encryption key). The content cannot be checked against an expected pattern; Shunya records the drive's security state before and after instead, and --verify is refused.")
	}
	n = append(n, "The erase sets a temporary random user password first (journaled before it is sent, so a drive left locked by a crash can be unlocked with `shunya ata unlock`); a successful erase clears it, and Shunya checks that it is gone.")
	if p.Virtual {
		n = append(n, "Virtual disk: host-side copies, snapshots and thin provisioning are out of reach.")
	}
	n = append(n, p.Hidden.notes(p.Media)...)
	if p.Hidden != nil && p.Hidden.RemoveHPA {
		n = append(n, "Some drives erase only up to the current maximum address, so the HPA is removed before the erase command is sent.")
	}
	n = append(n, "Estimated time is the drive's own IDENTIFY estimate where it gives one ("+time.Duration(p.EstimateSeconds*float64(time.Second)).Round(time.Second).String()+").")
	return n
}
