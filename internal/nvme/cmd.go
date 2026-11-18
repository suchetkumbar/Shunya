// Package nvme speaks the NVMe admin command set: Identify, Get Log Page (Sanitize
// Status), Format NVM and Sanitize. It is OS-neutral: a Transport carries AdminCmd (the
// layout of Linux's struct nvme_passthru_cmd) to a controller. On Linux the guarded
// backend.Block sends it with NVME_IOCTL_ADMIN_CMD; tests use internal/nvme/nvmefake.
//
// Only the commands below can be built. Firmware download/commit, namespace management
// and attachment, Set Features, Security Send and every vendor command are absent, and
// backend.CheckNVMe refuses them again on the raw fields.
//
// Field offsets and bit layouts follow NVMe Base 2.0 and were cross-checked against
// libnvme's src/nvme/types.h and ioctl.h.
package nvme

import (
	"errors"
	"fmt"
	"time"
)

// Admin opcodes.
const (
	OpGetLogPage = 0x02
	OpIdentify   = 0x06
	OpFormatNVM  = 0x80
	OpSanitize   = 0x84
)

// Identify CNS values.
const (
	CNSNamespace       = 0x00
	CNSController      = 0x01
	CNSActiveNamespace = 0x02 // active NSID list
)

// Log page identifiers.
const LogSanitize = 0x81

// Data sizes.
const (
	IdentifyBytes    = 4096
	SanitizeLogBytes = 512
)

// NSIDAll is the broadcast namespace ID.
const NSIDAll = 0xffffffff

// Format NVM Secure Erase Settings.
const (
	SESNone      = 0
	SESUserData  = 1
	SESCryptoErs = 2
)

// Sanitize actions (SANACT).
const (
	SanactExitFailure = 1
	SanactBlockErase  = 2
	SanactOverwrite   = 3
	SanactCryptoErase = 4
)

// AdminCmd is struct nvme_passthru_cmd (linux/nvme_ioctl.h), 72 bytes. Addr is set by
// the transport from the data buffer; callers leave it, Metadata and MetadataLen zero.
type AdminCmd struct {
	Opcode      uint8
	Flags       uint8
	Rsvd1       uint16
	NSID        uint32
	CDW2, CDW3  uint32
	Metadata    uint64
	Addr        uint64
	MetadataLen uint32
	DataLen     uint32
	CDW10       uint32
	CDW11       uint32
	CDW12       uint32
	CDW13       uint32
	CDW14       uint32
	CDW15       uint32
	TimeoutMS   uint32
	Result      uint32
}

// Command is one admin command with a name and timeout.
type Command struct {
	Name    string
	Cmd     AdminCmd
	Timeout time.Duration
}

func cmd(name string, c AdminCmd, timeout time.Duration) Command {
	ms := timeout.Milliseconds()
	c.TimeoutMS = uint32(min(ms, 1<<32-1))
	return Command{Name: name, Cmd: c, Timeout: timeout}
}

const shortTimeout = 30 * time.Second

// IdentifyController is Identify CNS 01h (4096 bytes in).
func IdentifyController() Command {
	return cmd("IDENTIFY CONTROLLER", AdminCmd{Opcode: OpIdentify, CDW10: CNSController, DataLen: IdentifyBytes}, shortTimeout)
}

// IdentifyNamespace is Identify CNS 00h for nsid.
func IdentifyNamespace(nsid uint32) Command {
	return cmd(fmt.Sprintf("IDENTIFY NAMESPACE %d", nsid), AdminCmd{Opcode: OpIdentify, NSID: nsid, CDW10: CNSNamespace, DataLen: IdentifyBytes}, shortTimeout)
}

// IdentifyActiveNamespaces is Identify CNS 02h: the active NSIDs above 0.
func IdentifyActiveNamespaces() Command {
	return cmd("IDENTIFY ACTIVE NAMESPACE LIST", AdminCmd{Opcode: OpIdentify, CDW10: CNSActiveNamespace, DataLen: IdentifyBytes}, shortTimeout)
}

// SanitizeStatusLog is Get Log Page 81h (512 bytes).
func SanitizeStatusLog() Command {
	numd := uint32(SanitizeLogBytes/4 - 1) // zero-based dword count
	return cmd("GET LOG PAGE (SANITIZE STATUS)", AdminCmd{Opcode: OpGetLogPage, NSID: NSIDAll,
		CDW10: LogSanitize | (numd&0xffff)<<16, CDW11: numd >> 16, DataLen: SanitizeLogBytes}, shortTimeout)
}

// ErrArgs: a command argument out of range.
var ErrArgs = errors.New("bad NVMe command argument")

// FormatNVM formats namespace nsid with LBA format lbaf (kept as the namespace's current
// one by callers) and Secure Erase Setting ses (1 user data, 2 crypto). mset, pi and pil
// must repeat the namespace's current metadata and protection settings, so the format
// changes nothing but the data. The broadcast NSID is not accepted.
func FormatNVM(nsid uint32, lbaf int, ses int, mset bool, pi int, pil bool, timeout time.Duration) (Command, error) {
	switch {
	case nsid == 0 || nsid == NSIDAll:
		return Command{}, fmt.Errorf("%w: Format NVM needs one namespace, not %#x", ErrArgs, nsid)
	case lbaf < 0 || lbaf > 63:
		return Command{}, fmt.Errorf("%w: LBA format %d", ErrArgs, lbaf)
	case ses != SESUserData && ses != SESCryptoErs:
		return Command{}, fmt.Errorf("%w: secure erase setting %d (only 1 or 2)", ErrArgs, ses)
	case pi < 0 || pi > 7:
		return Command{}, fmt.Errorf("%w: protection type %d", ErrArgs, pi)
	}
	c := uint32(lbaf&0xf) | uint32(pi)<<5 | uint32(ses)<<9 | uint32(lbaf>>4)<<12
	if mset {
		c |= 1 << 4
	}
	if pil {
		c |= 1 << 8
	}
	name := "FORMAT NVM (user data erase)"
	if ses == SESCryptoErs {
		name = "FORMAT NVM (cryptographic erase)"
	}
	return cmd(name, AdminCmd{Opcode: OpFormatNVM, NSID: nsid, CDW10: c}, timeout), nil
}

// Sanitize starts a sanitize of the whole NVM subsystem. Overwrite uses passes (1–16)
// of pattern without inverting between passes. AUSE (auto-restart) and No-Deallocate
// are never set.
func Sanitize(action int, passes int, pattern uint32) (Command, error) {
	c := uint32(action)
	switch action {
	case SanactBlockErase, SanactCryptoErase:
	case SanactOverwrite:
		if passes < 1 || passes > 16 {
			return Command{}, fmt.Errorf("%w: overwrite passes %d", ErrArgs, passes)
		}
		c |= uint32(passes&0xf) << 4 // 16 passes is encoded as 0
	default:
		return Command{}, fmt.Errorf("%w: sanitize action %d", ErrArgs, action)
	}
	name := map[int]string{SanactBlockErase: "SANITIZE (block erase)", SanactCryptoErase: "SANITIZE (crypto erase)", SanactOverwrite: "SANITIZE (overwrite)"}[action]
	a := AdminCmd{Opcode: OpSanitize, CDW10: c}
	if action == SanactOverwrite {
		a.CDW11 = pattern
	}
	return cmd(name, a, shortTimeout), nil
}

// Status is the NVMe completion status field: SC 7:0, SCT 10:8, CRD 12:11, More 13,
// DNR 14.
type Status uint16

func (s Status) SC() uint8    { return uint8(s) }
func (s Status) SCT() uint8   { return uint8(s>>8) & 7 }
func (s Status) DNR() bool    { return s&0x4000 != 0 }
func (s Status) Code() uint16 { return uint16(s) & 0x7ff } // SCT and SC

// Known status codes (SCT<<8 | SC).
const (
	StatusInvalidOpcode      = 0x001
	StatusInvalidField       = 0x002
	StatusInvalidNamespace   = 0x00b
	StatusSanitizeFailed     = 0x01c
	StatusSanitizeInProgress = 0x01d
	StatusFormatInProgress   = 0x084
	StatusInvalidFormat      = 0x10a
)

var statusText = map[uint16]string{
	StatusInvalidOpcode:      "Invalid Command Opcode",
	StatusInvalidField:       "Invalid Field in Command",
	StatusInvalidNamespace:   "Invalid Namespace or Format",
	StatusSanitizeFailed:     "Sanitize Failed",
	StatusSanitizeInProgress: "Sanitize In Progress",
	StatusFormatInProgress:   "Format In Progress",
	StatusInvalidFormat:      "Invalid Format",
}

func (s Status) String() string {
	t := statusText[s.Code()]
	if t == "" {
		t = "status"
	}
	dnr := ""
	if s.DNR() {
		dnr = ", do not retry"
	}
	return fmt.Sprintf("%s (SCT %d SC %#02x%s)", t, s.SCT(), s.SC(), dnr)
}

// CommandError is a command the controller completed with a non-zero status.
type CommandError struct {
	Cmd    string
	Status Status
}

func (e *CommandError) Error() string { return e.Cmd + ": " + e.Status.String() }

// HasStatus reports whether err is a CommandError with code (SCT<<8 | SC).
func HasStatus(err error, code uint16) bool {
	var ce *CommandError
	return errors.As(err, &ce) && ce.Status.Code() == code
}
