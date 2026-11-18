package backend

import (
	"errors"
	"fmt"

	"shunya/internal/nvme"
)

// ErrNVMeRefused: an NVMe admin command outside Shunya's allowlist.
var ErrNVMeRefused = errors.New("NVMe admin command refused by the backend allowlist")

// NVMeCommand is an allowed admin command, as the backend sees it.
type NVMeCommand struct {
	Name     string
	Mutating bool // Format NVM, Sanitize: need --execute
}

// CheckNVMe checks one admin command and its data buffer against the allowlist, on the
// raw fields (independently of internal/nvme's constructors). Allowed: Identify (CNS 0,
// 1, 2), Get Log Page (Sanitize Status only), Format NVM with a secure erase of one
// namespace, Sanitize (block, overwrite, crypto; no auto-restart, no no-deallocate).
// Refused: everything else — firmware download/commit, namespace management and
// attachment, Set Features, Security Send, Exit Failure Mode, vendor commands.
func CheckNVMe(c nvme.AdminCmd, data []byte) (NVMeCommand, error) {
	refuse := func(f string, a ...any) (NVMeCommand, error) {
		return NVMeCommand{}, fmt.Errorf("%w: %s", ErrNVMeRefused, fmt.Sprintf(f, a...))
	}
	if c.Addr != 0 || c.Metadata != 0 || c.MetadataLen != 0 || c.Flags != 0 || c.CDW2 != 0 || c.CDW3 != 0 {
		return refuse("opcode %#02x: address, metadata, flags or CDW2/3 set by the caller", c.Opcode)
	}
	if int(c.DataLen) != len(data) {
		return refuse("opcode %#02x: DataLen %d, buffer %d bytes", c.Opcode, c.DataLen, len(data))
	}
	switch c.Opcode {
	case nvme.OpIdentify:
		if c.DataLen != nvme.IdentifyBytes || c.CDW10&^0xff != 0 || c.CDW11|c.CDW12|c.CDW13|c.CDW14|c.CDW15 != 0 {
			return refuse("IDENTIFY with unusual fields")
		}
		switch c.CDW10 {
		case nvme.CNSNamespace, nvme.CNSController, nvme.CNSActiveNamespace:
		default:
			return refuse("IDENTIFY CNS %#02x", c.CDW10)
		}
		return NVMeCommand{Name: "IDENTIFY"}, nil
	case nvme.OpGetLogPage:
		if c.CDW10&0xff != nvme.LogSanitize || c.DataLen != nvme.SanitizeLogBytes || c.CDW10>>16 != nvme.SanitizeLogBytes/4-1 || c.CDW11 != 0 ||
			c.CDW10&0xff00 != 0 || c.CDW12|c.CDW13|c.CDW14|c.CDW15 != 0 {
			return refuse("GET LOG PAGE %#02x (only the Sanitize Status log, 81h)", c.CDW10&0xff)
		}
		return NVMeCommand{Name: "GET LOG PAGE (SANITIZE STATUS)"}, nil
	case nvme.OpFormatNVM:
		ses := c.CDW10 >> 9 & 7
		switch {
		case c.DataLen != 0:
			return refuse("FORMAT NVM with data")
		case c.NSID == 0 || c.NSID == nvme.NSIDAll:
			return refuse("FORMAT NVM of NSID %#x (one namespace only)", c.NSID)
		case ses != nvme.SESUserData && ses != nvme.SESCryptoErs:
			return refuse("FORMAT NVM with secure erase setting %d (only 1 or 2)", ses)
		case c.CDW10>>14 != 0 || c.CDW11|c.CDW12|c.CDW13|c.CDW14|c.CDW15 != 0:
			return refuse("FORMAT NVM with reserved fields set")
		}
		return NVMeCommand{Name: "FORMAT NVM", Mutating: true}, nil
	case nvme.OpSanitize:
		act := c.CDW10 & 7
		switch {
		case c.DataLen != 0 || c.NSID != 0:
			return refuse("SANITIZE with data or a namespace")
		case act != nvme.SanactBlockErase && act != nvme.SanactOverwrite && act != nvme.SanactCryptoErase:
			return refuse("SANITIZE action %d", act)
		case c.CDW10&(1<<3) != 0:
			return refuse("SANITIZE with auto-restart (AUSE)")
		case c.CDW10&(1<<9) != 0:
			return refuse("SANITIZE with No-Deallocate After Sanitize")
		case c.CDW10&(1<<8) != 0:
			return refuse("SANITIZE with overwrite pattern inversion")
		case c.CDW10>>10 != 0 || c.CDW12|c.CDW13|c.CDW14|c.CDW15 != 0:
			return refuse("SANITIZE with reserved fields set")
		case act != nvme.SanactOverwrite && (c.CDW10>>4&0xf != 0 || c.CDW11 != 0):
			return refuse("SANITIZE overwrite fields on a non-overwrite action")
		}
		return NVMeCommand{Name: "SANITIZE", Mutating: true}, nil
	}
	return refuse("admin opcode %#02x is not on the allowlist", c.Opcode)
}
