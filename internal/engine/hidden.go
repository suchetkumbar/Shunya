package engine

import (
	"errors"
	"fmt"

	"shunya/internal/ata"
	"shunya/internal/device"
)

// HPA policies: what happens to a temporarily removed HPA after the wipe.
const (
	HPARestore      = "restore"       // SET MAX back to the original size (volatile)
	HPALeaveRemoved = "leave-removed" // keep the full native size until the next power cycle
)

// HiddenPlan is the hidden-area part of a plan: the state found before the wipe and how
// the wipe handles it. Image files have none.
type HiddenPlan struct {
	Before ata.HiddenArea `json:"before"`
	// RemoveHPA: the HPA is removed with a volatile SET MAX for the wipe, and its
	// sectors are part of the plan's SizeBytes (wiped through ATA pass-through).
	RemoveHPA bool   `json:"remove_hpa,omitempty"`
	Policy    string `json:"hpa_policy,omitempty"`
	// VisibleBytes is the size the kernel's block device has.
	VisibleBytes int64 `json:"visible_bytes"`
	// NativeFingerprint (fp-v2) binds the native capacity as well.
	NativeFingerprint string `json:"native_fingerprint,omitempty"`
	// SolidState: IDENTIFY word 217 says non-rotating media. Overrides a sysfs "hdd".
	SolidState bool `json:"solid_state,omitempty"`
	// Security is the Security feature set state at planning (nil: not ATA).
	Security *ata.Security `json:"security,omitempty"`
	// KeepReason says why an HPA that was found is not removed and wiped.
	KeepReason string `json:"hpa_kept_reason,omitempty"`
}

func (h *HiddenPlan) validate(size int64, sector int) error {
	if h == nil {
		return nil
	}
	b := h.Before
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if h.Policy != "" && h.Policy != HPARestore && h.Policy != HPALeaveRemoved {
		bad("unknown HPA policy %q", h.Policy)
	}
	if b.Checked && b.SectorBytes != 0 && b.SectorBytes != sector {
		bad("IDENTIFY sector size %d, plan %d", b.SectorBytes, sector)
	}
	if h.RemoveHPA {
		switch {
		case !b.Checked || !b.HPA:
			bad("HPA removal planned but no HPA was found")
		case h.Policy == "":
			bad("HPA removal needs a policy")
		case size != int64(b.NativeSectors)*int64(sector):
			bad("plan size %d is not the native size %d × %d", size, b.NativeSectors, sector)
		case h.VisibleBytes != int64(b.ReportedSectors)*int64(sector):
			bad("visible size %d is not the reported size %d × %d", h.VisibleBytes, b.ReportedSectors, sector)
		}
	} else if h.VisibleBytes != 0 && size != h.VisibleBytes {
		bad("plan size %d differs from the visible size %d without HPA removal", size, h.VisibleBytes)
	}
	return errors.Join(errs...)
}

// HiddenFrom is the byte offset where the wiped hidden range starts (-1: none).
func (h *HiddenPlan) HiddenFrom() int64 {
	if h == nil || !h.RemoveHPA {
		return -1
	}
	return h.VisibleBytes
}

// methodLevel is the NIST SP 800-88 level a firmware erase earns. ATA Security Erase on
// a real rotating disk is Purge (SP 800-88 Rev. 1, Appendix A, ATA hard disk drives).
// On flash its effect is vendor-defined and cannot be checked from the host, so Shunya
// reports Clear (SP 800-88 relies on ATA SANITIZE or a verified crypto erase for SSD
// Purge). On a virtual disk the command reaches an emulation, not a medium.
func methodLevel(method string, media device.MediaType, virtual bool, h *HiddenPlan) Level {
	if method == MethodOverwrite {
		return LevelClear
	}
	if media == device.MediaHDD && !virtual && h != nil && !h.SolidState {
		return LevelPurge
	}
	return LevelClear
}

// notes are the plan's hidden-area disclosures.
func (h *HiddenPlan) notes(media device.MediaType) []string {
	if h == nil {
		if media == MediaImage {
			return nil
		}
		return []string{"Hidden areas (HPA/DCO) were not checked for this device: sectors behind a host protected area would not be overwritten."}
	}
	b := h.Before
	if !b.Checked {
		return []string{"Hidden areas (HPA/DCO) not checked: " + b.Reason + "."}
	}
	var n []string
	switch {
	case !b.HPASupported:
		n = append(n, "HPA: the drive does not support the Host Protected Area feature set, so none can exist.")
	case !b.HPA:
		n = append(n, fmt.Sprintf("HPA: none (IDENTIFY and READ NATIVE MAX ADDRESS agree on %d sectors).", b.NativeSectors))
	case h.RemoveHPA:
		after := "restored to the original size afterwards (volatile SET MAX)"
		if h.Policy == HPALeaveRemoved {
			after = "left removed afterwards; it returns at the next power cycle"
		}
		n = append(n, fmt.Sprintf("HPA: %d sectors hidden beyond the reported %d. They are made addressable with a volatile SET MAX ADDRESS (lost at power-off, never permanent), included in this wipe, and the HPA is %s.",
			b.HPASectors(), b.ReportedSectors, after))
	default:
		why := h.KeepReason
		if why == "" {
			why = "the HPA could not be removed"
		}
		n = append(n, fmt.Sprintf("HPA: %d sectors hidden and NOT wiped (%s). The result covers sectors 0–%d only.", b.HPASectors(), why, b.ReportedSectors-1))
	}
	switch b.DCO {
	case ata.DCOPresent:
		n = append(n, fmt.Sprintf("DCO: the Device Configuration Overlay hides %d sectors beyond the native maximum (factory size %d sectors). Shunya never changes a DCO (the change is permanent), so those sectors are NOT wiped and the result covers the first %d sectors only.",
			b.DCOHiddenSectors(), b.DCOSectors, b.NativeSectors))
	case ata.DCOUnavailable:
		n = append(n, "DCO: state unknown — the drive refused DEVICE CONFIGURATION IDENTIFY (usually a DCO freeze lock from the BIOS). Sectors hidden by a DCO, if any, are not wiped.")
	case ata.DCOAbsent:
		n = append(n, "DCO: no restriction (the factory size equals the native size).")
	default:
		n = append(n, "DCO: the drive does not support the Device Configuration Overlay.")
	}
	return n
}
