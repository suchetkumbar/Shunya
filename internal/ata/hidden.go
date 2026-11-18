package ata

import (
	"context"
	"errors"
	"fmt"
)

// DCO states.
const (
	DCONotSupported = "not-supported" // IDENTIFY word 83 bit 11 clear
	DCOAbsent       = "absent"        // DCO maximum equals the native maximum
	DCOPresent      = "present"       // DCO hides sectors beyond the native maximum
	DCOUnavailable  = "unavailable"   // DCO IDENTIFY aborted (frozen by the BIOS, or not really supported)
)

// HiddenArea is what IDENTIFY, READ NATIVE MAX ADDRESS EXT and DCO IDENTIFY say about
// sectors the host cannot see. It goes into the plan, the journal and (Milestone 7) the
// certificate, before and after the wipe.
type HiddenArea struct {
	Checked bool `json:"checked"` // the ATA commands ran; false: see Reason
	// Reason explains why the hidden areas were not (fully) checked.
	Reason          string `json:"reason,omitempty"`
	ReportedSectors uint64 `json:"reported_sectors"` // IDENTIFY: user-addressable now
	NativeSectors   uint64 `json:"native_sectors"`   // READ NATIVE MAX + 1 (= reported without HPA support)
	HPASupported    bool   `json:"hpa_supported"`
	HPA             bool   `json:"hpa"` // native > reported
	DCO             string `json:"dco"`
	DCOSectors      uint64 `json:"dco_sectors,omitempty"` // DCO maximum LBA + 1
	SectorBytes     int    `json:"sector_bytes"`
}

// HPASectors is the number of sectors an HPA hides.
func (h HiddenArea) HPASectors() uint64 {
	if h.NativeSectors > h.ReportedSectors {
		return h.NativeSectors - h.ReportedSectors
	}
	return 0
}

// DCOHiddenSectors is the number of sectors a DCO hides beyond the native maximum.
func (h HiddenArea) DCOHiddenSectors() uint64 {
	if h.DCO == DCOPresent && h.DCOSectors > h.NativeSectors {
		return h.DCOSectors - h.NativeSectors
	}
	return 0
}

// Summary is a one-line description.
func (h HiddenArea) Summary() string {
	if !h.Checked {
		return "not checked: " + h.Reason
	}
	s := "no HPA"
	switch {
	case !h.HPASupported:
		s = "HPA not supported"
	case h.HPA:
		s = fmt.Sprintf("HPA hides %d sectors (reported %d, native %d)", h.HPASectors(), h.ReportedSectors, h.NativeSectors)
	}
	switch h.DCO {
	case DCOPresent:
		s += fmt.Sprintf("; DCO hides %d sectors beyond native (DCO max %d)", h.DCOHiddenSectors(), h.DCOSectors)
	case DCOAbsent:
		s += "; no DCO restriction"
	case DCOUnavailable:
		s += "; DCO IDENTIFY refused (state unknown)"
	default:
		s += "; DCO not supported"
	}
	return s
}

// ErrNo48Bit: HPA handling needs the 48-bit commands; 28-bit-only drives (pre-2003)
// are reported, not handled.
var ErrNo48Bit = errors.New("drive lacks 48-bit addressing; HPA commands not supported by Shunya")

// ProbeHidden reads the hidden-area state. All three commands are read-only.
func ProbeHidden(ctx context.Context, d Device, id *Identify) (HiddenArea, error) {
	h := HiddenArea{Checked: true, ReportedSectors: id.Sectors(), NativeSectors: id.Sectors(),
		HPASupported: id.HPASupported, DCO: DCONotSupported, SectorBytes: id.LogicalSectorBytes}
	if id.HPASupported {
		if !id.Supports48 {
			return HiddenArea{Reason: ErrNo48Bit.Error(), ReportedSectors: id.Sectors(), SectorBytes: id.LogicalSectorBytes}, nil
		}
		native, err := readNativeMax(ctx, d)
		if err != nil {
			return HiddenArea{}, err
		}
		h.NativeSectors = native
		h.HPA = native > h.ReportedSectors
		if native < h.ReportedSectors {
			return HiddenArea{}, fmt.Errorf("native max %d below reported size %d: inconsistent drive", native, h.ReportedSectors)
		}
	}
	if id.DCOSupported {
		buf := make([]byte, SectorBytes)
		_, err := d.Exec(ctx, DCOIdentify(), buf)
		switch {
		case Aborted(err):
			h.DCO = DCOUnavailable
		case err != nil:
			return HiddenArea{}, err
		default:
			dco, err := ParseDCO(buf)
			if err != nil {
				return HiddenArea{}, err
			}
			h.DCOSectors = dco.MaxSectors
			h.DCO = DCOAbsent
			if dco.MaxSectors > h.NativeSectors {
				h.DCO = DCOPresent
			}
		}
	}
	return h, nil
}

func readNativeMax(ctx context.Context, d Device) (uint64, error) {
	r, err := d.Exec(ctx, ReadNativeMaxExt(), nil)
	if err != nil {
		return 0, err
	}
	return r.LBA + 1, nil
}

// SetMaxVolatile makes sectors the drive's user-addressable size until the next power
// cycle: READ NATIVE MAX ADDRESS EXT immediately followed by SET MAX ADDRESS EXT with
// the volatile bit, then IDENTIFY to confirm. sectors must not exceed the native size.
func SetMaxVolatile(ctx context.Context, d Device, sectors uint64) error {
	native, err := readNativeMax(ctx, d)
	if err != nil {
		return err
	}
	if sectors == 0 || sectors > native {
		return fmt.Errorf("SET MAX to %d sectors: native size is %d", sectors, native)
	}
	c, err := SetMaxAddressExtVolatile(sectors - 1)
	if err != nil {
		return err
	}
	if _, err := d.Exec(ctx, c, nil); err != nil {
		if Aborted(err) {
			return fmt.Errorf("%w (many drives accept only one SET MAX per power cycle)", err)
		}
		return err
	}
	id, _, err := d.Identify(ctx)
	if err != nil {
		return err
	}
	if id.Sectors() != sectors {
		return fmt.Errorf("SET MAX to %d sectors: IDENTIFY now reports %d", sectors, id.Sectors())
	}
	return nil
}
