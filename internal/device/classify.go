package device

import "strings"

// classify decides the media type from transport and sysfs hints, and says how sure it
// is. It errs towards lower confidence: the planner (Milestone 3) must not claim Purge
// for a device whose medium it cannot establish.
func classify(d *Device) Media {
	m := Media{Confidence: High}
	why := func(s string) { m.Reasons = append(m.Reasons, s) }

	if v := virtualHint(d); v != "" {
		m.Virtual = true
		why(v)
	}

	switch d.Transport {
	case TransportLoop, TransportDM, TransportMD, TransportRAM:
		m.Type = MediaLogical
		why("kernel " + string(d.Transport) + " device, not a physical medium")
	case TransportNVMe:
		m.Type = MediaNVMeSSD
		why("NVMe namespace")
	case TransportVirtio:
		m.Type = MediaVirtual
		m.Virtual = true
		why("virtio-blk: paravirtual disk, backing medium unknown to the guest")
	case TransportHyperV:
		m.Type = MediaVirtual
		m.Virtual = true
		why("Hyper-V storvsc disk: backing medium unknown to the guest")
	case TransportMMC:
		switch t := d.typeHint; t {
		case "MMC":
			m.Type = MediaEMMC
			why("mmc card type MMC (eMMC)")
		case "SD":
			m.Type = MediaSDCard
			why("mmc card type SD")
		default:
			m.Type, m.Confidence = MediaEMMC, Low
			why("mmc device with unknown card type " + quote(t))
		}
	case TransportUSB:
		// usb-storage marks most devices rotational regardless of what is inside, so the
		// flag says little. Removable media bit is a better hint for sticks/card readers.
		m.Confidence = Medium
		if d.Removable {
			m.Type = MediaUSBFlash
			why("USB mass storage with removable-media bit: flash stick or card reader")
		} else {
			m.Type = MediaUSBDisk
			why("USB mass storage without removable-media bit: likely a drive in an enclosure")
		}
		why("USB bridges hide the device type and often misreport rotation")
	case TransportSATA, TransportSAS, TransportSCSI:
		if d.typeHint == "5" { // SCSI peripheral type 5 = CD/DVD
			m.Type = MediaOptical
			why("SCSI peripheral type 5 (CD/DVD)")
			break
		}
		if d.Rotational {
			m.Type = MediaHDD
		} else {
			m.Type = MediaSSD
		}
		switch d.Transport {
		case TransportSATA:
			why("ATA IDENTIFY nominal rotation rate via queue/rotational=" + boolDigit(d.Rotational))
		case TransportSAS:
			why("SCSI VPD 0xB1 rotation rate via queue/rotational=" + boolDigit(d.Rotational))
		default:
			m.Confidence = Medium
			why("SCSI device of unidentified transport; queue/rotational=" + boolDigit(d.Rotational))
		}
	default:
		m.Type, m.Confidence = MediaUnknown, Low
		why("unrecognised transport")
	}
	return m
}

// virtualHint returns a reason if identity strings show an emulated device.
func virtualHint(d *Device) string {
	id := strings.ToUpper(d.Vendor + " " + d.Model)
	for _, s := range []string{"QEMU", "VBOX", "VMWARE", "MSFT VIRTUAL", "VIRTUAL DISK"} {
		if strings.Contains(id, s) {
			return "identity " + quote(strings.TrimSpace(d.Vendor+" "+d.Model)) + " is an emulated device"
		}
	}
	return ""
}

func boolDigit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func quote(s string) string { return "\"" + s + "\"" }
