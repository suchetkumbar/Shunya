package device

import (
	"path"
	"regexp"
	"strings"

	"shunya/internal/sysfs"
)

var (
	reATAPort  = regexp.MustCompile(`^ata\d+$`)
	reUSBBus   = regexp.MustCompile(`^usb\d+$`)
	reVirtio   = regexp.MustCompile(`^virtio\d+$`)
	reSCSIHost = regexp.MustCompile(`^host\d+$`)
)

// detectTransport works out the bus from the device's resolved sysfs path, e.g.
//
//	sys/devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda → sata
//	sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/host6/…/block/sdc        → usb
//
// The path is more trustworthy than names (sdX is used by SATA, SAS, USB and Hyper-V
// alike). Order matters: a USB-SATA bridge has no ataN element but a usbN one, and a
// SAS controller has neither.
func detectTransport(name, devPath string, r *sysfs.Reader) Transport {
	switch {
	case strings.HasPrefix(name, "loop"):
		return TransportLoop
	case strings.HasPrefix(name, "dm-"):
		return TransportDM
	case strings.HasPrefix(name, "md"):
		return TransportMD
	case strings.HasPrefix(name, "ram"), strings.HasPrefix(name, "zram"):
		return TransportRAM
	}
	parts := strings.Split(devPath, "/")
	has := func(re *regexp.Regexp) bool {
		for _, p := range parts {
			if re.MatchString(p) {
				return true
			}
		}
		return false
	}
	hasElem := func(e string) bool {
		for _, p := range parts {
			if p == e {
				return true
			}
		}
		return false
	}
	switch {
	case hasElem("nvme") || hasElem("nvme-subsystem") || strings.HasPrefix(name, "nvme"):
		return TransportNVMe
	case has(reUSBBus):
		return TransportUSB
	case has(reATAPort):
		return TransportSATA
	case hasElem("mmc_host") || strings.HasPrefix(name, "mmcblk"):
		return TransportMMC
	case has(reVirtio):
		return TransportVirtio
	case strings.Contains(devPath, "/MSFT1000:") || strings.Contains(devPath, "/VMBUS:"):
		return TransportHyperV
	case has(reSCSIHost):
		if r.Exists(devPath+"/device/sas_address") || strings.Contains(devPath, "/end_device-") {
			return TransportSAS
		}
		return TransportSCSI
	}
	return TransportUnknown
}

// readIdentity fills vendor, model, serial, firmware and WWID from the attributes each
// subsystem exposes. On SATA these come from the SCSI translation layer (libata's
// INQUIRY emulation), so the model is cut to 16 characters and firmware to 4; the full
// ATA IDENTIFY strings arrive in Milestone 5.
func readIdentity(d *Device, r *sysfs.Reader, devPath string) {
	dev := devPath + "/device"
	switch d.Transport {
	case TransportNVMe:
		// nvme0n1/device is the controller (nvme0); wwid lives on the namespace.
		d.Model = r.String(dev + "/model")
		d.Serial, d.SerialSource = r.String(dev+"/serial"), "nvme controller"
		d.Firmware = r.String(dev + "/firmware_rev")
		d.WWID = r.String(devPath + "/wwid")
	case TransportVirtio:
		d.Serial, d.SerialSource = r.String(devPath+"/serial"), "virtio-blk serial"
	case TransportMMC:
		d.Model = r.String(dev + "/name")
		d.Serial, d.SerialSource = r.String(dev+"/serial"), "mmc cid serial"
		d.Firmware = r.String(dev + "/fwrev")
		if cid := r.String(dev + "/cid"); cid != "" {
			d.WWID = "cid." + cid
		}
	case TransportSATA, TransportSAS, TransportSCSI, TransportUSB, TransportHyperV, TransportUnknown:
		d.Vendor = r.String(dev + "/vendor")
		d.Model = r.String(dev + "/model")
		d.Firmware = r.String(dev + "/rev")
		d.WWID = r.String(dev + "/wwid")
		if b, err := r.Bytes(dev + "/vpd_pg80"); err == nil {
			if s, err := sysfs.ParseVPD80(b); err == nil && s != "" {
				d.Serial, d.SerialSource = s, "scsi vpd page 0x80"
			}
		}
		if d.Serial == "" && d.Transport == TransportUSB {
			if s := usbSerial(r, devPath); s != "" {
				d.Serial, d.SerialSource = s, "usb device descriptor (bridge)"
			}
		}
	}
}

// usbSerial walks up from the block device to the USB device directory (the first
// ancestor with an idVendor file) and returns its iSerial string. Note this is the
// serial of the USB bridge or stick, not of a drive inside an enclosure.
func usbSerial(r *sysfs.Reader, devPath string) string {
	for p := devPath; p != "." && p != "sys/devices" && p != "/"; p = path.Dir(p) {
		if r.Exists(p + "/idVendor") {
			return r.String(p + "/serial")
		}
	}
	return ""
}
