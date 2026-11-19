package device

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"shunya/internal/winstorage"
)

// WinDisk is what Windows reports about one \\.\PhysicalDriveN: the raw outputs of the
// storage IOCTLs (decoded here, so this logic is tested on any OS). A nil field means
// the IOCTL failed; required ones make enumeration fail closed.
type WinDisk struct {
	Number      uint32
	Descriptor  []byte // StorageDeviceProperty (required)
	Geometry    []byte // IOCTL_DISK_GET_DRIVE_GEOMETRY_EX (required)
	Layout      []byte // IOCTL_DISK_GET_DRIVE_LAYOUT_EX (required)
	Alignment   []byte // StorageAccessAlignmentProperty (optional)
	SeekPenalty []byte // StorageDeviceSeekPenaltyProperty (optional)
	ReadOnly    bool   // IOCTL_DISK_IS_WRITABLE said write-protected
}

// WinVolume is one volume (\\?\Volume{…}\) and what it is used for.
type WinVolume struct {
	Name    string
	Mounts  []string // drive letters and folder mount points
	Extents []byte   // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS; nil if it failed
	// Why the system depends on it (each makes the disks under it PROTECTED):
	System   bool // holds %SystemRoot%
	Boot     bool // the EFI system / boot partition
	Exe      bool // holds the running shunya.exe
	Pagefile bool // holds a paging file
}

// EnumerateWindows builds the report from Windows' answers. Windows has no equivalent of
// /proc/*/mountinfo for every namespace, so it errs further towards caution than Linux:
// a disk with partitions but no volume Windows can see (a locked BitLocker volume, a
// foreign file system, a dynamic disk) is IN-USE, not AVAILABLE.
func EnumerateWindows(sys System, disks []WinDisk, vols []WinVolume) (*Report, error) {
	rep := &Report{System: sys}
	byNum := map[uint32]*Device{}
	seen := map[uint32]bool{}
	for _, w := range disks {
		if seen[w.Number] {
			return nil, fmt.Errorf("PhysicalDrive%d listed twice", w.Number)
		}
		seen[w.Number] = true
		d, err := winDevice(w)
		if err != nil {
			// A disk Windows describes in a way we cannot decode is left out: it is never
			// offered for wiping, and nothing on it needs protecting from Shunya.
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("PhysicalDrive%d left out: %v", w.Number, err))
			continue
		}
		byNum[w.Number] = d
	}
	volumesOn := map[uint32]int{}
	for _, v := range vols {
		where := v.Name
		if len(v.Mounts) > 0 {
			where = strings.Join(v.Mounts, ", ")
		}
		if v.Extents == nil {
			// We cannot tell which disk holds it; if it matters to the system, no disk can
			// be trusted to be free of it.
			if v.System || v.Boot || v.Exe || v.Pagefile {
				return nil, fmt.Errorf("volume %s is used by the system but Windows did not say which disk holds it", where)
			}
			rep.Warnings = append(rep.Warnings, "volume "+where+": disk extents unavailable; its disk could not be identified")
			continue
		}
		ex, err := winstorage.ParseDiskExtents(v.Extents)
		if err != nil {
			return nil, fmt.Errorf("volume %s: %w", where, err)
		}
		var roles []string
		if v.System {
			roles = append(roles, "Windows system volume "+where)
		}
		if v.Boot {
			roles = append(roles, "boot volume "+where)
		}
		if v.Exe {
			roles = append(roles, "holds the running shunya.exe ("+where+")")
		}
		if v.Pagefile {
			roles = append(roles, "paging file on "+where)
		}
		for _, e := range ex {
			d := byNum[e.Disk]
			if d == nil {
				if len(roles) > 0 && !seen[e.Disk] {
					return nil, fmt.Errorf("volume %s lies on PhysicalDrive%d, which was not enumerated", where, e.Disk)
				}
				continue
			}
			volumesOn[e.Disk]++
			if len(roles) > 0 {
				d.Status = StatusProtected
				for _, r := range roles {
					d.Reasons = appendUnique(d.Reasons, r)
				}
				continue
			}
			d.Reasons = appendUnique(d.Reasons, "mounted at "+where)
			d.Mounts = append(d.Mounts, MountRef{MountPoint: where, Source: v.Name})
			if d.Status != StatusProtected {
				d.Status = StatusInUse
			}
		}
	}
	for _, n := range slices.Sorted(maps.Keys(byNum)) {
		d := byNum[n]
		if d.Status == "" && len(d.Partitions) > 0 && volumesOn[n] == 0 {
			d.Status = StatusInUse
			d.Reasons = append(d.Reasons, fmt.Sprintf("has %d partition(s) but no volume Windows can see (locked BitLocker, foreign file system, dynamic disk …): remove the partitions in Disk Management first", len(d.Partitions)))
		}
		if d.Status == "" {
			d.Status = StatusAvailable
		}
		markHypervisor(d, rep.System)
		rep.Devices = append(rep.Devices, *d)
	}
	rep.Warnings = append(rep.Warnings, "Windows: volumes are matched to disks through their extents; "+
		"Shunya on Windows lists and identifies disks only and refuses to write to them (boot the Shunya live image to wipe).")
	return rep, nil
}

func winTransport(b winstorage.BusType) Transport {
	switch b {
	case winstorage.BusNVMe:
		return TransportNVMe
	case winstorage.BusATA, winstorage.BusSATA, winstorage.BusATAPI:
		return TransportSATA
	case winstorage.BusSAS:
		return TransportSAS
	case winstorage.BusSCSI, winstorage.BusISCSI, winstorage.BusFibre:
		return TransportSCSI
	case winstorage.BusUSB:
		return TransportUSB
	case winstorage.BusSD, winstorage.BusMMC:
		return TransportMMC
	case winstorage.BusSpaces, winstorage.BusRAID:
		return TransportMD
	case winstorage.BusVirtual, winstorage.BusFileBackedVirtual:
		return TransportLoop
	}
	return TransportUnknown
}

func winDevice(w WinDisk) (*Device, error) {
	if w.Descriptor == nil || w.Geometry == nil || w.Layout == nil {
		return nil, fmt.Errorf("storage descriptor, geometry or partition layout unavailable")
	}
	desc, err := winstorage.ParseDeviceDescriptor(w.Descriptor)
	if err != nil {
		return nil, err
	}
	geo, err := winstorage.ParseGeometryEx(w.Geometry)
	if err != nil {
		return nil, err
	}
	lay, err := winstorage.ParseDriveLayout(w.Layout)
	if err != nil {
		return nil, err
	}
	name := "PhysicalDrive" + strconv.FormatUint(uint64(w.Number), 10)
	d := &Device{
		Name: name, Path: `\\.\` + name, SysPath: `\\.\` + name, DevNum: "disk " + strconv.FormatUint(uint64(w.Number), 10),
		SizeBytes: uint64(geo.DiskSize), LogicalSectorSize: geo.BytesPerSector, PhysicalSectorSize: geo.BytesPerSector,
		Removable: desc.Removable, ReadOnly: w.ReadOnly, Transport: winTransport(desc.Bus),
		Vendor: desc.Vendor, Model: strings.TrimSpace(desc.Vendor + " " + desc.Product), Serial: desc.Serial,
		Firmware: desc.Revision, typeHint: strconv.Itoa(int(desc.DeviceType)),
	}
	if desc.Vendor == "" || desc.Bus == winstorage.BusNVMe || desc.Bus == winstorage.BusATA || desc.Bus == winstorage.BusSATA {
		d.Model = desc.Product // StorNVMe/storahci report "NVMe"/"ATA" or nothing as the vendor
	}
	if d.Serial != "" {
		d.SerialSource = "STORAGE_DEVICE_DESCRIPTOR"
	}
	if w.Alignment != nil {
		if a, err := winstorage.ParseAccessAlignment(w.Alignment); err == nil && a.LogicalSector == geo.BytesPerSector {
			d.PhysicalSectorSize = a.PhysicalSector
		}
	}
	rotKnown := false
	if w.SeekPenalty != nil {
		if rot, err := winstorage.ParseSeekPenalty(w.SeekPenalty); err == nil {
			d.Rotational, rotKnown = rot, true
		}
	}
	for _, p := range lay.Partitions {
		d.Partitions = append(d.Partitions, Partition{
			Name: fmt.Sprintf("%s partition %d", name, p.Disk), Number: uint64(p.Disk),
			StartSector: uint64(p.Offset) / 512, SizeBytes: uint64(p.Length),
		})
	}
	d.Media = classify(d)
	switch d.Transport {
	case TransportSATA, TransportSAS, TransportSCSI:
		if d.Media.Type == MediaOptical {
			break
		}
		r := d.Media.Reasons[:0:0]
		for _, s := range d.Media.Reasons {
			if !strings.Contains(s, "queue/rotational") {
				r = append(r, s)
			}
		}
		if rotKnown {
			r = append(r, "Windows seek-penalty property: incurs seek penalty="+boolDigit(d.Rotational))
		} else {
			d.Media.Confidence = Low
			r = append(r, "Windows did not report a seek penalty: SSD or HDD unknown")
		}
		d.Media.Reasons = r
	case TransportMD:
		d.Media.Reasons = []string{"Storage Spaces or RAID virtual disk, not a physical medium"}
	case TransportLoop:
		d.Media.Reasons = []string{"virtual disk (VHD/VHDX) attached by Windows, not a physical medium"}
	}
	switch {
	case d.Media.Type == MediaOptical:
		d.Status, d.Reasons = StatusIgnored, []string{"optical drive"}
	case d.Transport == TransportMD:
		d.Status, d.Reasons = StatusIgnored, []string{"logical device: wipe the underlying disks instead"}
	case d.Transport == TransportLoop:
		d.Status, d.Reasons = StatusIgnored, []string{"virtual disk: wipe the backing file instead"}
	}
	d.Fingerprint = ComputeFingerprint(FingerprintInput{
		Model: d.Model, Serial: d.Serial, WWID: d.WWID, Firmware: d.Firmware, CapacityBytes: d.SizeBytes,
	})
	return d, nil
}
