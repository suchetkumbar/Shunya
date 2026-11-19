// Package winstorage decodes and encodes the Windows storage IOCTL structures Shunya
// uses: STORAGE_DEVICE_DESCRIPTOR, DISK_GEOMETRY_EX, STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR,
// DRIVE_LAYOUT_INFORMATION_EX, VOLUME_DISK_EXTENTS, the NVMe protocol-specific
// property query, and ATA_PASS_THROUGH_EX.
//
// Everything in this file set is plain byte handling with no build tag, so it is unit
// tested and fuzzed on Linux. Only sys_windows.go issues the IOCTLs. Layouts are those of
// 64-bit Windows (ULONG_PTR is 8 bytes); 32-bit Windows is not supported.
//
// Shunya has never been run against a physical disk on Windows: the developer's
// Windows machine is the host the safety rules protect, and no Windows VM was available
// (design/SAFETY.md). These decoders are tested against byte layouts built from the
// Windows SDK headers, not against real drivers.
package winstorage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

var le = binary.LittleEndian

// ErrShort: a structure is shorter than its fixed part or than its own size fields say.
var ErrShort = errors.New("winstorage: structure truncated")

// BusType is STORAGE_BUS_TYPE (ntddstor.h).
type BusType uint32

// STORAGE_BUS_TYPE values.
const (
	BusUnknown           BusType = 0x00
	BusSCSI              BusType = 0x01
	BusATAPI             BusType = 0x02
	BusATA               BusType = 0x03
	Bus1394              BusType = 0x04
	BusSSA               BusType = 0x05
	BusFibre             BusType = 0x06
	BusUSB               BusType = 0x07
	BusRAID              BusType = 0x08
	BusISCSI             BusType = 0x09
	BusSAS               BusType = 0x0A
	BusSATA              BusType = 0x0B
	BusSD                BusType = 0x0C
	BusMMC               BusType = 0x0D
	BusVirtual           BusType = 0x0E
	BusFileBackedVirtual BusType = 0x0F
	BusSpaces            BusType = 0x10
	BusNVMe              BusType = 0x11
	BusSCM               BusType = 0x12
	BusUFS               BusType = 0x13
)

var busNames = map[BusType]string{
	BusUnknown: "unknown", BusSCSI: "scsi", BusATAPI: "atapi", BusATA: "ata", Bus1394: "1394",
	BusSSA: "ssa", BusFibre: "fibre", BusUSB: "usb", BusRAID: "raid", BusISCSI: "iscsi",
	BusSAS: "sas", BusSATA: "sata", BusSD: "sd", BusMMC: "mmc", BusVirtual: "virtual",
	BusFileBackedVirtual: "file-backed-virtual", BusSpaces: "storage-spaces", BusNVMe: "nvme",
	BusSCM: "scm", BusUFS: "ufs",
}

func (b BusType) String() string {
	if s, ok := busNames[b]; ok {
		return s
	}
	return fmt.Sprintf("bus-%#x", uint32(b))
}

// DeviceDescriptor is the decoded STORAGE_DEVICE_DESCRIPTOR.
type DeviceDescriptor struct {
	DeviceType uint8 // SCSI peripheral device type (0 disk, 5 CD/DVD)
	Removable  bool
	Vendor     string
	Product    string
	Revision   string
	Serial     string
	Bus        BusType
}

// descriptorFixed is the size of STORAGE_DEVICE_DESCRIPTOR up to RawDeviceProperties.
const descriptorFixed = 36

// ParseDeviceDescriptor decodes the output of IOCTL_STORAGE_QUERY_PROPERTY with
// StorageDeviceProperty. String fields are offsets from the start of the structure to
// NUL-terminated ASCII; offset 0 means "not reported". Every offset is bounds-checked.
func ParseDeviceDescriptor(b []byte) (DeviceDescriptor, error) {
	var d DeviceDescriptor
	if len(b) < descriptorFixed {
		return d, fmt.Errorf("%w: STORAGE_DEVICE_DESCRIPTOR is %d bytes", ErrShort, len(b))
	}
	size := int(le.Uint32(b[4:]))
	if size < descriptorFixed {
		return d, fmt.Errorf("%w: STORAGE_DEVICE_DESCRIPTOR says it is %d bytes", ErrShort, size)
	}
	if size < len(b) {
		b = b[:size] // the driver says how much it filled; ignore the rest of the buffer
	}
	d.DeviceType = b[8]
	d.Removable = b[10] != 0
	d.Bus = BusType(le.Uint32(b[28:]))
	var err error
	str := func(at int) string {
		if err != nil {
			return ""
		}
		var s string
		s, err = cString(b, le.Uint32(b[at:]))
		return s
	}
	d.Vendor, d.Product, d.Revision, d.Serial = str(12), str(16), str(20), str(24)
	if err != nil {
		return DeviceDescriptor{}, err
	}
	return d, nil
}

// cString reads the NUL-terminated string at off (0: absent). Windows pads these fields
// with spaces; they are trimmed. A string without a terminator inside b is an error.
func cString(b []byte, off uint32) (string, error) {
	if off == 0 {
		return "", nil
	}
	if off < descriptorFixed || uint64(off) >= uint64(len(b)) {
		return "", fmt.Errorf("%w: string offset %d outside the %d-byte descriptor", ErrShort, off, len(b))
	}
	s := b[off:]
	n := 0
	for n < len(s) && s[n] != 0 {
		n++
	}
	if n == len(s) {
		return "", fmt.Errorf("%w: string at offset %d has no terminator", ErrShort, off)
	}
	for _, c := range s[:n] {
		if c < 0x20 || c > 0x7e {
			return "", fmt.Errorf("winstorage: string at offset %d is not printable ASCII", off)
		}
	}
	return strings.TrimSpace(string(s[:n])), nil
}

// Geometry is the decoded DISK_GEOMETRY_EX.
type Geometry struct {
	BytesPerSector uint32
	DiskSize       int64
}

// ParseGeometryEx decodes IOCTL_DISK_GET_DRIVE_GEOMETRY_EX output: DISK_GEOMETRY (24
// bytes: Cylinders, MediaType, TracksPerCylinder, SectorsPerTrack, BytesPerSector) then
// DiskSize (LARGE_INTEGER).
func ParseGeometryEx(b []byte) (Geometry, error) {
	if len(b) < 32 {
		return Geometry{}, fmt.Errorf("%w: DISK_GEOMETRY_EX is %d bytes", ErrShort, len(b))
	}
	g := Geometry{BytesPerSector: le.Uint32(b[20:]), DiskSize: int64(le.Uint64(b[24:]))}
	if g.DiskSize < 0 {
		return Geometry{}, fmt.Errorf("winstorage: negative disk size %d", g.DiskSize)
	}
	if !validSector(g.BytesPerSector) {
		return Geometry{}, fmt.Errorf("winstorage: %d bytes per sector", g.BytesPerSector)
	}
	return g, nil
}

func validSector(n uint32) bool { return n >= 512 && n <= 65536 && n&(n-1) == 0 }

// Alignment is the decoded STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR.
type Alignment struct {
	LogicalSector, PhysicalSector uint32
}

// ParseAccessAlignment decodes StorageAccessAlignmentProperty output: seven ULONGs
// (Version, Size, BytesPerCacheLine, BytesOffsetForCacheAlignment,
// BytesPerLogicalSector, BytesPerPhysicalSector, BytesOffsetForSectorAlignment).
func ParseAccessAlignment(b []byte) (Alignment, error) {
	if len(b) < 28 {
		return Alignment{}, fmt.Errorf("%w: STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR is %d bytes", ErrShort, len(b))
	}
	a := Alignment{LogicalSector: le.Uint32(b[16:]), PhysicalSector: le.Uint32(b[20:])}
	if !validSector(a.LogicalSector) || !validSector(a.PhysicalSector) || a.PhysicalSector < a.LogicalSector {
		return Alignment{}, fmt.Errorf("winstorage: sector sizes logical %d physical %d", a.LogicalSector, a.PhysicalSector)
	}
	return a, nil
}

// ParseSeekPenalty decodes StorageDeviceSeekPenaltyProperty output
// (DEVICE_SEEK_PENALTY_DESCRIPTOR: Version, Size, IncursSeekPenalty): true for a
// rotating disk.
func ParseSeekPenalty(b []byte) (bool, error) {
	if len(b) < 9 {
		return false, fmt.Errorf("%w: DEVICE_SEEK_PENALTY_DESCRIPTOR is %d bytes", ErrShort, len(b))
	}
	if s := le.Uint32(b[4:]); s < 9 || s > 64 {
		return false, fmt.Errorf("winstorage: seek penalty descriptor size %d", s)
	}
	return b[8] != 0, nil
}

// Extent is one DISK_EXTENT of a volume.
type Extent struct {
	Disk           uint32
	Offset, Length int64
}

// ParseDiskExtents decodes IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS output:
// NumberOfDiskExtents (ULONG, padded to 8) then DISK_EXTENT entries of 24 bytes
// (DiskNumber ULONG + pad, StartingOffset, ExtentLength).
func ParseDiskExtents(b []byte) ([]Extent, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("%w: VOLUME_DISK_EXTENTS is %d bytes", ErrShort, len(b))
	}
	n := uint64(le.Uint32(b))
	if n == 0 || n > 4096 || 8+24*n > uint64(len(b)) {
		return nil, fmt.Errorf("%w: %d extents in %d bytes", ErrShort, n, len(b))
	}
	out := make([]Extent, n)
	for i := range out {
		e := b[8+24*i:]
		out[i] = Extent{Disk: le.Uint32(e), Offset: int64(le.Uint64(e[8:])), Length: int64(le.Uint64(e[16:]))}
		if out[i].Offset < 0 || out[i].Length <= 0 {
			return nil, fmt.Errorf("winstorage: extent %d: offset %d length %d", i, out[i].Offset, out[i].Length)
		}
	}
	return out, nil
}

// Partition styles (PARTITION_STYLE).
const (
	StyleMBR = 0
	StyleGPT = 1
	StyleRAW = 2
)

// Layout is the decoded DRIVE_LAYOUT_INFORMATION_EX, reduced to what the guard needs.
type Layout struct {
	Style      uint32
	Partitions []Extent // used entries only (length > 0); Disk is the partition number
}

// layoutHeader: PartitionStyle, PartitionCount, then a 40-byte union (MBR or GPT info).
const (
	layoutHeader = 48
	partEntry    = 144 // PARTITION_INFORMATION_EX
)

// ParseDriveLayout decodes IOCTL_DISK_GET_DRIVE_LAYOUT_EX output. MBR layouts always
// list four primary slots; empty slots (length 0) are dropped.
func ParseDriveLayout(b []byte) (Layout, error) {
	if len(b) < layoutHeader {
		return Layout{}, fmt.Errorf("%w: DRIVE_LAYOUT_INFORMATION_EX is %d bytes", ErrShort, len(b))
	}
	l := Layout{Style: le.Uint32(b)}
	if l.Style > StyleRAW {
		return Layout{}, fmt.Errorf("winstorage: partition style %d", l.Style)
	}
	n := uint64(le.Uint32(b[4:]))
	if n > 1024 || layoutHeader+partEntry*n > uint64(len(b)) {
		return Layout{}, fmt.Errorf("%w: %d partition entries in %d bytes", ErrShort, n, len(b))
	}
	for i := range int(n) {
		e := b[layoutHeader+partEntry*i:]
		off, length := int64(le.Uint64(e[8:])), int64(le.Uint64(e[16:]))
		if off < 0 || length < 0 {
			return Layout{}, fmt.Errorf("winstorage: partition entry %d: offset %d length %d", i, off, length)
		}
		if length > 0 {
			l.Partitions = append(l.Partitions, Extent{Disk: le.Uint32(e[24:]), Offset: off, Length: length})
		}
	}
	return l, nil
}
