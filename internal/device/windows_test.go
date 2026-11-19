package device

import (
	"encoding/binary"
	"strings"
	"testing"

	"shunya/internal/winstorage"
)

var le = binary.LittleEndian

// The fixtures below are laid out as in the Windows SDK headers (see the winstorage
// tests); they are synthetic: Shunya has not been run on a Windows machine's disks.

func winDescriptor(devType uint8, removable bool, bus winstorage.BusType, vendor, product, rev, serial string) []byte {
	b := make([]byte, 36)
	var tail []byte
	for i, s := range []string{vendor, product, rev, serial} {
		if s == "" {
			continue
		}
		le.PutUint32(b[12+4*i:], uint32(36+len(tail)))
		tail = append(append(tail, s...), 0)
	}
	b = append(b, tail...)
	le.PutUint32(b[0:], 36)
	le.PutUint32(b[4:], uint32(len(b)))
	b[8] = devType
	if removable {
		b[10] = 1
	}
	le.PutUint32(b[28:], uint32(bus))
	return b
}

func winGeometry(size int64, sector uint32) []byte {
	b := make([]byte, 32)
	le.PutUint32(b[20:], sector)
	le.PutUint64(b[24:], uint64(size))
	return b
}

func winLayout(parts int) []byte {
	b := make([]byte, 48+144*parts)
	le.PutUint32(b, winstorage.StyleGPT)
	le.PutUint32(b[4:], uint32(parts))
	for i := range parts {
		e := b[48+144*i:]
		le.PutUint64(e[8:], uint64(i+1)<<20)
		le.PutUint64(e[16:], 1<<30)
		le.PutUint32(e[24:], uint32(i+1))
	}
	return b
}

func winExtents(disks ...uint32) []byte {
	b := make([]byte, 8+24*len(disks))
	le.PutUint32(b, uint32(len(disks)))
	for i, d := range disks {
		le.PutUint32(b[8+24*i:], d)
		le.PutUint64(b[8+24*i+8:], 1<<20)
		le.PutUint64(b[8+24*i+16:], 1<<30)
	}
	return b
}

func seek(rot bool) []byte {
	b := make([]byte, 12)
	le.PutUint32(b, 12)
	le.PutUint32(b[4:], 12)
	if rot {
		b[8] = 1
	}
	return b
}

func align(logical, physical uint32) []byte {
	b := make([]byte, 28)
	for i, v := range []uint32{28, 28, 64, 0, logical, physical, 0} {
		le.PutUint32(b[4*i:], v)
	}
	return b
}

func winWorkstation() ([]WinDisk, []WinVolume) {
	disks := []WinDisk{
		{Number: 0, Descriptor: winDescriptor(0, false, winstorage.BusNVMe, "", "Samsung SSD 980 PRO 1TB", "5B2QGXA7", "0025_38B5_11A2_C3D4."),
			Geometry: winGeometry(1000204886016, 512), Layout: winLayout(4), Alignment: align(512, 512), SeekPenalty: seek(false)},
		{Number: 1, Descriptor: winDescriptor(0, false, winstorage.BusSATA, "", "CT500MX500SSD1", "M3CR046", "2117E1A2B3C4"),
			Geometry: winGeometry(500107862016, 512), Layout: winLayout(1), Alignment: align(512, 4096), SeekPenalty: seek(false)},
		{Number: 2, Descriptor: winDescriptor(0, true, winstorage.BusUSB, "SanDisk", "Cruzer Blade", "1.00", "4C530001230616118063"),
			Geometry: winGeometry(15376318464, 512), Layout: winLayout(0)},
		{Number: 3, Descriptor: winDescriptor(0, false, winstorage.BusSATA, "", "WDC WD20EZRZ-00Z5HB0", "80.00A80", "WD-WCC4M1ABCDEF"),
			Geometry: winGeometry(2000398934016, 512), Layout: winLayout(2), SeekPenalty: seek(true)},
		{Number: 4, Descriptor: winDescriptor(0, false, winstorage.BusSpaces, "Microsoft", "Storage Space", "0.1", "{8f3c1a2b}"),
			Geometry: winGeometry(4<<40, 512), Layout: winLayout(1)},
		{Number: 5, Descriptor: winDescriptor(0, false, winstorage.BusSATA, "", "ST1000DM010-2EP102", "CC46", "Z9A1B2C3"),
			Geometry: winGeometry(1000204886016, 512), Layout: winLayout(0)},
	}
	vols := []WinVolume{
		{Name: `\\?\Volume{a}\`, Mounts: []string{`C:\`}, Extents: winExtents(0), System: true, Exe: true, Pagefile: true},
		{Name: `\\?\Volume{b}\`, Extents: winExtents(0), Boot: true},
		{Name: `\\?\Volume{c}\`, Mounts: []string{`D:\`}, Extents: winExtents(1)},
		{Name: `\\?\Volume{d}\`, Mounts: []string{`E:\`}, Extents: winExtents(4)},
	}
	return disks, vols
}

func TestEnumerateWindows(t *testing.T) {
	disks, vols := winWorkstation()
	r, err := EnumerateWindows(System{DMIVendor: "Dell Inc.", DMIProduct: "XPS 15 9520"}, disks, vols)
	if err != nil {
		t.Fatal(err)
	}
	checkDevices(t, r, map[string]want{
		"PhysicalDrive0": {transport: TransportNVMe, media: MediaNVMeSSD, confidence: High, status: StatusProtected,
			reasons: []string{`Windows system volume C:\`, `holds the running shunya.exe (C:\)`, `paging file on C:\`, `boot volume \\?\Volume{b}\`},
			model:   "Samsung SSD 980 PRO 1TB", serial: "0025_38B5_11A2_C3D4.", firmware: "5B2QGXA7", sizeBytes: 1000204886016,
			partitions: []string{"PhysicalDrive0 partition 1", "PhysicalDrive0 partition 2", "PhysicalDrive0 partition 3", "PhysicalDrive0 partition 4"}},
		"PhysicalDrive1": {transport: TransportSATA, media: MediaSSD, confidence: High, status: StatusInUse,
			reasons: []string{`mounted at D:\`}, physSector: 4096},
		"PhysicalDrive2": {transport: TransportUSB, media: MediaUSBFlash, confidence: Medium, status: StatusAvailable,
			model: "SanDisk Cruzer Blade", serial: "4C530001230616118063", removable: true, partitions: []string{}},
		"PhysicalDrive3": {transport: TransportSATA, media: MediaHDD, confidence: High, status: StatusInUse,
			reasons: []string{"has 2 partition(s) but no volume Windows can see"}},
		// As on Linux, a mounted logical device is IN-USE (its volume is in use).
		"PhysicalDrive4": {transport: TransportMD, media: MediaLogical, status: StatusInUse,
			reasons: []string{"logical device", `mounted at E:\`}},
		// No seek-penalty answer: SSD or HDD unknown, said plainly with low confidence.
		"PhysicalDrive5": {transport: TransportSATA, media: MediaSSD, confidence: Low, status: StatusAvailable, partitions: []string{}},
	})
	for _, d := range r.Devices {
		if d.Path != `\\.\`+d.Name {
			t.Errorf("%s: path %q", d.Name, d.Path)
		}
		for _, m := range d.Media.Reasons {
			if strings.Contains(m, "queue/rotational") {
				t.Errorf("%s: Linux wording in a Windows reason: %q", d.Name, m)
			}
		}
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), "refuses to write") {
		t.Errorf("warnings %q", r.Warnings)
	}
}

func TestEnumerateWindowsFailsClosed(t *testing.T) {
	cases := map[string]func([]WinDisk, []WinVolume) ([]WinDisk, []WinVolume){
		"system volume without extents": func(d []WinDisk, v []WinVolume) ([]WinDisk, []WinVolume) {
			v[0].Extents = nil
			return d, v
		},
		"system volume on a disk that was not listed": func(d []WinDisk, v []WinVolume) ([]WinDisk, []WinVolume) {
			v[0].Extents = winExtents(9)
			return d, v
		},
		"garbled extents": func(d []WinDisk, v []WinVolume) ([]WinDisk, []WinVolume) {
			v[2].Extents = []byte{9, 0, 0, 0}
			return d, v
		},
		"duplicate disk": func(d []WinDisk, v []WinVolume) ([]WinDisk, []WinVolume) {
			return append(d, d[2]), v
		},
	}
	for name, mut := range cases {
		d, v := winWorkstation()
		d, v = mut(d, v)
		if _, err := EnumerateWindows(System{}, d, v); err == nil {
			t.Errorf("%s: enumeration succeeded", name)
		}
	}
	// A disk that cannot be decoded is left out (never offered), with a warning, and
	// the system volumes on it need no protection from a tool that cannot see it.
	for name, mut := range map[string]func(d []WinDisk){
		"no geometry":          func(d []WinDisk) { d[2].Geometry = nil },
		"truncated descriptor": func(d []WinDisk) { d[1].Descriptor = d[1].Descriptor[:20] },
		"garbled system disk":  func(d []WinDisk) { d[0].Descriptor[40] = 0x01 },
	} {
		d, v := winWorkstation()
		mut(d)
		r, err := EnumerateWindows(System{}, d, v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r.Devices) != len(d)-1 || !strings.Contains(strings.Join(r.Warnings, " "), "left out") {
			t.Errorf("%s: %d devices, warnings %q", name, len(r.Devices), r.Warnings)
		}
	}
	// An ordinary volume whose disk is unknown only warns.
	d, v := winWorkstation()
	v[2].Extents = nil
	r, err := EnumerateWindows(System{}, d, v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.Warnings, " "), `D:\: disk extents unavailable`) {
		t.Fatalf("%q", r.Warnings)
	}
}

// A Hyper-V or QEMU guest marks its disks virtual, as on Linux.
func TestEnumerateWindowsVirtualMachine(t *testing.T) {
	d, v := winWorkstation()
	r, err := EnumerateWindows(System{DMIVendor: "QEMU", DMIProduct: "Standard PC (Q35 + ICH9, 2009)"}, d, v)
	if err != nil {
		t.Fatal(err)
	}
	for _, dev := range r.Devices {
		if dev.Transport != TransportMD && !dev.Media.Virtual {
			t.Errorf("%s not marked virtual", dev.Name)
		}
	}
}
