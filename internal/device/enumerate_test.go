package device

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"shunya/internal/sysfs"
	"shunya/internal/sysfs/sysfstest"
)

// want describes the expected view of one device. Zero-valued fields are not checked,
// except Status, Transport and Media which every row must state.
type want struct {
	transport  Transport
	media      MediaType
	confidence Confidence
	status     Status
	reasons    []string // each must be a substring of some reason
	model      string
	serial     string
	firmware   string
	wwid       string
	sizeBytes  uint64
	physSector uint32
	removable  bool
	virtual    bool
	partitions []string
	holders    string // flattened holder tree, see flattenHolders
}

func enumerateSpec(t *testing.T, name string) *Report {
	t.Helper()
	fsys, err := sysfstest.Load(filepath.Join("testdata", "sysfs", name+".spec"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Enumerate(fsys)
	if err != nil {
		t.Fatalf("Enumerate(%s): %v", name, err)
	}
	return r
}

func checkDevices(t *testing.T, r *Report, wants map[string]want) {
	t.Helper()
	got := map[string]Device{}
	for _, d := range r.Devices {
		got[d.Name] = d
	}
	for name, w := range wants {
		d, ok := got[name]
		if !ok {
			t.Errorf("%s: missing from report (have %v)", name, keys(got))
			continue
		}
		if d.Transport != w.transport {
			t.Errorf("%s: transport %q, want %q", name, d.Transport, w.transport)
		}
		if d.Media.Type != w.media {
			t.Errorf("%s: media %q, want %q (reasons %v)", name, d.Media.Type, w.media, d.Media.Reasons)
		}
		if w.confidence != "" && d.Media.Confidence != w.confidence {
			t.Errorf("%s: confidence %q, want %q (reasons %v)", name, d.Media.Confidence, w.confidence, d.Media.Reasons)
		}
		if d.Status != w.status {
			t.Errorf("%s: status %q, want %q (reasons %v)", name, d.Status, w.status, d.Reasons)
		}
		for _, sub := range w.reasons {
			if !slices.ContainsFunc(d.Reasons, func(r string) bool { return strings.Contains(r, sub) }) {
				t.Errorf("%s: no reason containing %q in %q", name, sub, d.Reasons)
			}
		}
		if w.status == StatusAvailable && len(d.Reasons) != 0 {
			t.Errorf("%s: available but has reasons %q", name, d.Reasons)
		}
		eq := func(field, got, want string) {
			if want != "" && got != want {
				t.Errorf("%s: %s %q, want %q", name, field, got, want)
			}
		}
		eq("model", d.Model, w.model)
		eq("serial", d.Serial, w.serial)
		eq("firmware", d.Firmware, w.firmware)
		eq("wwid", d.WWID, w.wwid)
		eq("holders", flattenHolders(d), w.holders)
		if w.sizeBytes != 0 && d.SizeBytes != w.sizeBytes {
			t.Errorf("%s: size %d, want %d", name, d.SizeBytes, w.sizeBytes)
		}
		if w.physSector != 0 && d.PhysicalSectorSize != w.physSector {
			t.Errorf("%s: physical sector %d, want %d", name, d.PhysicalSectorSize, w.physSector)
		}
		if d.Removable != w.removable {
			t.Errorf("%s: removable %v, want %v", name, d.Removable, w.removable)
		}
		if d.Media.Virtual != w.virtual {
			t.Errorf("%s: virtual %v, want %v", name, d.Media.Virtual, w.virtual)
		}
		if w.partitions != nil {
			var ps []string
			for _, p := range d.Partitions {
				ps = append(ps, p.Name)
			}
			if !slices.Equal(ps, w.partitions) {
				t.Errorf("%s: partitions %v, want %v", name, ps, w.partitions)
			}
		}
		if d.Path != "/dev/"+name && d.Path != `\\.\`+name { // Windows: \\.\PhysicalDriveN
			t.Errorf("%s: path %q", name, d.Path)
		}
	}
}

// flattenHolders renders the holder forest as "on>holder(kind)>holder(kind),...".
func flattenHolders(d Device) string {
	var out []string
	var walk func(prefix string, hs []Holder)
	walk = func(prefix string, hs []Holder) {
		for _, h := range hs {
			p := prefix + ">" + h.Name + "(" + string(h.Kind) + ")"
			if len(h.Holders) == 0 {
				out = append(out, p)
			}
			walk(p, h.Holders)
		}
	}
	walk(d.Name, d.Holders)
	for _, p := range d.Partitions {
		walk(p.Name, p.Holders)
	}
	return strings.Join(out, ",")
}

func keys(m map[string]Device) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func TestWorkstation(t *testing.T) {
	r := enumerateSpec(t, "workstation")
	checkDevices(t, r, map[string]want{
		"nvme0n1": {
			transport: TransportNVMe, media: MediaNVMeSSD, confidence: High, status: StatusProtected,
			reasons: []string{"root filesystem /", "boot filesystem /boot/efi", "active swap"},
			model:   "Samsung SSD 980 PRO 1TB", serial: "S5GXNF0R123456", firmware: "5B2QGXA7",
			wwid: "eui.002538b511a2c3d4", sizeBytes: 1953525168 * 512, physSector: 512,
			partitions: []string{"nvme0n1p1", "nvme0n1p2", "nvme0n1p3"},
		},
		"sda": {
			transport: TransportSATA, media: MediaSSD, confidence: High, status: StatusAvailable,
			model: "CT500MX500SSD1", serial: "2117E1A2B3C4", firmware: "046", wwid: "naa.500a0751e1a2b3c4",
			physSector: 4096, partitions: []string{},
		},
		"sdb": {
			transport: TransportSATA, media: MediaHDD, confidence: High, status: StatusInUse,
			reasons: []string{"mounted at /data", "mnt:[4026532999]"},
			serial:  "WD-WCC7K1ABCDEF", partitions: []string{"sdb1"},
		},
		"sdc": {
			transport: TransportUSB, media: MediaUSBFlash, confidence: Medium, status: StatusAvailable,
			model: "Cruzer Blade", serial: "4C530001230616118063", removable: true,
		},
		"mmcblk0": {
			transport: TransportMMC, media: MediaEMMC, confidence: High, status: StatusAvailable,
			model: "HBG4a2", serial: "0x1a2b3c4d", firmware: "0x0300000000000000",
			wwid: "cid.90014a484247346132a1b2c3d4e5f600",
		},
		"mmcblk1": {
			transport: TransportMMC, media: MediaSDCard, confidence: High, status: StatusAvailable,
			model: "SD64G", serial: "0x00001234",
		},
		"loop0": {
			transport: TransportLoop, media: MediaLogical, confidence: High, status: StatusInUse,
			reasons: []string{"mounted at /snap/core/123", "backed by file /var/lib/snapd/snaps/core_123.snap"},
		},
		"ram0": {
			transport: TransportRAM, media: MediaLogical, confidence: High, status: StatusIgnored,
			reasons: []string{"not a storage device"},
		},
	})
	for _, d := range r.Devices {
		if d.Name == "loop1" {
			t.Error("loop1 has size 0 and must be omitted")
		}
	}
	if r.System.MountNamespaces != 2 {
		t.Errorf("mount namespaces = %d, want 2", r.System.MountNamespaces)
	}
	if r.System.DMIVendor != "Dell Inc." || r.System.LabMarker {
		t.Errorf("system = %+v", r.System)
	}
}

func TestLVMOnLUKS(t *testing.T) {
	r := enumerateSpec(t, "lvm-on-luks")
	checkDevices(t, r, map[string]want{
		"sda": {
			transport: TransportSATA, media: MediaSSD, confidence: High, status: StatusProtected,
			reasons: []string{
				"root filesystem / via dm-1 (vg0-root) → dm-0 (luks-3f2a9c1e) → sda2",
				"boot filesystem /boot via sda1",
				"active swap /dev/mapper/vg0-swap via dm-2 (vg0-swap) → dm-0 (luks-3f2a9c1e) → sda2",
			},
			serial:     "S6PNNX0T123456A",
			partitions: []string{"sda1", "sda2"},
			holders:    "sda2>dm-0(dm-crypt)>dm-1(lvm),sda2>dm-0(dm-crypt)>dm-2(lvm)",
		},
		"dm-0": {transport: TransportDM, media: MediaLogical, status: StatusProtected,
			reasons: []string{"root filesystem /"}, holders: "dm-0>dm-1(lvm),dm-0>dm-2(lvm)"},
		"dm-1": {transport: TransportDM, media: MediaLogical, status: StatusProtected},
		"dm-2": {transport: TransportDM, media: MediaLogical, status: StatusInUse, reasons: []string{"active swap"}},
	})
}

func TestServer(t *testing.T) {
	r := enumerateSpec(t, "server")
	checkDevices(t, r, map[string]want{
		"sdc": {transport: TransportSAS, media: MediaSSD, confidence: High, status: StatusProtected,
			reasons: []string{"root filesystem / via sdc1"}, serial: "HLJ0A1B20000C123D4E5"},
		"sda": {transport: TransportSATA, media: MediaHDD, confidence: High, status: StatusInUse,
			reasons: []string{"mounted at /srv via md0 → sda1", "held by md0 (md-raid"}, holders: "sda1>md0(md)"},
		"sdb": {transport: TransportSATA, media: MediaHDD, confidence: High, status: StatusInUse,
			reasons: []string{"mounted at /srv via md0 → sdb1"}},
		"md0": {transport: TransportMD, media: MediaLogical, status: StatusInUse},
		"sdd": {transport: TransportSATA, media: MediaHDD, status: StatusInUse,
			reasons: []string{"mounted at /backup", "member of btrfs filesystem 7a1c0d6e"}},
		"sde": {transport: TransportSATA, media: MediaHDD, status: StatusInUse,
			reasons: []string{"member of btrfs filesystem 7a1c0d6e"}},
	})
}

func TestLabVM(t *testing.T) {
	r := enumerateSpec(t, "lab-vm")
	checkDevices(t, r, map[string]want{
		"vda": {transport: TransportVirtio, media: MediaVirtual, confidence: High, status: StatusProtected,
			reasons: []string{"root filesystem / via vda3", "boot filesystem /boot via vda1"},
			serial:  "SHUNYA-BOOT-0", virtual: true},
		"vdb": {transport: TransportVirtio, media: MediaVirtual, confidence: High, status: StatusAvailable,
			serial: "SHUNYA-VIRTIO-01", virtual: true},
		"sda": {transport: TransportSATA, media: MediaHDD, confidence: High, status: StatusAvailable,
			serial: "SHUNYA-SATA-HDD-01", model: "SHUNYA LAB SATA", firmware: "2.5+", virtual: true}, // virtual from DMI (M6),
		"sdb": {transport: TransportSATA, media: MediaSSD, confidence: High, status: StatusAvailable,
			serial: "SHUNYA-SATA-SSD-01", virtual: true},
		"nvme0n1": {transport: TransportNVMe, media: MediaNVMeSSD, confidence: High, status: StatusAvailable,
			serial: "SHUNYA-NVME-01", model: "QEMU NVMe Ctrl", wwid: "eui.5348554e59410001", virtual: true},
		"sdc": {transport: TransportUSB, media: MediaUSBFlash, confidence: Medium, status: StatusAvailable,
			serial: "SHUNYA-USB-01", removable: true, virtual: true},
		"sr0": {transport: TransportSATA, media: MediaOptical, status: StatusIgnored, removable: true, virtual: true,
			reasons: []string{"optical drive"}},
	})
	if r.System.DMIVendor != "QEMU" || !r.System.LabMarker {
		t.Errorf("system = %+v", r.System)
	}
}

func TestWSL(t *testing.T) {
	r := enumerateSpec(t, "wsl")
	checkDevices(t, r, map[string]want{
		"sdd": {transport: TransportHyperV, media: MediaVirtual, confidence: High, status: StatusProtected,
			reasons: []string{"root filesystem /"}, virtual: true, model: "Virtual Disk"},
		"sdc": {transport: TransportHyperV, media: MediaVirtual, confidence: High, status: StatusInUse,
			reasons: []string{"active swap /dev/sdc"}, virtual: true},
		"sda": {transport: TransportHyperV, media: MediaVirtual, confidence: High, status: StatusAvailable, virtual: true},
	})
	if len(r.Warnings) == 0 {
		t.Error("expected a warning about invisible mount namespaces")
	}
}

func TestEnumerateFailsClosed(t *testing.T) {
	// Without mountinfo we cannot tell what is mounted, so enumeration must fail
	// rather than report every disk as available.
	fsys, err := sysfstest.Parse(`
disk sda 8:0 /sys/devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda
size = 100
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Enumerate(fsys); err == nil || !strings.Contains(err.Error(), "mountinfo") {
		t.Fatalf("want mountinfo error, got %v", err)
	}
}

func TestEnumerateRejectsUnreadableSize(t *testing.T) {
	fsys, err := sysfstest.Parse(`
disk sda 8:0 /sys/devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda
size = banana
/proc/self/mountinfo = 20 1 8:1 / / rw - ext4 /dev/sda1 rw
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Enumerate(fsys); err == nil {
		t.Fatal("want error for unparsable size")
	}
}

func TestEnumerateExtraProtect(t *testing.T) {
	fsys, err := sysfstest.Load(filepath.Join("testdata", "sysfs", "server.spec"))
	if err != nil {
		t.Fatal(err)
	}
	// The running binary lives on md0 (9:0); both RAID members must become PROTECTED.
	r, err := EnumerateWith(fsys, Options{Protect: []Protect{{Dev: sysfs.DevNum{Major: 9, Minor: 0}, Why: "holds the running shunya binary"}}})
	if err != nil {
		t.Fatal(err)
	}
	checkDevices(t, r, map[string]want{
		"sda": {transport: TransportSATA, media: MediaHDD, status: StatusProtected,
			reasons: []string{"holds the running shunya binary via md0 → sda1"}},
		"sdb": {transport: TransportSATA, media: MediaHDD, status: StatusProtected},
	})
	for _, d := range r.Devices {
		if d.Name == "sda" && (len(d.Partitions) != 1 || d.Partitions[0].DevNum != "8:1") {
			t.Errorf("sda partitions %+v", d.Partitions)
		}
	}
}

// The Shunya live image records the medium it booted from in /run/shunya/boot-device
// (one MAJOR:MINOR per line, a whole disk or a partition). That disk is PROTECTED even
// when nothing on it is mounted, and in every build.
func TestBootDeviceMarker(t *testing.T) {
	fsys, err := sysfstest.Load(filepath.Join("testdata", "sysfs", "lab-vm.spec"))
	if err != nil {
		t.Fatal(err)
	}
	fsys[BootDeviceFile] = &fstest.MapFile{Data: []byte("# written by the live image's init\n8:32\n259:0\n\n")}
	r, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	checkDevices(t, r, map[string]want{
		"sdc": {transport: TransportUSB, media: MediaUSBFlash, status: StatusProtected, removable: true, virtual: true,
			reasons: []string{"boot medium of this Shunya live system"}},
		"nvme0n1": {transport: TransportNVMe, media: MediaNVMeSSD, status: StatusProtected, virtual: true,
			reasons: []string{"boot medium of this Shunya live system"}},
		"vdb": {transport: TransportVirtio, media: MediaVirtual, status: StatusAvailable, virtual: true},
	})
}

// A partition number marks its whole disk.
func TestBootDeviceMarkerPartition(t *testing.T) {
	fsys, err := sysfstest.Load(filepath.Join("testdata", "sysfs", "lab-vm.spec"))
	if err != nil {
		t.Fatal(err)
	}
	fsys[BootDeviceFile] = &fstest.MapFile{Data: []byte("253:2\n")}
	r, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	checkDevices(t, r, map[string]want{
		"vda": {transport: TransportVirtio, media: MediaVirtual, status: StatusProtected, virtual: true,
			reasons: []string{"boot medium of this Shunya live system via vda2"}},
	})
}

// A marker that cannot be read fails closed: the boot medium might be any disk.
func TestBootDeviceMarkerFailsClosed(t *testing.T) {
	for _, bad := range []string{"8:32 extra\n", "sdc\n", "8:\n", "-1:0\n"} {
		fsys, err := sysfstest.Load(filepath.Join("testdata", "sysfs", "lab-vm.spec"))
		if err != nil {
			t.Fatal(err)
		}
		fsys[BootDeviceFile] = &fstest.MapFile{Data: []byte(bad)}
		// The line itself is rejected (not just the device it would name).
		if _, err := Enumerate(fsys); err == nil || !strings.Contains(err.Error(), "boot-device line 1") {
			t.Errorf("%q: want a boot-device line 1 error, got %v", bad, err)
		}
	}
	// A device number that names no disk is an error too: the live image recorded a
	// medium this enumeration cannot see, so its protection cannot be applied.
	fsys, _ := sysfstest.Load(filepath.Join("testdata", "sysfs", "lab-vm.spec"))
	fsys[BootDeviceFile] = &fstest.MapFile{Data: []byte("8:240\n")}
	if _, err := Enumerate(fsys); err == nil || !strings.Contains(err.Error(), "8:240") {
		t.Errorf("unknown device: want an error naming 8:240, got %v", err)
	}
}

// Found in the M6 lab run: QEMU SATA disks with custom model strings looked physical.
// On a virtual machine every physical-looking disk is treated as emulated.
func TestHypervisorMarksDisks(t *testing.T) {
	for sys, want := range map[System]bool{
		{DMIVendor: "QEMU", DMIProduct: "Standard PC (Q35 + ICH9, 2009)"}:   true,
		{DMIVendor: "Microsoft Corporation", DMIProduct: "Virtual Machine"}: true,
		{DMIVendor: "innotek GmbH", DMIProduct: "VirtualBox"}:               true,
		{DMIVendor: "Dell Inc.", DMIProduct: "OptiPlex 7090"}:               false,
		{DMIVendor: "LENOVO", DMIProduct: "20XW0055US"}:                     false,
		{}: false,
	} {
		d := &Device{Media: Media{Type: MediaHDD}}
		markHypervisor(d, sys)
		if d.Media.Virtual != want {
			t.Errorf("%+v: virtual %v", sys, d.Media.Virtual)
		}
		l := &Device{Media: Media{Type: MediaLogical}}
		markHypervisor(l, sys)
		if l.Media.Virtual {
			t.Error("logical device marked virtual")
		}
	}
	r := enumerateSpec(t, "lab-vm")
	for _, d := range r.Devices {
		if d.Name == "sda" && !strings.Contains(strings.Join(d.Media.Reasons, " "), "virtual machine") {
			t.Errorf("sda reasons %v", d.Media.Reasons)
		}
	}
}
