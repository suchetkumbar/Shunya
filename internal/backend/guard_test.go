package backend

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"shunya/internal/device"
	"shunya/internal/sysfs"
)

// These guards apply in every build (brief §2.3.4); this file runs with and without
// -tags release.

func hasReason(v *Verdict, sub string) bool {
	return slices.ContainsFunc(v.Reasons, func(r string) bool { return strings.Contains(r, sub) })
}

func TestGuardAbsoluteRefusals(t *testing.T) {
	tests := []struct {
		scenario, path string
		reason         string
	}{
		{"lab-vm", "/dev/vda", "PROTECTED: root filesystem / via vda3"},
		{"lab-vm", "vda", "PROTECTED: boot filesystem /boot via vda1"},
		{"lab-vm", "/dev/vda3", "is a partition of vda"},
		{"lab-vm", "/dev/sr0", "IGNORED: optical drive"},
		{"lab-vm", "/dev/nope", "no such block device"},
		{"lvm-on-luks", "/dev/sda", "PROTECTED: root filesystem / via dm-1 (vg0-root)"},
		{"lvm-on-luks", "/dev/dm-0", "logical device"},
		{"server", "/dev/sda", "IN-USE: held by md0 (md-raid1) on sda1"},
		{"server", "/dev/sde", "IN-USE: member of btrfs filesystem"},
		{"workstation", "/dev/sdb", "IN-USE: mounted at /data"},
		{"workstation", "/dev/nvme0n1", "active swap"},
		{"workstation", "/dev/loop0", "logical device"},
		{"wsl", "/dev/sdc", "IN-USE: active swap /dev/sdc"},
	}
	for _, tt := range tests {
		t.Run(tt.scenario+tt.path, func(t *testing.T) {
			withLabToken(t, testToken)
			v, err := Check(Env{FS: spec(t, tt.scenario)}, tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if v.Allowed {
				t.Fatalf("allowed; want refusal containing %q", tt.reason)
			}
			if !hasReason(v, tt.reason) {
				t.Fatalf("reasons %q lack %q", v.Reasons, tt.reason)
			}
		})
	}
}

func TestGuardBadPaths(t *testing.T) {
	env, _ := labEnv(t)
	for _, p := range []string{"", "/dev/", "/dev/../dev/sdb", "/dev/mapper/x", "../sdb", "/tmp/sdb", "/dev/sd b", ".sdb"} {
		if _, err := Check(env, p); err == nil {
			t.Errorf("Check(%q): want error", p)
		}
	}
}

func TestGuardReadOnlyAndWeak(t *testing.T) {
	env, m := labEnv(t)
	dir := "sys/devices/pci0000:00/0000:00:04.0/ata2/host1/target1:0:0/1:0:0:0"
	m[dir+"/block/sdb/ro"].Data = []byte("1\n")
	delete(m, dir+"/vpd_pg80")
	delete(m, dir+"/wwid")
	v, err := Check(env, "/dev/sdb")
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed || !hasReason(v, "read-only") || !hasReason(v, "no serial number or WWID") {
		t.Fatalf("verdict %+v", v)
	}
}

func TestGuardSelfBinaryDisk(t *testing.T) {
	env, _ := labEnv(t)
	env.Protect = []device.Protect{{Dev: sysfs.DevNum{Major: 8, Minor: 16}, Why: "holds the running shunya binary"}}
	v, err := Check(env, "/dev/sdb")
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed || !hasReason(v, "PROTECTED: holds the running shunya binary") {
		t.Fatalf("verdict %+v", v)
	}
}

func TestGuardFailsClosedWithoutMountinfo(t *testing.T) {
	env, m := labEnv(t)
	delete(m, "proc/self/mountinfo")
	if _, err := Check(env, "/dev/sdb"); err == nil {
		t.Fatal("want error")
	}
}

func TestGuardAllowsLabTarget(t *testing.T) {
	env, _ := labEnv(t)
	for _, p := range []string{"/dev/vdb", "/dev/sda", "/dev/sdb", "/dev/nvme0n1", "/dev/sdc"} {
		v, err := Check(env, p)
		if err != nil {
			t.Fatal(err)
		}
		if !v.Allowed {
			t.Errorf("%s refused: %q", p, v.Reasons)
		}
		if v.Device == nil || v.Device.Path != p {
			t.Errorf("%s: verdict device %+v", p, v.Device)
		}
	}
}

func TestRefusalError(t *testing.T) {
	err := error(&RefusalError{Path: "/dev/vda", Reasons: []string{"a", "b"}})
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "/dev/vda") || !strings.Contains(err.Error(), "a; b") {
		t.Fatalf("%v", err)
	}
}

// On Windows the guard runs on the report from device.EnumerateWindows, with \\.\ paths.
func TestGuardWindowsEnv(t *testing.T) {
	sys := device.Report{Devices: []device.Device{
		{Name: "PhysicalDrive0", Path: `\\.\PhysicalDrive0`, Status: device.StatusProtected, Reasons: []string{`Windows system volume C:\`},
			Serial: "S1", Media: device.Media{Type: device.MediaNVMeSSD}, Fingerprint: device.Fingerprint{Value: "fp1:aa"}},
		{Name: "PhysicalDrive2", Path: `\\.\PhysicalDrive2`, Status: device.StatusAvailable,
			Serial: "4C530001230616118063", Media: device.Media{Type: device.MediaUSBFlash}, Fingerprint: device.Fingerprint{Value: "fp1:bb"}},
	}}
	env := Env{FS: fstest.MapFS{}, Enumerate: func() (*device.Report, error) { r := sys; return &r, nil }}
	v, err := Check(env, `\\.\PhysicalDrive0`)
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed || v.Path != `\\.\PhysicalDrive0` || !hasReason(v, "Windows system volume") {
		t.Fatalf("%+v", v)
	}
	v, err = Check(env, `\\.\PhysicalDrive2`)
	if err != nil || v.Device == nil || v.Device.Serial != "4C530001230616118063" {
		t.Fatalf("%+v %v", v, err)
	}
	// Dev builds: the lab lock refuses (no QEMU DMI, no /etc/shunya-lab).
	if BuildKind == "dev" && (v.Allowed || !hasReason(v, "lab lock")) {
		t.Fatalf("dev build allowed a Windows disk: %+v", v)
	}
	if _, err := Check(env, `\\.\PhysicalDrive2\..\x`); err == nil {
		t.Error("path with separators accepted")
	}
	env.Enumerate = func() (*device.Report, error) { return nil, errors.New("boom") }
	if _, err := Check(env, `\\.\PhysicalDrive2`); err == nil {
		t.Error("enumeration failure did not fail closed")
	}
}
