package sysfs

import (
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseMountInfo(t *testing.T) {
	const in = `22 1 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg0-root rw
23 22 8:1 / /boot rw,relatime shared:2 - ext4 /dev/sda1 rw
24 22 0:5 / /dev rw - devtmpfs none rw
25 22 8:17 /sub /mnt/my\040disk rw - vfat /dev/sdb1 rw
26 22 0:44 / /data rw - btrfs /dev/sdc rw,space_cache
`
	got, err := ParseMountInfo([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Mount{
		{Dev: DevNum{253, 1}, Root: "/", MountPoint: "/", FSType: "ext4", Source: "/dev/mapper/vg0-root"},
		{Dev: DevNum{8, 1}, Root: "/", MountPoint: "/boot", FSType: "ext4", Source: "/dev/sda1"},
		{Dev: DevNum{0, 5}, Root: "/", MountPoint: "/dev", FSType: "devtmpfs", Source: "none"},
		{Dev: DevNum{8, 17}, Root: "/sub", MountPoint: "/mnt/my disk", FSType: "vfat", Source: "/dev/sdb1"},
		{Dev: DevNum{0, 44}, Root: "/", MountPoint: "/data", FSType: "btrfs", Source: "/dev/sdc"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseMountInfoErrors(t *testing.T) {
	for _, in := range []string{
		"22 1 253:1 / / rw shared:1 ext4 /dev/x rw\n", // no separator
		"22 1 253 / / rw - ext4 /dev/x rw\n",          // bad dev
		"22 1 8:1 /\n",                                // short
	} {
		if _, err := ParseMountInfo([]byte(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestParseSwaps(t *testing.T) {
	const in = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n" +
		"/dev/sdc                                partition\t1048576\t\t0\t\t-2\n" +
		"/swap\\040file                           file\t\t1024\t\t0\t\t-3\n"
	got, err := ParseSwaps([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Swap{{Path: "/dev/sdc", Type: "partition"}, {Path: "/swap file", Type: "file"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestParseVPD80(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
		ok   bool
	}{
		{"normal", append([]byte{0, 0x80, 0, 18}, "SHUNYA-SATA-SSD-01"...), "SHUNYA-SATA-SSD-01", true},
		{"padded", append([]byte{0, 0x80, 0, 8}, "  AB12\x00\x00 "...), "AB12", true},
		{"short header", []byte{0, 0x80}, "", false},
		{"wrong page", append([]byte{0, 0x83, 0, 2}, "AB"...), "", false},
		{"length overrun", append([]byte{0, 0x80, 0, 9}, "AB"...), "", false},
		{"empty", []byte{0, 0x80, 0, 0}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseVPD80(tt.in)
			if (err == nil) != tt.ok || got != tt.want {
				t.Fatalf("got %q, %v; want %q ok=%v", got, err, tt.want, tt.ok)
			}
		})
	}
}

func TestParseDevNum(t *testing.T) {
	d, err := ParseDevNum("259:3\n")
	if err != nil || d != (DevNum{259, 3}) {
		t.Fatalf("got %v %v", d, err)
	}
	for _, bad := range []string{"", "8", "8:", ":1", "a:b", "8:1:2", "-1:2", "99999999999:1"} {
		if _, err := ParseDevNum(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestReaders(t *testing.T) {
	fsys := fstest.MapFS{
		"sys/block/sda": {Data: []byte("../devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda"), Mode: 0o777 | fs.ModeSymlink},
		"sys/devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda/size":       {Data: []byte("2048\n")},
		"sys/devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda/removable":  {Data: []byte("0\n")},
		"sys/devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda/model_name": {Data: []byte("  Model X  \n")},
		"sys/devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda/bad":        {Data: []byte("abc\n")},
	}
	r := New(fsys)
	if v, err := r.Uint("sys/block/sda/size"); err != nil || v != 2048 {
		t.Fatalf("Uint: %v %v", v, err)
	}
	if v, err := r.Bool("sys/block/sda/removable"); err != nil || v {
		t.Fatalf("Bool: %v %v", v, err)
	}
	if v := r.String("sys/block/sda/model_name"); v != "Model X" {
		t.Fatalf("String: %q", v)
	}
	if v := r.String("sys/block/sda/missing"); v != "" {
		t.Fatalf("missing: %q", v)
	}
	if _, err := r.Uint("sys/block/sda/bad"); err == nil {
		t.Fatal("expected parse error")
	}
	p, err := r.Resolve("sys/block/sda")
	if err != nil || p != "sys/devices/pci0000:00/ata1/host0/target0:0:0/0:0:0:0/block/sda" {
		t.Fatalf("Resolve: %q %v", p, err)
	}
	if _, err := r.Resolve("sys/devices"); err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("Resolve non-link: %v", err)
	}
}

func FuzzParseMountInfo(f *testing.F) {
	f.Add([]byte("22 1 253:1 / / rw,relatime shared:1 - ext4 /dev/mapper/vg0-root rw\n"))
	f.Add([]byte("25 22 8:17 /sub /mnt/my\\040disk rw - vfat /dev/sdb1 rw\n"))
	f.Add([]byte("1 2 3:4 \\ \\777 - - x y\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ms, err := ParseMountInfo(b)
		if err != nil {
			return
		}
		for _, m := range ms {
			if m.MountPoint == "" {
				t.Fatalf("empty mount point accepted: %+v", m)
			}
		}
	})
}

func FuzzParseSwaps(f *testing.F) {
	f.Add([]byte("Filename Type Size Used Priority\n/dev/sdc partition 1048576 0 -2\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ss, err := ParseSwaps(b)
		if err != nil {
			return
		}
		for _, s := range ss {
			if s.Path == "" {
				t.Fatal("empty path accepted")
			}
		}
	})
}

func FuzzParseVPD80(f *testing.F) {
	f.Add(append([]byte{0, 0x80, 0, 4}, "ABCD"...))
	f.Add([]byte{0, 0x80, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseVPD80(b)
		if err != nil {
			return
		}
		if len(s) > len(b) {
			t.Fatal("serial longer than input")
		}
	})
}

func FuzzParseDevNum(f *testing.F) {
	f.Add("8:0")
	f.Add("4294967295:4294967295")
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDevNum(s)
		if err != nil {
			return
		}
		if d2, err := ParseDevNum(d.String()); err != nil || d2 != d {
			t.Fatalf("round trip %q -> %v -> %v %v", s, d, d2, err)
		}
	})
}

func FuzzParseUint(f *testing.F) {
	f.Add("512\n")
	f.Add(" 18446744073709551615 ")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseUint(s)
	})
}
