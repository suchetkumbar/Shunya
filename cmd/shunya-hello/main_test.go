package main

import (
	"testing"
	"testing/fstest"
)

func TestScanFakeSysfs(t *testing.T) {
	f := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s + "\n")} }
	root := fstest.MapFS{
		"sys/class/dmi/id/sys_vendor":        f("QEMU"),
		"sys/class/dmi/id/product_name":      f("Standard PC (Q35 + ICH9, 2009)"),
		"etc/shunya-lab":                     f("token"),
		"sys/block/vda/size":                 f("4194304"),
		"sys/block/vda/serial":               f("SHUNYA-BOOT-0"),
		"sys/block/vda/queue/rotational":     f("1"),
		"sys/block/vda/removable":            f("0"),
		"sys/block/nvme0n1/size":             f("2097152"),
		"sys/block/nvme0n1/queue/rotational": f("0"),
		"sys/block/nvme0n1/device/model":     f("QEMU NVMe Ctrl"),
		"sys/block/nvme0n1/device/serial":    f("SHUNYA-NVME-01"),
		"sys/block/loop0/size":               f("0"),
		"sys/block/sda/size":                 f("2097152"),
		"sys/block/sda/device/vpd_pg80":      {Data: append([]byte{0, 0x80, 0, 18}, "SHUNYA-SATA-SSD-01"...)},
	}
	r, err := scan(root)
	if err != nil {
		t.Fatal(err)
	}
	if !r.LabMarker || r.DMIVendor != "QEMU" {
		t.Fatalf("dmi/marker wrong: %+v", r)
	}
	if len(r.Disks) != 3 {
		t.Fatalf("want 3 disks (loop skipped), got %d: %+v", len(r.Disks), r.Disks)
	}
	tests := []struct {
		i      int
		name   string
		size   int64
		serial string
		rota   bool
	}{
		{0, "nvme0n1", 1 << 30, "SHUNYA-NVME-01", false},
		{1, "sda", 1 << 30, "SHUNYA-SATA-SSD-01", false},
		{2, "vda", 2 << 30, "SHUNYA-BOOT-0", true},
	}
	for _, tc := range tests {
		d := r.Disks[tc.i]
		if d.Name != tc.name || d.SizeBytes != tc.size || d.Serial != tc.serial || d.Rotational != tc.rota {
			t.Errorf("disk %d = %+v, want %+v", tc.i, d, tc)
		}
	}
}

func TestHuman(t *testing.T) {
	for in, want := range map[int64]string{512: "512B", 1 << 30: "1.0GiB", 1536: "1.5KiB"} {
		if got := human(in); got != want {
			t.Errorf("human(%d) = %q, want %q", in, got, want)
		}
	}
}
