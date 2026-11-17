package main

import (
	"bytes"
	"strings"
	"testing"

	"shunya/internal/device"
	"shunya/internal/sysfs/sysfstest"
)

func TestPrintTableLab(t *testing.T) {
	fsys, err := sysfstest.Load("../../internal/device/testdata/sysfs/lab-vm.spec")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := device.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	printTable(&b, rep, false)
	out := b.String()
	for _, want := range []string{
		"/dev/vda", "PROTECTED", "root filesystem / via vda3",
		"/dev/nvme0n1", "nvme-ssd (high) virt", "SHUNYA-NVME-01",
		"/dev/sdc", "usb-flash (medium)", "lab marker: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}

func TestRunUsage(t *testing.T) {
	var o, e bytes.Buffer
	if code := run(nil, &o, &e); code != 2 || !strings.Contains(e.String(), "usage") {
		t.Fatalf("code %d, stderr %q", code, e.String())
	}
	if code := run([]string{"bogus"}, &o, &e); code != 2 {
		t.Fatalf("code %d", code)
	}
}

func TestHuman(t *testing.T) {
	for in, want := range map[uint64]string{0: "0B", 1023: "1023B", 1024: "1.0KiB", 1 << 30: "1.0GiB", 1000204886016: "931.5GiB"} {
		if got := human(in); got != want {
			t.Errorf("human(%d) = %q, want %q", in, got, want)
		}
	}
}
