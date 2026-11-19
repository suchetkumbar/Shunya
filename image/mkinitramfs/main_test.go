package main

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
	"testing/fstest"
)

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// body is a module's content: repetitive, so gzip really compresses it (tiny inputs
// would be stored verbatim and look decompressed either way).
func body(name string) []byte { return []byte(strings.Repeat("BODY:"+name+";", 64)) }

func modTree() fstest.MapFS {
	return fstest.MapFS{
		"modules.dep": {Data: []byte(`kernel/fs/ext4/ext4.ko.gz: kernel/fs/jbd2/jbd2.ko.gz kernel/fs/mbcache.ko.gz kernel/lib/crc16.ko.gz
kernel/fs/jbd2/jbd2.ko.gz:
kernel/fs/mbcache.ko.gz:
kernel/lib/crc16.ko.gz:
kernel/drivers/nvme/host/nvme.ko.gz: kernel/drivers/nvme/host/nvme-core.ko.gz
kernel/drivers/nvme/host/nvme-core.ko.gz:
kernel/drivers/usb/host/xhci-pci.ko.gz: kernel/drivers/usb/host/xhci-hcd.ko.gz
kernel/drivers/usb/host/xhci-hcd.ko.gz:
`)},
		"modules.builtin":                          {Data: []byte("kernel/drivers/ata/ahci.ko\nkernel/drivers/scsi/scsi_mod.ko\n")},
		"kernel/fs/ext4/ext4.ko.gz":                {Data: gz(body("ext4"))},
		"kernel/fs/jbd2/jbd2.ko.gz":                {Data: gz(body("jbd2"))},
		"kernel/fs/mbcache.ko.gz":                  {Data: gz(body("mbcache"))},
		"kernel/lib/crc16.ko.gz":                   {Data: gz(body("crc16"))},
		"kernel/drivers/nvme/host/nvme.ko.gz":      {Data: gz(body("nvme"))},
		"kernel/drivers/nvme/host/nvme-core.ko.gz": {Data: gz(body("nvme-core"))},
		"kernel/drivers/usb/host/xhci-pci.ko.gz":   {Data: gz(body("xhci-pci"))},
		"kernel/drivers/usb/host/xhci-hcd.ko.gz":   {Data: gz(body("xhci-hcd"))},
	}
}

func TestResolveModules(t *testing.T) {
	order, err := resolveModules(modTree(), []string{"nvme", "xhci_pci", "ext4", "ahci"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(order, " ")
	want := "kernel/drivers/nvme/host/nvme-core.ko.gz kernel/drivers/nvme/host/nvme.ko.gz " +
		"kernel/drivers/usb/host/xhci-hcd.ko.gz kernel/drivers/usb/host/xhci-pci.ko.gz " +
		"kernel/fs/jbd2/jbd2.ko.gz kernel/fs/mbcache.ko.gz kernel/lib/crc16.ko.gz kernel/fs/ext4/ext4.ko.gz"
	if got != want {
		t.Fatalf("order\n %s\nwant\n %s", got, want)
	}
	if _, err := resolveModules(modTree(), []string{"nosuchmod"}); err == nil {
		t.Error("unknown module accepted")
	}
	cyc := modTree()
	cyc["modules.dep"] = &fstest.MapFile{Data: []byte("a.ko: b.ko\nb.ko: a.ko\n")}
	if _, err := resolveModules(cyc, []string{"a"}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("cycle: %v", err)
	}
}

func TestBuildDeterministic(t *testing.T) {
	root := fstest.MapFS{
		"init":            {Data: []byte("#!/bin/busybox sh\n"), Mode: 0o755},
		"bin/busybox":     {Data: []byte("busybox"), Mode: 0o755},
		"bin/shunya":      {Data: []byte("shunya"), Mode: 0o755},
		"etc/shunya/motd": {Data: []byte("hello\n"), Mode: 0o644},
	}
	var a, b bytes.Buffer
	sa, err := build(&a, root, modTree(), "6.18.64-0-virt", []string{"nvme", "ext4"}, 1763500000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := build(&b, root, modTree(), "6.18.64-0-virt", []string{"nvme", "ext4"}, 1763500000); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("not reproducible")
	}
	arc := a.String()
	for _, want := range []string{"lib/modules/6.18.64-0-virt/kernel/fs/ext4/ext4.ko", "dev/console", "etc/shunya/modules.order", "TRAILER!!!"} {
		if !strings.Contains(arc, want) {
			t.Errorf("archive lacks %s", want)
		}
	}
	if strings.Contains(arc, ".ko.gz") || !strings.Contains(arc, string(body("ext4"))) || !strings.Contains(arc, string(body("nvme-core"))) {
		t.Error("modules not decompressed")
	}
	// The load order init reads: dependencies first.
	if !strings.Contains(arc, "6.18.64-0-virt/kernel/drivers/nvme/host/nvme-core.ko\n6.18.64-0-virt/kernel/drivers/nvme/host/nvme.ko\n") {
		t.Error("modules.order wrong")
	}
	if len(sa) != 4+6+1 || !strings.HasSuffix(sa[0], "  bin/busybox") {
		t.Errorf("sums %q", sa)
	}
	// A different epoch changes the archive (the time is really written).
	var c bytes.Buffer
	build(&c, root, modTree(), "6.18.64-0-virt", []string{"nvme", "ext4"}, 1)
	if bytes.Equal(a.Bytes(), c.Bytes()) {
		t.Error("epoch ignored")
	}
}
