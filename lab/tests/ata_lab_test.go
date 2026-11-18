//go:build labtest && linux

package labtests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/ata"
	"shunya/internal/device"
	"shunya/internal/engine"
)

// Milestone 5 in the lab. QEMU's AHCI disks answer IDENTIFY, READ DMA and the like
// through SG_IO, but advertise no HPA, no Security feature set, and abort DCO IDENTIFY
// (design/LAB_CAPABILITIES.md). So the lab proves: the real SG_IO path, the IDENTIFY
// parser on emulated drives, the identity cross-check, and every refusal; HPA removal and
// Security Erase are proven against the simulated drive only (pending-real-hardware).

func results(t *testing.T) string {
	out := os.Getenv("SHUNYA_RESULTS")
	if out == "" {
		out = "results"
	}
	os.MkdirAll(out, 0o755)
	return out
}

func TestLabATAIdentify(t *testing.T) {
	env := inLab(t)
	rep, err := device.EnumerateWith(env.FS, device.Options{Protect: env.Protect})
	if err != nil {
		t.Fatal(err)
	}
	for _, serial := range []string{"SHUNYA-SATA-SSD-01", "SHUNYA-SATA-HDD-01"} {
		t.Run(serial, func(t *testing.T) {
			dev := pathOf(t, env, serial)
			save := filepath.Join(results(t), "identify-"+serial+".txt")
			out := shunya(t, 0, "ata", "identify", "--json", "--save", save, dev)
			var id ata.Identify
			if err := json.Unmarshal([]byte(out), &id); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			var d device.Device
			for _, x := range rep.Devices {
				if x.Path == dev {
					d = x
				}
			}
			if id.Serial != serial || !strings.HasPrefix(id.Model, strings.TrimSpace(d.Model)) {
				t.Errorf("IDENTIFY serial %q model %q; sysfs serial %q model %q", id.Serial, id.Model, d.Serial, d.Model)
			}
			if id.Sectors()*uint64(id.LogicalSectorBytes) != d.SizeBytes || !id.Supports48 {
				t.Errorf("IDENTIFY capacity %d × %d, sysfs %d", id.Sectors(), id.LogicalSectorBytes, d.SizeBytes)
			}
			if w := strings.TrimPrefix(d.WWID, "naa."); id.WWN != "" && w != id.WWN {
				t.Errorf("WWN %s, sysfs %s", id.WWN, d.WWID)
			}
			// QEMU's rotation_rate property: SSD 1 (non-rotating), HDD 7200.
			if (serial == "SHUNYA-SATA-SSD-01") != id.SolidState() {
				t.Errorf("rotation rate %d", id.RotationRPM)
			}
			// The saved dump parses back to the same identity (hdparm --Istdout format).
			out = shunya(t, 0, "ata", "identify", "--dump", save)
			if !strings.Contains(out, serial) {
				t.Errorf("saved dump: %s", out)
			}
			t.Logf("%s: %s, %d sectors, HPA %v, DCO %v, security %v, checksum %s", serial, id.Model, id.Sectors(),
				id.HPASupported, id.DCOSupported, id.Security.Supported, id.Checksum)
		})
	}
}

func TestLabATAHiddenAreas(t *testing.T) {
	env := inLab(t)
	for _, serial := range []string{"SHUNYA-SATA-SSD-01", "SHUNYA-SATA-HDD-01"} {
		out := shunya(t, 0, "ata", "hidden", "--json", pathOf(t, env, serial))
		var hp engine.HiddenPlan
		if err := json.Unmarshal([]byte(out), &hp); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		b := hp.Before
		if !b.Checked || b.HPA || b.ReportedSectors != b.NativeSectors || hp.NativeFingerprint == "" {
			t.Errorf("%s: %+v", serial, hp)
		}
		t.Logf("%s: %s", serial, b.Summary())
		os.WriteFile(filepath.Join(results(t), "hidden-"+serial+".json"), []byte(out), 0o644)
	}
}

// Everything that must be refused, refused on live devices.
func TestLabATARefusals(t *testing.T) {
	env := inLab(t)
	// QEMU advertises no Security feature set: the erase is refused at planning, and the
	// drive never sees a Security command.
	for _, m := range []string{"ata-secure-erase", "ata-enhanced-secure-erase"} {
		out := shunya(t, 1, "wipe", "--method", m, pathOf(t, env, "SHUNYA-SATA-HDD-01"))
		if !strings.Contains(out, "PRECONDITIONS NOT MET") || !strings.Contains(out, "does not support the ATA Security feature set") {
			t.Errorf("%s:\n%s", m, out)
		}
	}
	dir, key := workDir(t)
	out := shunya(t, 1, "wipe", "--method", "ata-secure-erase", "--execute", "--journal", filepath.Join(dir, "j"), "--key", key,
		pathOf(t, env, "SHUNYA-SATA-HDD-01"))
	if !strings.Contains(out, "does not support the ATA Security") {
		t.Errorf("execute: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "j")); err == nil {
		t.Error("refused erase created a journal")
	}
	// Not ATA: NVMe, virtio. ata commands refuse; the plan says why hidden areas don't apply.
	for serial, want := range map[string]string{"SHUNYA-NVME-01": "NVMe drive", "SHUNYA-VIRTIO-01": "virtio disk"} {
		dev := pathOf(t, env, serial)
		if out := shunya(t, 1, "ata", "identify", dev); !strings.Contains(out, want) {
			t.Errorf("%s identify: %s", serial, out)
		}
		if out := shunya(t, 0, "wipe", dev); !strings.Contains(out, want) {
			t.Errorf("%s plan: %s", serial, out)
		}
		if out := shunya(t, 2, "wipe", "--method", "ata-secure-erase", dev); !strings.Contains(out, "needs an ATA drive") {
			t.Errorf("%s erase: %s", serial, out)
		}
	}
	// USB mass storage without SAT (QEMU usb-storage): IDENTIFY comes back empty or is
	// refused; the plan discloses it and the overwrite remains available.
	usb := pathOf(t, env, "SHUNYA-USB-01")
	out = shunya(t, 0, "wipe", usb)
	if !strings.Contains(out, "does not answer ATA commands") && !strings.Contains(out, "USB bridge") {
		t.Errorf("usb plan: %s", out)
	}
	t.Log(out)
}
