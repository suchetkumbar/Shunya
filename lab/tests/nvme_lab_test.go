//go:build labtest && linux

package labtests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/device"
	"shunya/internal/engine"
	"shunya/internal/nvme"
)

// Milestone 6 in the lab. QEMU's NVMe controller answers Identify, accepts Format NVM
// (and zeroes the namespace), reports SANICAP = 0, FNA = 0 and refuses the Sanitize
// Status log (design/LAB_CAPABILITIES.md). So the lab proves the real
// NVME_IOCTL_ADMIN_CMD path, the parsers on a live controller, a real Format NVM user
// data erase with read-back, and every refusal; Sanitize itself is proven against the
// simulated controller only (pending-real-hardware).

func TestLabNVMeIdentify(t *testing.T) {
	env := inLab(t)
	dev := pathOf(t, env, "SHUNYA-NVME-01")
	rep, err := device.EnumerateWith(env.FS, device.Options{Protect: env.Protect})
	if err != nil {
		t.Fatal(err)
	}
	var d device.Device
	for _, x := range rep.Devices {
		if x.Path == dev {
			d = x
		}
	}
	save := filepath.Join(results(t), "nvme")
	out := shunya(t, 0, "nvme", "identify", "--json", "--save-dir", save, dev)
	var got struct {
		Controller nvme.Controller `json:"controller"`
		Namespace  nvme.Namespace  `json:"namespace"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	c, n := got.Controller, got.Namespace
	// The kernel reports "eui.<EUI-64>" or, as on this QEMU, an "nvme.<vid>-<serial>-<model>-<nsid>" WWID.
	if c.Serial != d.Serial || c.Model != d.Model || n.SizeBytes() != d.SizeBytes || (strings.HasPrefix(d.WWID, "eui.") && "eui."+n.EUI64 != d.WWID) {
		t.Errorf("Identify %q %q %d eui %s; sysfs %q %q %d %s", c.Serial, c.Model, n.SizeBytes(), n.EUI64, d.Serial, d.Model, d.SizeBytes, d.WWID)
	}
	if c.Sanicap.Any() || c.FNA.CryptoErase || !c.FormatSupported || n.DeallocRead != 1 {
		t.Errorf("capabilities changed from the recorded QEMU data: %+v %+v", c.Sanicap, c.FNA)
	}
	// The live data parses exactly like the recorded testdata (same QEMU version).
	b, _ := os.ReadFile(filepath.Join(save, "id-ctrl.bin"))
	if cc, err := nvme.ParseController(b); err != nil || cc.SubNQN != c.SubNQN {
		t.Errorf("saved id-ctrl: %v", err)
	}
	t.Logf("%s: %s, NVMe %s, %d × %d B, SANICAP %#x, FNA %#x", dev, c.Model, c.Version, n.Size, n.BlockBytes(), c.Sanicap.Raw, c.FNA.Raw)
}

// A real Format NVM (user data erase) through the guarded backend, verified by full
// read-back (DLFEAT: deallocated blocks read as zeros) and by the markers.
func TestLabNVMeFormat(t *testing.T) {
	env := inLab(t)
	dev := pathOf(t, env, "SHUNYA-NVME-01")
	dir, key := workDir(t)
	j := filepath.Join(dir, "format.journal")
	out := shunya(t, 0, "wipe", "--method", "nvme-format-user-data-erase", "--execute", "--verify", "--journal", j, "--key", key, dev)
	for _, want := range []string{"planted 1024 markers", "FORMAT NVM (user data erase)", "NIST SP 800-88 level: Clear", "VERIFIED (markers)", "VERIFIED (full)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	st := journalState(t, key, j)
	if !st.Done || !st.MarkersPlanted || !st.FirmwareDone || st.Plan.Level != engine.LevelClear || len(st.Verifications) != 2 {
		t.Errorf("journal state: %+v", st)
	}
	t.Log(out)
}

func TestLabNVMeRefusalsAndPlans(t *testing.T) {
	env := inLab(t)
	dev := pathOf(t, env, "SHUNYA-NVME-01")
	// FNA bit 2 is clear: QEMU would "succeed", Shunya refuses.
	if out := shunya(t, 2, "wipe", "--method", "nvme-format-crypto-erase", dev); !strings.Contains(out, "FNA bit 2") {
		t.Errorf("crypto format: %s", out)
	}
	for _, m := range []string{"nvme-sanitize-crypto-erase", "nvme-sanitize-block-erase", "nvme-sanitize-overwrite"} {
		if out := shunya(t, 2, "wipe", "--method", m, dev); !strings.Contains(out, "SANICAP") {
			t.Errorf("%s: %s", m, out)
		}
	}
	if out := shunya(t, 1, "nvme", "sanitize-log", dev); !strings.Contains(out, "Invalid Field") {
		t.Errorf("sanitize-log: %s", out)
	}
	// ATA Sanitize on the QEMU SATA disks: not advertised.
	if out := shunya(t, 2, "wipe", "--method", "ata-sanitize-block-erase", pathOf(t, env, "SHUNYA-SATA-SSD-01")); !strings.Contains(out, "does not advertise") {
		t.Errorf("ata sanitize: %s", out)
	}
	// shunya plan on every target disk: read-only, and every recommendation is Clear
	// (all lab disks are virtual).
	want := map[string]string{"SHUNYA-NVME-01": "nvme-format-user-data-erase", "SHUNYA-SATA-SSD-01": "overwrite",
		"SHUNYA-SATA-HDD-01": "overwrite", "SHUNYA-VIRTIO-01": "overwrite", "SHUNYA-USB-01": "overwrite"}
	for serial, best := range want {
		out := shunya(t, 0, "plan", "--json", pathOf(t, env, serial))
		var r engine.Recommendation
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatalf("%s: %v\n%s", serial, err, out)
		}
		if r.Best != best || !strings.Contains(r.Reason, "virtual") {
			t.Errorf("%s: best %s (%s), want %s", serial, r.Best, r.Reason, best)
		}
		for _, o := range r.Options {
			if o.Level != engine.LevelClear {
				t.Errorf("%s: %s claims %s on a virtual disk", serial, o.Method, o.Level)
			}
		}
		os.WriteFile(filepath.Join(results(t), "plan-"+serial+".json"), []byte(out), 0o644)
		t.Logf("%s → %s", serial, r.Best)
	}
	t.Log(shunya(t, 0, "plan", dev))
}
