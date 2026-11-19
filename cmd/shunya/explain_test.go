package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/ata"
	"shunya/internal/backend"
	"shunya/internal/cert"
	"shunya/internal/device"
	"shunya/internal/engine"
	"shunya/internal/keys"
	"shunya/internal/logclient"
	"shunya/internal/sysfs/sysfstest"
)

// guardText is the guard's real refusal for a device of a fake-sysfs scenario.
func guardText(t *testing.T, scenario, path string) string {
	t.Helper()
	fs, err := sysfstest.Load(filepath.Join("..", "..", "internal", "device", "testdata", "sysfs", scenario+".spec"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := backend.Check(backend.Env{FS: fs}, path)
	if err != nil {
		t.Fatal(err)
	}
	if v.Allowed {
		t.Fatalf("%s %s allowed", scenario, path)
	}
	return strings.Join(v.Reasons, "\n")
}

// Every explanation is reached from the message the real code produces, so rewording
// a message without updating its rule fails here.
func TestExplainRealMessages(t *testing.T) {
	frozen := &ata.Identify{Security: ata.Security{Supported: true, Frozen: true}}
	foreign := &ata.Identify{Security: ata.Security{Supported: true, Enabled: true}}
	conf := backend.Confirmation{Typed: "zzzz"}
	cases := []struct {
		name, text, want string
	}{
		{"root disk", guardText(t, "lab-vm", "/dev/vda"), "runs the computer you are using"},
		{"mounted", guardText(t, "workstation", "/dev/sdb"), "file system that is in use"},
		{"raid member", guardText(t, "server", "/dev/sda"), "RAID, LVM"},
		{"swap", guardText(t, "wsl", "/dev/sdc"), "swap memory"},
		{"ATA frozen", ata.CheckErase(frozen, false, false).Error(), "security is frozen"},
		{"sanitize frozen", ata.SanitizeFrozenHelp, "sanitize is frozen"},
		{"foreign password", ata.CheckErase(foreign, false, false).Error(), "password that Shunya did not set"},
		{"identity", fmt.Errorf("x: %w: serial", backend.ErrIdentityChanged).Error(), "changed between choosing it"},
		{"journal on target", fmt.Errorf("%w: /mnt is on device 8:16", engine.ErrJournalOnTarget).Error(), "journal would be on the disk"},
		{"confirmation", conf.Check(&device.Device{Path: "/dev/sdb", Serial: "ABC123"}).Error(), "not confirmed"},
		{"log down", fmt.Errorf("%w: dial tcp", logclient.ErrUnreachable).Error(), "could not be reached"},
		{"revoked", fmt.Errorf("seed request refused: %w", keys.ErrRevoked).Error(), "revoked by the organisation"},
		{"dev key", cert.ErrDevKey.Error(), "no certificate from the organisation's root"},
	}
	if !backend.RequiresConfirmation() { // dev builds: the lab lock refuses outside the VM
		cases = append(cases, struct{ name, text, want string }{"lab lock", guardText(t, "workstation", "/dev/sdc"), "development build"})
	}
	for _, c := range cases {
		ex := Explain(c.text)
		if !anyContains(ex, c.want) {
			t.Errorf("%s: %q\n  explanations %+v, want %q", c.name, c.text, ex, c.want)
		}
		for _, e := range ex {
			if e.What == "" || e.Why == "" || e.Do == "" {
				t.Errorf("%s: incomplete explanation %+v", c.name, e)
			}
		}
	}
	if ex := Explain("all good"); len(ex) != 0 {
		t.Errorf("unrelated text explained: %+v", ex)
	}
}

func anyContains(ex []Explanation, s string) bool {
	for _, e := range ex {
		if strings.Contains(e.What, s) {
			return true
		}
	}
	return false
}

// The CLI prints the explanation after a failed wipe (here: a journal on the image).
func TestWipeExplainsFailure(t *testing.T) {
	f := newFixture(t, 1<<20)
	code, _, errs := runCLI(t, "wipe", "--execute", "--image", f.img, "--journal", f.img, "--key", f.key)
	if code == 0 || !strings.Contains(errs, "WHAT HAPPENED: The progress journal would be on the disk being wiped") || !strings.Contains(errs, "what to do:") {
		t.Fatalf("%d\n%s", code, errs)
	}
}
