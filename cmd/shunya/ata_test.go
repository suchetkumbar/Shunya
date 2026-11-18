package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shunya/internal/ata"
	"shunya/internal/ata/atafake"
	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/engine"
)

// CLI tests against the simulated SATA drive (internal/ata/atafake): HPA handling and
// ATA Security Erase end to end, which QEMU cannot emulate. Labelled
// pending-real-hardware in design/LAB_CAPABILITIES.md.

const fakePath = "/dev/fake-sda"

// fakeATA is what backend.Block is for a real drive: the kernel's view of the disk plus
// SG_IO, with the same allowlist and dry-run rule.
type fakeATA struct {
	*atafake.Visible
	d       *atafake.Drive
	execute bool
}

func (f fakeATA) PassThrough(ctx context.Context, cdb [16]byte, data []byte, timeout time.Duration) ([]byte, error) {
	c, err := backend.CheckATA(cdb, data)
	if err != nil {
		return nil, err
	}
	if c.Mutating && !f.execute {
		return nil, backend.ErrDryRun
	}
	return f.d.PassThrough(ctx, cdb, data, timeout)
}

type fakeSetup struct {
	o      atafake.Options
	media  device.MediaType
	serial string // what "sysfs" reports; default the dump's serial
	size   int64  // what the kernel sees; default Sectors × 512
	tr     device.Transport
}

func withDrive(t *testing.T, s fakeSetup) *atafake.Drive {
	t.Helper()
	old := sanitizePoll
	sanitizePoll = time.Millisecond
	t.Cleanup(func() { sanitizePoll = old })
	dump, err := os.ReadFile(filepath.Join("..", "..", "internal", "ata", "testdata", "identify", "samsung-hd321kj.txt"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := atafake.New(dump, s.o)
	if err != nil {
		t.Fatal(err)
	}
	if s.serial == "" {
		s.serial = "S0ZEJ1NP601353"
	}
	if s.size == 0 {
		s.size = int64(s.o.Sectors) * 512
	}
	if s.media == "" {
		s.media = device.MediaHDD
	}
	if s.tr == "" {
		s.tr = device.TransportSATA
	}
	id := backend.Identity{Path: fakePath, DevNum: "8:0", Model: "SAMSUNG HD321KJ", Serial: s.serial, SizeBytes: uint64(s.size),
		Fingerprint: device.ComputeFingerprint(device.FingerprintInput{Model: "SAMSUNG HD321KJ", Serial: s.serial, CapacityBytes: uint64(s.size)}).Value}
	testDevice = func(p string) (*targetSpec, bool) {
		if p != fakePath {
			return nil, false
		}
		return &targetSpec{path: fakePath, id: id, media: s.media, size: s.size, sector: 512, transport: s.tr, firmware: "CP100-11",
			opener: func(execute bool) (backend.Target, error) {
				return fakeATA{Visible: d.Visible(id, execute), d: d, execute: execute}, nil
			}}, true
	}
	t.Cleanup(func() { testDevice = nil })
	return d
}

func setMaxCount(d *atafake.Drive) int {
	return strings.Count(strings.Join(d.Log, ","), "SET MAX EXT")
}

func oldSectors(d *atafake.Drive, from, to uint64) int {
	n := 0
	for lba := from; lba < to; lba++ {
		if bytes.Equal(d.Sector(lba), atafake.OldSector(lba)) {
			n++
		}
	}
	return n
}

func TestATAIdentifyDump(t *testing.T) {
	p := filepath.Join("..", "..", "internal", "ata", "testdata", "identify", "intel-ssdsa2ct040g3.txt")
	code, out, errs := runCLI(t, "ata", "identify", "--dump", p)
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"INTEL SSDSA2CT040G3", "solid state", "frozen true", "suspend the machine to RAM", "checksum:  valid"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "ata", "identify", "--json", "--dump", p)
	var id ata.Identify
	if code != 0 || json.Unmarshal([]byte(out), &id) != nil || id.Sectors() != 78165360 {
		t.Fatalf("json: %d %s", code, out)
	}
}

func TestATAHiddenAndIdentifyDevice(t *testing.T) {
	d := withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096, NativeSectors: 4224, DCO: true, DCOSectors: 5000}})
	code, out, errs := runCLI(t, "ata", "hidden", "--confirm", "1353", fakePath)
	if code != 0 || !strings.Contains(out, "HPA hides 128 sectors") || !strings.Contains(out, "DCO hides 776") || !strings.Contains(out, "fp2:") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	save := filepath.Join(t.TempDir(), "id.txt")
	if code, _, errs := runCLI(t, "ata", "identify", "--save", save, "--confirm", "1353", fakePath); code != 0 {
		t.Fatal(errs)
	}
	if code, out, _ := runCLI(t, "ata", "identify", "--dump", save); code != 0 || !strings.Contains(out, "4096 sectors") {
		t.Fatalf("saved dump: %s", out)
	}
	if setMaxCount(d) != 0 {
		t.Fatal("read-only commands changed the max address")
	}
}

func TestWipeHPADryRun(t *testing.T) {
	d := withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096, NativeSectors: 4224}})
	code, out, errs := runCLI(t, "wipe", "--confirm", "1353", fakePath)
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"HPA hides 128 sectors", "removed for the wipe (volatile), then restored", "opened read-only for ATA IDENTIFY", "2.1MiB"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if setMaxCount(d) != 0 || oldSectors(d, 0, 4224) != 4224 {
		t.Fatal("dry run changed the drive")
	}
	code, out, _ = runCLI(t, "wipe", "--json", "--confirm", "1353", fakePath)
	var p engine.Plan
	if code != 0 || json.Unmarshal([]byte(out), &p) != nil || p.SizeBytes != 4224*512 || !p.Hidden.RemoveHPA || p.Hidden.VisibleBytes != 4096*512 {
		t.Fatalf("json plan: %s", out)
	}
}

func TestWipeHPARestore(t *testing.T) {
	d := withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096, NativeSectors: 4224, OneSetMax: false}})
	f := newFixture(t, 512)
	code, out, errs := runCLI(t, "wipe", "--execute", "--verify", "--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath)
	if code != 0 {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	if n := oldSectors(d, 0, 4224); n != 0 {
		t.Fatalf("%d sectors still hold old data (hidden range from 4096)", n)
	}
	if cur, _, _, _ := d.State(); cur != 4096 {
		t.Fatalf("HPA not restored: %d", cur)
	}
	for _, want := range []string{"HPA removed for this power cycle", "VERIFIED (full)", "HPA restored"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if d.NonVolatileAttempts != 0 {
		t.Fatal("non-volatile SET MAX")
	}
	code, out, _ = runCLI(t, "journal", "show", "--key", f.key, f.journal)
	if code != 0 || !strings.Contains(out, "hpa-removed") || !strings.Contains(out, "hpa-restored") || !strings.Contains(out, "COMPLETE") {
		t.Fatalf("journal show: %s", out)
	}
	// Later verification: the HPA is back, so only the visible range is read, and the
	// record says so.
	code, out, errs = runCLI(t, "verify", "--sample", "64", "--seed", strings.Repeat("ab", 16), "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(out, "visible range only") {
		t.Fatalf("verify: %d %s %s", code, out, errs)
	}
	if setMaxCount(d) != 2 {
		t.Fatalf("verify changed the max address: %v", d.Log)
	}
}

func TestWipeHPALeaveRemovedAndSkip(t *testing.T) {
	d := withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096, NativeSectors: 4224}})
	f := newFixture(t, 512)
	if code, out, errs := runCLI(t, "wipe", "--execute", "--hpa", "leave-removed", "--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath); code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if cur, _, _, _ := d.State(); cur != 4224 {
		t.Fatalf("current %d, want 4224 (left removed)", cur)
	}
	code, out, _ := runCLI(t, "verify", "--journal", f.journal, "--key", f.key)
	if code != 0 || strings.Contains(out, "visible range only") || !strings.Contains(out, "2.1MiB read back") {
		t.Fatalf("verify of the whole native range: %d %s", code, out)
	}

	d = withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096, NativeSectors: 4224}})
	f = newFixture(t, 512)
	code, out, errs := runCLI(t, "wipe", "--execute", "--hpa", "skip", "--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath)
	if code != 0 || !strings.Contains(out, "NOT wiped (the operator chose --hpa skip)") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if oldSectors(d, 0, 4096) != 0 || oldSectors(d, 4096, 4224) != 128 || setMaxCount(d) != 0 {
		t.Fatal("--hpa skip: visible must be wiped, hidden untouched")
	}
}

func TestWipeIdentityRefusals(t *testing.T) {
	f := newFixture(t, 512)
	withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096}, serial: "SOMEONE-ELSE"})
	if code, _, errs := runCLI(t, "wipe", "--confirm", "1353", fakePath); code != 1 || !strings.Contains(errs, "IDENTIFY serial") {
		t.Fatalf("serial mismatch: %d %s", code, errs)
	}
	withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096}, size: 4000 * 512})
	if code, _, errs := runCLI(t, "wipe", "--confirm", "1353", fakePath); code != 1 || !strings.Contains(errs, "Power-cycle the drive") {
		t.Fatalf("size mismatch: %d %s", code, errs)
	}
	// USB bridge without SAT: no ATA, overwrite still possible, hidden areas disclosed.
	withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096, NoSAT: true}, tr: device.TransportUSB})
	code, out, _ := runCLI(t, "wipe", "--confirm", "1353", fakePath)
	if code != 0 || !strings.Contains(out, "does not answer ATA commands") {
		t.Fatalf("usb: %d %s", code, out)
	}
	if code, _, errs := runCLI(t, "wipe", "--method", "ata-secure-erase", "--confirm", "1353", fakePath); code != 2 || !strings.Contains(errs, "needs an ATA drive") {
		t.Fatalf("erase over usb: %d %s", code, errs)
	}
	// Not ATA at all.
	withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096}, tr: device.TransportVirtio})
	if code, out, _ := runCLI(t, "wipe", "--confirm", "1353", fakePath); code != 0 || !strings.Contains(out, "virtio disk: the hypervisor presents no ATA") {
		t.Fatalf("virtio: %d %s", code, out)
	}
	if code, _, _ := runCLI(t, "wipe", "--method", "ata-secure-erase", "--image", f.img); code != 2 {
		t.Fatal("secure erase of an image accepted")
	}
}

func eraseDrive(t *testing.T, media device.MediaType) *atafake.Drive {
	return withDrive(t, fakeSetup{media: media, o: atafake.Options{Sectors: 4096, NativeSectors: 4160, Security: true, Enhanced: true,
		EnhancedFill: 0x6b, EraseMinutes: 4}})
}

func TestWipeSecureErase(t *testing.T) {
	d := eraseDrive(t, device.MediaHDD)
	f := newFixture(t, 512)
	code, out, _ := runCLI(t, "wipe", "--method", "ata-secure-erase", "--confirm", "1353", fakePath)
	if code != 0 || !strings.Contains(out, "NIST level:  Purge") || !strings.Contains(out, "firmware erase") {
		t.Fatalf("dry run: %d %s", code, out)
	}
	if strings.Contains(strings.Join(d.Log, ","), "SECURITY") {
		t.Fatal("dry run sent a Security command")
	}
	code, out, errs := runCLI(t, "wipe", "--method", "ata-secure-erase", "--execute", "--sample", "100", "--seed", strings.Repeat("cd", 16),
		"--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath)
	if code != 0 {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	for lba := uint64(0); lba < 4160; lba++ {
		if !bytes.Equal(d.Sector(lba), make([]byte, 512)) {
			t.Fatalf("sector %d not zero (hidden range starts at 4096)", lba)
		}
	}
	if cur, en, locked, _ := d.State(); cur != 4096 || en || locked {
		t.Fatalf("after: max %d enabled %v locked %v", cur, en, locked)
	}
	for _, want := range []string{"DONE: ATA Security Erase (normal)", "NIST SP 800-88 level: Purge", "VERIFIED (sampled)", "HPA restored"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "journal", "show", "--key", f.key, f.journal)
	if code != 0 || !strings.Contains(out, "security steps journaled: 5 (last: security-checked)") {
		t.Fatalf("journal: %s", out)
	}
	if code, out, _ := runCLI(t, "verify", "--journal", f.journal, "--key", f.key); code != 0 || !strings.Contains(out, "match the zero pattern") {
		t.Fatalf("verify: %d %s", code, out)
	}
}

func TestWipeEnhancedEraseSSD(t *testing.T) {
	d := eraseDrive(t, device.MediaSSD)
	f := newFixture(t, 512)
	code, out, _ := runCLI(t, "wipe", "--method", "ata-enhanced-secure-erase", "--confirm", "1353", fakePath)
	if code != 0 || !strings.Contains(out, "NIST level:  Clear") || !strings.Contains(out, "vendor-defined") {
		t.Fatalf("ssd plan: %d %s", code, out)
	}
	if code, _, _ := runCLI(t, "wipe", "--method", "ata-enhanced-secure-erase", "--verify", "--confirm", "1353", fakePath); code != 2 {
		t.Fatal("--verify of an enhanced erase accepted")
	}
	if code, out, errs := runCLI(t, "wipe", "--method", "ata-enhanced-secure-erase", "--execute", "--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath); code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if !bytes.Equal(d.Sector(4100), bytes.Repeat([]byte{0x6b}, 512)) {
		t.Fatal("hidden range not erased")
	}
	// Nothing to compare after an enhanced erase: a pattern check is refused, the marker
	// check (planted before the erase) still runs.
	if code, _, _ := runCLI(t, "verify", "--full", "--journal", f.journal, "--key", f.key); code != 2 {
		t.Fatal("pattern verify of an enhanced erase accepted")
	}
	if code, out, _ := runCLI(t, "verify", "--journal", f.journal, "--key", f.key); code != 0 || !strings.Contains(out, "VERIFIED (markers)") {
		t.Fatalf("marker verify: %d %s", code, out)
	}
}

func TestWipeSecureEraseFrozen(t *testing.T) {
	d := withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096, Security: true, FreezeOnBoot: true}})
	f := newFixture(t, 512)
	code, out, _ := runCLI(t, "wipe", "--method", "ata-secure-erase", "--confirm", "1353", fakePath)
	if code != 1 || !strings.Contains(out, "PRECONDITIONS NOT MET") || !strings.Contains(out, "suspend the machine to RAM") {
		t.Fatalf("dry run: %d %s", code, out)
	}
	code, _, errs := runCLI(t, "wipe", "--method", "ata-secure-erase", "--execute", "--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath)
	if code != 1 || !strings.Contains(errs, "FROZEN") {
		t.Fatalf("execute: %d %s", code, errs)
	}
	if _, err := os.Stat(f.journal); err == nil {
		t.Fatal("a refused erase created a journal")
	}
	if strings.Contains(strings.Join(d.Log, ","), "SECURITY") {
		t.Fatal("a Security command reached a frozen drive")
	}
}

// Power lost during ERASE UNIT: the drive comes back locked with Shunya's temporary
// password. ata unlock recovers it from the journal; wipe --resume erases again.
func TestWipeSecureEraseCrashUnlockResume(t *testing.T) {
	d := eraseDrive(t, device.MediaHDD)
	f := newFixture(t, 512)
	d.Before = func(c uint8) error {
		if c == ata.CmdSecurityEraseUnit {
			return errors.New("power lost")
		}
		return nil
	}
	code, out, _ := runCLI(t, "wipe", "--method", "ata-secure-erase", "--execute", "--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath)
	if code != 1 || !strings.Contains(out, "shunya ata unlock --journal") || !strings.Contains(out, "HPA stays removed") {
		t.Fatalf("%d %s", code, out)
	}
	d.Before = nil
	d.PowerCycle()
	if _, en, locked, _ := d.State(); !en || !locked {
		t.Fatal("expected a locked drive")
	}
	code, out, errs := runCLI(t, "ata", "unlock", "--execute", "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(out, "NOT complete") {
		t.Fatalf("unlock: %d %s %s", code, out, errs)
	}
	if _, en, _, _ := d.State(); en {
		t.Fatal("still enabled after unlock")
	}
	code, out, errs = runCLI(t, "wipe", "--resume", "--execute", "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(out, "DONE: ATA Security Erase") {
		t.Fatalf("resume: %d\n%s\n%s", code, out, errs)
	}
	if n := oldSectors(d, 0, 4160); n != 0 || !bytes.Equal(d.Sector(4150), make([]byte, 512)) {
		t.Fatalf("%d old sectors after the resumed erase", n)
	}
	if cur, _, _, _ := d.State(); cur != 4096 {
		t.Fatalf("HPA not restored after resume: %d", cur)
	}
	code, out, _ = runCLI(t, "journal", "show", "--key", f.key, f.journal)
	if code != 0 || !strings.Contains(out, "COMPLETE") || !strings.Contains(out, "interruptions: 1") {
		t.Fatalf("journal: %s", out)
	}
}

// Resume straight after the power cycle, without ata unlock: the erase unlocks the
// drive with the journaled password itself.
func TestWipeSecureEraseResumeLocked(t *testing.T) {
	d := eraseDrive(t, device.MediaHDD)
	f := newFixture(t, 512)
	d.Before = func(c uint8) error {
		if c == ata.CmdSecurityEraseUnit {
			return errors.New("power lost")
		}
		return nil
	}
	runCLI(t, "wipe", "--method", "ata-secure-erase", "--execute", "--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath)
	d.Before = nil
	d.PowerCycle()
	code, out, errs := runCLI(t, "wipe", "--resume", "--execute", "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(out, "last journaled step: erase-unit") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(strings.Join(d.Log, ","), "SECURITY UNLOCK") || oldSectors(d, 0, 4160) != 0 {
		t.Fatal("resume did not unlock and erase")
	}
}
