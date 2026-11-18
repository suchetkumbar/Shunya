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

	"shunya/internal/ata/atafake"
	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/engine"
	"shunya/internal/nvme"
	"shunya/internal/nvme/nvmefake"
)

// CLI tests against the simulated NVMe controller (Sanitize is pending-real-hardware:
// QEMU has none).

const nvmePath = "/dev/nvme9n1"

// fakeNVMe is the namespace block device plus NVME_IOCTL_ADMIN_CMD, with the backend's
// allowlist and dry-run rule.
type fakeNVMe struct {
	*nvmefake.Visible
	c       *nvmefake.Controller
	execute bool
}

func (f fakeNVMe) AdminCommand(ctx context.Context, c nvme.AdminCmd, data []byte) (uint32, nvme.Status, error) {
	k, err := backend.CheckNVMe(c, data)
	if err != nil {
		return 0, 0, err
	}
	if k.Mutating && !f.execute {
		return 0, 0, backend.ErrDryRun
	}
	return f.c.AdminCommand(ctx, c, data)
}

type nvmeSetup struct {
	o       nvmefake.Options
	virtual bool
	serial  string
}

func withNVMe(t *testing.T, s nvmeSetup) *nvmefake.Controller {
	t.Helper()
	old := sanitizePoll
	sanitizePoll = time.Millisecond
	t.Cleanup(func() { sanitizePoll = old })
	td := filepath.Join("..", "..", "internal", "nvme", "testdata")
	cb, _ := os.ReadFile(filepath.Join(td, "qemu-id-ctrl.bin"))
	nb, _ := os.ReadFile(filepath.Join(td, "qemu-id-ns.bin"))
	c, err := nvmefake.New(cb, nb, s.o)
	if err != nil {
		t.Fatal(err)
	}
	if s.serial == "" {
		s.serial = "SHUNYA-NVME-01"
	}
	bs := s.o.BlockBytes
	if bs == 0 {
		bs = 512
	}
	size := int64(s.o.Blocks) * int64(bs)
	id := backend.Identity{Path: nvmePath, DevNum: "259:0", Model: "QEMU NVMe Ctrl", Serial: s.serial, WWID: "eui.5348554e59410001",
		SizeBytes: uint64(size), Fingerprint: "fp1:nvme-test-" + s.serial}
	testDevice = func(p string) (*targetSpec, bool) {
		if p != nvmePath {
			return nil, false
		}
		return &targetSpec{path: nvmePath, id: id, media: device.MediaNVMeSSD, virtual: s.virtual, size: size, sector: bs,
			transport: device.TransportNVMe, firmware: "10.0.13",
			opener: func(execute bool) (backend.Target, error) {
				return fakeNVMe{Visible: c.Visible(id, execute), c: c, execute: execute}, nil
			}}, true
	}
	t.Cleanup(func() { testDevice = nil })
	return c
}

func oldBlocks(c *nvmefake.Controller, n uint64, bs int) int {
	k := 0
	for lba := uint64(0); lba < n; lba++ {
		if bytes.Equal(c.Block(lba), nvmefake.OldBlock(lba, bs)) {
			k++
		}
	}
	return k
}

var conf = []string{"--confirm", "e-01"} // serial SHUNYA-NVME-01

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	// Device-taking commands get the release-build confirmation before the path.
	if n := len(args); n > 0 && args[n-1] == nvmePath {
		args = append(append(args[:n-1:n-1], conf...), nvmePath)
	}
	return runCLI(t, args...)
}

func TestNVMeIdentifyCLI(t *testing.T) {
	td := filepath.Join("..", "..", "internal", "nvme", "testdata")
	code, out, errs := runCLI(t, "nvme", "identify", "--ctrl", filepath.Join(td, "qemu-id-ctrl.bin"), "--ns", filepath.Join(td, "qemu-id-ns.bin"))
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"QEMU NVMe Ctrl", "SHUNYA-NVME-01", "crypto erase false, block erase false", "deallocated blocks read as: zeros", "2097152 blocks of 512 bytes"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 2048}})
	dir := t.TempDir()
	if code, out, errs := cli(t, "nvme", "identify", "--save-dir", dir, nvmePath); code != 0 || !strings.Contains(out, "namespace: 1, 2048 blocks") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "id-ctrl.bin")); len(b) != 4096 {
		t.Fatal("id-ctrl.bin not saved")
	}
	if code, out, _ := cli(t, "nvme", "sanitize-log", nvmePath); code != 0 || !strings.Contains(out, "never sanitized") {
		t.Fatalf("sanitize-log: %d %s", code, out)
	}
}

func TestPlanNVMe(t *testing.T) {
	// As the lab's QEMU drive: virtual, no Sanitize, crypto format "succeeds" but FNA=0.
	withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 2048, CryptoLies: true, DeallocRead: 1}, virtual: true})
	code, out, errs := cli(t, "plan", nvmePath)
	if code != 0 || !strings.Contains(out, "RECOMMENDED: nvme-format-user-data-erase") || !strings.Contains(out, "virtual") ||
		!strings.Contains(out, "FNA bit 2") || !strings.Contains(out, "SANICAP = 0") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 2048, SanitizeCrypto: true, SanitizeBlock: true, FNA: 4, DeallocRead: 1}})
	code, out, _ = cli(t, "plan", "--json", nvmePath)
	var r engine.Recommendation
	if code != 0 || json.Unmarshal([]byte(out), &r) != nil || r.Best != engine.MethodNVMeSanitizeCrypto || r.Options[0].Level != engine.LevelPurge {
		t.Fatalf("%d %s", code, out)
	}
}

func TestWipeNVMeSanitize(t *testing.T) {
	c := withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 2048, SanitizeBlock: true, DeallocRead: 1, SanitizePolls: 3}})
	f := newFixture(t, 512)
	code, out, _ := cli(t, "wipe", "--method", "nvme-sanitize-block-erase", nvmePath)
	if code != 0 || !strings.Contains(out, "NIST level:  Purge") || !strings.Contains(out, "opened read-only for NVMe Identify") || c.Sanitizes != 0 {
		t.Fatalf("dry run: %d %s", code, out)
	}
	code, out, errs := cli(t, "wipe", "--method", "nvme-sanitize-block-erase", "--execute", "--sample", "64", "--seed", strings.Repeat("ab", 16),
		"--journal", f.journal, "--key", f.key, nvmePath)
	if code != 0 {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"planted 1024 markers", "DONE: nvme-sanitize-block-erase completed. NIST SP 800-88 level: Purge", "VERIFIED (markers)", "VERIFIED (sampled)"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if n := oldBlocks(c, 2048, 512); n != 0 || c.Sanitizes != 1 {
		t.Fatalf("%d old blocks, %d sanitizes", n, c.Sanitizes)
	}
	code, out, _ = runCLI(t, "journal", "show", "--key", f.key, f.journal)
	if code != 0 || !strings.Contains(out, "markers planted true") || !strings.Contains(out, "sanitize-completed") || !strings.Contains(out, "COMPLETE") {
		t.Fatalf("journal: %s", out)
	}
	if code, out, _ := runCLI(t, "verify", "--journal", f.journal, "--key", f.key); code != 0 || !strings.Contains(out, "VERIFIED (markers)") || !strings.Contains(out, "VERIFIED (full)") {
		t.Fatalf("verify: %d %s", code, out)
	}
}

// The machine crashes while the drive sanitizes; the drive carries on. The resume waits
// for it instead of starting another one.
func TestWipeNVMeSanitizeResume(t *testing.T) {
	c := withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 1024, SanitizeCrypto: true, SanitizePolls: 4}})
	f := newFixture(t, 512)
	started := false
	c.Before = func(op uint8) error {
		if op == nvme.OpSanitize {
			started = true
		} else if started && op == nvme.OpGetLogPage {
			return errors.New("host crashed")
		}
		return nil
	}
	code, out, _ := cli(t, "wipe", "--method", "nvme-sanitize-crypto-erase", "--execute", "--journal", f.journal, "--key", f.key, nvmePath)
	if code != 1 || !strings.Contains(out, "resume with") {
		t.Fatalf("%d %s", code, out)
	}
	c.Before = nil
	code, out, errs := runCLI(t, "wipe", "--resume", "--execute", "--journal", f.journal, "--key", f.key)
	if code != 0 || c.Sanitizes != 1 || !strings.Contains(out, "VERIFIED (markers)") {
		t.Fatalf("resume: %d sanitizes %d\n%s\n%s", code, c.Sanitizes, out, errs)
	}
	_, out, _ = runCLI(t, "journal", "show", "--key", f.key, f.journal)
	if !strings.Contains(out, "sanitize-waiting") || !strings.Contains(out, "interruptions: 1") {
		t.Fatalf("journal: %s", out)
	}
}

func TestWipeNVMeFailedSanitize(t *testing.T) {
	withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 1024, SanitizeBlock: true, SanitizeFails: true}})
	f := newFixture(t, 512)
	code, out, _ := cli(t, "wipe", "--method", "nvme-sanitize-block-erase", "--execute", "--journal", f.journal, "--key", f.key, nvmePath)
	if code != 1 || !strings.Contains(out, "FAILED") || !strings.Contains(out, "failure mode") {
		t.Fatalf("%d %s", code, out)
	}
	_, out, _ = runCLI(t, "journal", "show", "--key", f.key, f.journal)
	if !strings.Contains(out, "sanitize-failed") || strings.Contains(out, "status: COMPLETE") {
		t.Fatalf("journal: %s", out)
	}
}

func TestWipeNVMeFormat(t *testing.T) {
	// QEMU-like: crypto format refused although the controller would accept it.
	c := withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 1024, BlockBytes: 4096, CryptoLies: true, DeallocRead: 1}, virtual: true})
	f := newFixture(t, 512)
	if code, _, errs := cli(t, "wipe", "--method", "nvme-format-crypto-erase", nvmePath); code != 2 || !strings.Contains(errs, "FNA bit 2") {
		t.Fatalf("crypto: %d %s", code, errs)
	}
	code, out, errs := cli(t, "wipe", "--method", "nvme-format-user-data-erase", "--execute", "--verify", "--journal", f.journal, "--key", f.key, nvmePath)
	if code != 0 || !strings.Contains(out, "NIST SP 800-88 level: Clear") || !strings.Contains(out, "VERIFIED (full)") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	if oldBlocks(c, 1024, 4096) != 0 || c.Formats != 1 {
		t.Fatal("not formatted")
	}
}

func TestWipeNVMeRefusals(t *testing.T) {
	withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 1024, SanitizeBlock: true, ExtraNamespaces: 1}})
	if code, _, errs := cli(t, "wipe", "--method", "nvme-sanitize-block-erase", nvmePath); code != 2 || !strings.Contains(errs, "1 other namespace") {
		t.Fatalf("multi-ns: %d %s", code, errs)
	}
	withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 1024}, serial: "SOMEONE-ELSE"})
	if code, _, errs := cli(t, "wipe", nvmePath); code != 1 || !strings.Contains(errs, "controller serial") {
		t.Fatalf("identity: %d %s", code, errs)
	}
	withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 1024}})
	if code, _, errs := cli(t, "wipe", "--method", "nvme-sanitize-crypto-erase", nvmePath); code != 2 || !strings.Contains(errs, "SANICAP") {
		t.Fatalf("unsupported: %d %s", code, errs)
	}
	if code, _, errs := cli(t, "wipe", "--method", "ata-sanitize-block-erase", nvmePath); code != 2 || !strings.Contains(errs, "needs an ATA drive") {
		t.Fatalf("ata method on nvme: %d %s", code, errs)
	}
	if code, _, _ := cli(t, "wipe", "--method", "dco-restore", nvmePath); code != 2 {
		t.Fatal("unknown method accepted")
	}
}

func TestWipeATASanitizeCLI(t *testing.T) {
	d := withDrive(t, fakeSetup{media: device.MediaSSD, o: atafake.Options{Sectors: 4096, NativeSectors: 4160, SanitizeCrypto: true, SanitizeBlock: true,
		Security: true, Enhanced: true}})
	f := newFixture(t, 512)
	code, out, _ := runCLI(t, "plan", "--confirm", "1353", fakePath)
	if code != 0 || !strings.Contains(out, "RECOMMENDED: ata-sanitize-crypto-scramble") {
		t.Fatalf("plan: %d %s", code, out)
	}
	code, out, errs := runCLI(t, "wipe", "--method", "ata-sanitize-crypto-scramble", "--execute", "--journal", f.journal, "--key", f.key, "--confirm", "1353", fakePath)
	if code != 0 || !strings.Contains(out, "level: Purge") || !strings.Contains(out, "VERIFIED (markers)") || !strings.Contains(out, "HPA restored") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	if oldSectors(d, 0, 4160) != 0 || d.Sanitizes != 1 {
		t.Fatal("not sanitized (hidden range included)")
	}
	// Frozen sanitize: refused with the explanation.
	withDrive(t, fakeSetup{o: atafake.Options{Sectors: 4096, SanitizeBlock: true, SanitizeFrozen: true}})
	if code, _, errs := runCLI(t, "wipe", "--method", "ata-sanitize-block-erase", "--execute", "--journal", filepath.Join(t.TempDir(), "j"), "--key", f.key,
		"--confirm", "1353", fakePath); code != 1 || !strings.Contains(errs, "Sanitize FROZEN") {
		t.Fatalf("frozen: %d %s", code, errs)
	}
}

// A controller that returns from Format NVM with different geometry: the wipe fails
// instead of certifying a namespace that is no longer the one planned.
func TestWipeNVMeFormatGeometryChange(t *testing.T) {
	withNVMe(t, nvmeSetup{o: nvmefake.Options{Blocks: 1024, DeallocRead: 1, FormatResizes: true}})
	f := newFixture(t, 512)
	code, out, _ := cli(t, "wipe", "--method", "nvme-format-user-data-erase", "--execute", "--journal", f.journal, "--key", f.key, nvmePath)
	if code != 1 || !strings.Contains(out, "after the format the namespace is 512") {
		t.Fatalf("%d %s", code, out)
	}
}
