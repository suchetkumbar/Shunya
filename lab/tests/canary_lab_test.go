//go:build labtest && linux

package labtests

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shunya/internal/backend"
	"shunya/internal/canary"
)

// Milestone 4 acceptance: the forensic canary harness on real (virtual) block devices.
//
// Per case: fill the whole disk with HMAC canaries, make a file system, store the
// planted files (and delete one copy of each), then
//   - before the wipe: the raw scan must find canaries and every marker, and photorec
//     must recover every planted file intact (the test is not vacuous);
//   - wipe with shunya (one AES-CTR pass, O_DIRECT), full verify;
//   - after the wipe: no canary, no fragment, no marker, no carved file with planted
//     content.
//
// The negative case wipes with shunya-broken (test-only build that skips the last 1 %)
// and must be caught: residue in the skipped tail, and full verification fails.
func TestLabCanaryHarness(t *testing.T) {
	env := inLab(t)
	dir, key := workDir(t)
	runKey := make([]byte, canary.KeySize)
	rand.Read(runKey)
	set, err := canary.NewSet(runKey)
	if err != nil {
		t.Fatal(err)
	}
	files, err := canary.GenerateFiles(runKey[:8], 2)
	if err != nil {
		t.Fatal(err)
	}
	rep := &canary.Report{Version: 1, Started: time.Now().UTC(), Build: backend.BuildKind, Planted: files}
	cases := []struct {
		serial, fs string
		broken     bool
	}{
		{"SHUNYA-VIRTIO-01", "ext4", false},
		{"SHUNYA-VIRTIO-01", "vfat", false},
		{"SHUNYA-VIRTIO-01", "exfat", false},
		{"SHUNYA-NVME-01", "ext4", false},
		{"SHUNYA-SATA-SSD-01", "ext4", true},
	}
	for _, tc := range cases {
		name := strings.TrimPrefix(tc.serial, "SHUNYA-")
		if tc.broken {
			name += "-broken"
		}
		t.Run(name+"/"+tc.fs, func(t *testing.T) {
			start := time.Now()
			c := canary.Case{Name: name, Serial: tc.serial, FS: tc.fs, Broken: tc.broken}
			c.Device = pathOf(t, env, tc.serial)
			runCase(t, env, set, files, &c, filepath.Join(dir, name+"-"+tc.fs), key)
			c.Seconds = time.Since(start).Seconds()
			c.Evaluate(files)
			rep.Cases = append(rep.Cases, c)
			switch {
			case c.Skipped != "":
				t.Skip("SKIPPED: " + c.Skipped)
			case !c.Pass:
				t.Errorf("%s/%s: %v", name, tc.fs, c.Why)
			}
		})
	}
	rep.Finish()
	out := os.Getenv("SHUNYA_RESULTS")
	if out == "" {
		out = "results"
	}
	if err := rep.WriteFiles(out, "canary-report"); err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + rep.Summary())
	if !rep.Pass {
		t.Fatal("canary harness FAILED (see results/canary-report.txt)")
	}
}

func runCase(t *testing.T, env backend.Env, set *canary.Set, files []canary.Planted, c *canary.Case, dir, key string) {
	ctx := context.Background()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// 1. Canaries over the whole disk (through the guarded backend).
	b, err := backend.OpenBlock(env, c.Device, backend.Options{Execute: true, Direct: true})
	if err != nil {
		t.Fatal(err)
	}
	c.SizeBytes = b.Size()
	c.SkipFrom = b.Size() - b.Size()/100/int64(b.SectorSize())*int64(b.SectorSize())
	if err := canary.Plant(ctx, b, set, 4<<20); err != nil {
		t.Fatal(err)
	}
	b.Close()

	// 2. File system with the planted files; copy 1 of each is deleted again, as a
	// user would have done before handing the disk in.
	mkfs := map[string][]string{
		"ext4":  {"mkfs.ext4", "-F", "-q", "-E", "nodiscard", c.Device},
		"vfat":  {"mkfs.vfat", "-F", "32", c.Device},
		"exfat": {"mkfs.exfat", c.Device},
	}[c.FS]
	if _, err := exec.LookPath(mkfs[0]); err != nil {
		c.Skipped = mkfs[0] + " not installed in the lab VM"
		return
	}
	run(t, mkfs[0], mkfs[1:]...)
	mnt := "/mnt/shunya-canary"
	os.MkdirAll(mnt, 0o755)
	if out, err := exec.Command("mount", "-t", c.FS, c.Device, mnt).CombinedOutput(); err != nil {
		c.Skipped = fmt.Sprintf("cannot mount %s in the lab VM kernel: %s", c.FS, strings.TrimSpace(string(out)))
		return
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(mnt, f.Name), f.Data, 0o644); err != nil {
			exec.Command("umount", mnt).Run()
			t.Fatal(err)
		}
	}
	run(t, "sync")
	for _, f := range files {
		if strings.HasPrefix(f.Name, "planted-1.") {
			os.Remove(filepath.Join(mnt, f.Name))
		}
	}
	run(t, "umount", mnt)

	// 3. Before the wipe.
	c.Before = look(t, env, set, files, c.Device, filepath.Join(dir, "carve-before"))

	// 4. Wipe (shunya or the broken build), then a full verify with the honest binary.
	bin := shunyaBin(t)
	if c.Broken {
		bin = filepath.Join(filepath.Dir(bin), "shunya-broken")
	}
	j := filepath.Join(dir, "wipe.journal")
	c.WipeExit = exitOf(exec.Command(bin, "wipe", "--execute", "--journal", j, "--key", key, c.Device))
	c.VerifyExit = exitOf(exec.Command(shunyaBin(t), "verify", "--journal", j, "--key", key))

	// 5. After the wipe.
	c.After = look(t, env, set, files, c.Device, filepath.Join(dir, "carve-after"))
}

// look scans the raw device and runs photorec on it.
func look(t *testing.T, env backend.Env, set *canary.Set, files []canary.Planted, dev, carveDir string) canary.Phase {
	t.Helper()
	os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0o200) // photorec reads through the page cache
	var ph canary.Phase
	b, err := backend.OpenBlock(env, dev, backend.Options{Direct: true}) // read-only, O_EXCL
	if err != nil {
		t.Fatal(err)
	}
	ph.Residue, err = canary.NewScanner(set, canary.Markers(files), b.SectorSize()).Scan(context.Background(), b, b.Size(), 4<<20)
	b.Close()
	if err != nil {
		t.Fatal(err)
	}
	ph.Carve = photorec(t, dev, files, carveDir)
	return ph
}

func photorec(t *testing.T, dev string, files []canary.Planted, out string) canary.Carve {
	t.Helper()
	if _, err := exec.LookPath("photorec"); err != nil {
		return canary.Carve{Tool: "photorec", SkipReason: "photorec not installed"}
	}
	os.RemoveAll(out)
	os.MkdirAll(out, 0o700)
	cmd := exec.Command("photorec", "/log", "/d", filepath.Join(out, "r"), "/cmd", dev,
		"partition_none,fileopt,everything,disable,jpg,enable,pdf,enable,zip,enable,search")
	cmd.Dir = out
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("photorec: %v\n%s", err, tail(string(b)))
	}
	c, err := canary.InspectCarved("photorec", out, files)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func exitOf(cmd *exec.Cmd) int {
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

func tail(s string) string {
	if len(s) > 2000 {
		return s[len(s)-2000:]
	}
	return s
}
