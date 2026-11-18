//go:build labtest && linux

package labtests

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"shunya/internal/engine"
)

// shunyaBin is the token-bearing lab build pushed next to this test binary.
func shunyaBin(t *testing.T) string {
	t.Helper()
	p := os.Getenv("SHUNYA_BIN")
	if p == "" {
		p = "./shunya"
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("shunya binary: %v", err)
	}
	return abs
}

// workDir is on the boot disk (the tool's own medium), which every guard protects.
func workDir(t *testing.T) (dir, key string) {
	t.Helper()
	dir = filepath.Join("/var/lib/shunya", t.Name()+"-"+time.Now().UTC().Format("20060102T150405"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	key = filepath.Join(dir, "station.key")
	shunya(t, 0, "keys", "gen-dev", key)
	return dir, key
}

// shunya runs the CLI and fails unless it exits with want.
func shunya(t *testing.T, want int, args ...string) string {
	t.Helper()
	cmd := exec.Command(shunyaBin(t), args...)
	out, _ := cmd.CombinedOutput()
	if got := cmd.ProcessState.ExitCode(); got != want {
		t.Fatalf("shunya %v: exit %d, want %d\n%s", args, got, want, out)
	}
	return string(out)
}

func journalState(t *testing.T, key, j string) engine.State {
	t.Helper()
	var s struct {
		State engine.State `json:"state"`
	}
	out := shunya(t, 0, "journal", "show", "--json", "--key", key, j)
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	return s.State
}

// Milestone 3 acceptance on a real (virtual) block device: wipe with O_DIRECT, kill -9
// mid-wipe, resume, read the whole disk back; the journal shows the unclean stop.
func TestLabWipeKill9Resume(t *testing.T) {
	env := inLab(t)
	dev := pathOf(t, env, "SHUNYA-SATA-HDD-01")
	dir, key := workDir(t)
	j := filepath.Join(dir, "wipe.journal")

	cmd := exec.Command(shunyaBin(t), "wipe", "--execute", "--chunk-mib", "1", "--sync-mib", "8",
		"--journal", j, "--key", key, dev)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		b, _ := os.ReadFile(j)
		if bytes.Count(b, []byte(`"type":"checkpoint"`)) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("no checkpoints after 60 s:\n%s", out.String())
		}
		time.Sleep(time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGKILL)
	cmd.Wait()
	ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("wipe was not killed mid-way (finished first?):\n%s", out.String())
	}
	st := journalState(t, key, j)
	if st.Done || st.Pending() != engine.StopUnclean {
		t.Fatalf("after kill -9: %+v", st)
	}
	t.Logf("%s: kill -9 at synced offset %d of %d bytes", dev, st.Offset, st.Plan.SizeBytes)

	res := shunya(t, 0, "wipe", "--resume", "--execute", "--verify", "--journal", j, "--key", key)
	for _, want := range []string{"previous run: unclean-stop", "DONE", "VERIFIED"} {
		if !strings.Contains(res, want) {
			t.Fatalf("resume output lacks %q:\n%s", want, res)
		}
	}
	fin := journalState(t, key, j)
	if !fin.Done || len(fin.Interruptions) != 1 || fin.Interruptions[0].Kind != engine.StopUnclean ||
		fin.Interruptions[0].Offset != st.Offset {
		t.Fatalf("final journal state %+v", fin)
	}
	t.Logf("resumed, completed and verified: %s", strings.TrimSpace(res[strings.LastIndex(res, "VERIFIED"):]))
	t.Log(shunya(t, 0, "journal", "show", "--key", key, j))
}

// The wipe command goes through the same guards: the boot disk is refused before any
// journal is created, and a journal on the target disk is refused.
func TestLabWipeRefusals(t *testing.T) {
	env := inLab(t)
	dir, key := workDir(t)
	j := filepath.Join(dir, "boot.journal")
	out := shunya(t, 1, "wipe", "--execute", "--journal", j, "--key", key, pathOf(t, env, bootSerial))
	if !strings.Contains(out, "root filesystem /") {
		t.Fatalf("boot disk refusal:\n%s", out)
	}
	if _, err := os.Stat(j); err == nil {
		t.Fatal("refused wipe created a journal")
	}

	// A journal path that is a device node is refused from lstat alone, before anything
	// is opened: by a fresh wipe, by --resume and by journal show. (A journal in a file
	// system on the target can't occur here: the guard already refuses a target with a
	// mounted file system; the device-number check behind it is unit-tested.)
	dev := pathOf(t, env, "SHUNYA-NVME-01")
	for _, args := range [][]string{
		{"wipe", "--execute", "--journal", dev, "--key", key, dev},
		{"wipe", "--resume", "--execute", "--journal", dev, "--key", key},
		{"journal", "show", "--key", key, dev},
	} {
		if out := shunya(t, 1, args...); !strings.Contains(out, "journal must be a regular file") {
			t.Fatalf("%v:\n%s", args, out)
		}
	}
}

// Dry run prints the plan with the honest disclosures. A SATA drive is opened read-only
// for IDENTIFY (Milestone 5); nothing is written.
func TestLabWipeDryRun(t *testing.T) {
	env := inLab(t)
	out := shunya(t, 0, "wipe", pathOf(t, env, "SHUNYA-SATA-SSD-01"))
	for _, want := range []string{"NIST level:  Clear", "Flash media", "hidden areas: HPA not supported", "DCO", "DRY RUN", "opened read-only for ATA IDENTIFY"} {
		if !strings.Contains(out, want) {
			t.Fatalf("dry run lacks %q:\n%s", want, out)
		}
	}
	t.Log(out)
}
