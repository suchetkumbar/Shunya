package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"shunya/internal/backend"
	"shunya/internal/engine"
)

// TestMain doubles as the shunya CLI for the kill tests: with SHUNYA_TEST_CHILD=1 the
// test binary runs run(os.Args[1:]) with every write slowed down, so the test can kill
// it mid-wipe.
func TestMain(m *testing.M) {
	if os.Getenv("SHUNYA_TEST_CHILD") == "1" {
		wrapTarget = func(t backend.Target) backend.Target { return slowTarget{t} }
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

type slowTarget struct{ backend.Target }

func (s slowTarget) WriteAt(p []byte, off int64) (int, error) {
	time.Sleep(15 * time.Millisecond)
	return s.Target.WriteAt(p, off)
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

type fixture struct {
	dir, img, key, journal string
	orig                   []byte
}

func newFixture(t *testing.T, size int) fixture {
	t.Helper()
	dir := t.TempDir()
	f := fixture{dir: dir, img: filepath.Join(dir, "disk.img"), key: filepath.Join(dir, "station.key"),
		journal: filepath.Join(dir, "wipe.journal"), orig: bytes.Repeat([]byte("old data "), size/9+1)[:size]}
	if err := os.WriteFile(f.img, f.orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := runCLI(t, "keys", "gen-dev", f.key); code != 0 || !strings.Contains(out, "key id: ed25519:") {
		t.Fatalf("keys gen-dev: %d %s %s", code, out, errs)
	}
	return f
}

func TestWipeDryRunWritesNothing(t *testing.T) {
	f := newFixture(t, 1<<20)
	code, out, errs := runCLI(t, "wipe", "--image", f.img)
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"PLAN", "NIST level:  Clear", "random", "DRY RUN", "Image file:"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out)
		}
	}
	if got, _ := os.ReadFile(f.img); !bytes.Equal(got, f.orig) {
		t.Fatal("dry run changed the image")
	}
	if _, err := os.Stat(f.journal); err == nil {
		t.Fatal("dry run created a journal")
	}
	code, out, _ = runCLI(t, "wipe", "--json", "--pattern", "zero,one", "--image", f.img)
	var p engine.Plan
	if code != 0 || json.Unmarshal([]byte(out), &p) != nil || len(p.Passes) != 2 || p.Level != engine.LevelClear {
		t.Fatalf("json plan: %d %s", code, out)
	}
}

func TestWipeUsageErrors(t *testing.T) {
	f := newFixture(t, 1<<20)
	for _, args := range [][]string{
		{"wipe"},
		{"wipe", "--image", f.img, "/dev/sdb"},
		{"wipe", "--execute", "--image", f.img}, // no journal/key
		{"wipe", "--execute", "--image", f.img, "--journal", f.journal}, // no key
		{"wipe", "--pattern", "dod", "--image", f.img},
		{"wipe", "--pattern", "zero,one", "--passes", "3", "--image", f.img},
		{"wipe", "--resume", "--journal", f.journal, "--key", f.key}, // no --execute
		{"journal", "show", f.journal},                               // no key
	} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if got, _ := os.ReadFile(f.img); !bytes.Equal(got, f.orig) {
		t.Fatal("a refused command changed the image")
	}
}

func TestWipeRefusesJournalOnImage(t *testing.T) {
	f := newFixture(t, 1<<20)
	code, _, errs := runCLI(t, "wipe", "--execute", "--image", f.img, "--journal", f.img, "--key", f.key)
	if code != 1 || !strings.Contains(errs, "journal must not live on the wipe target") {
		t.Fatalf("%d %s", code, errs)
	}
	if got, _ := os.ReadFile(f.img); !bytes.Equal(got, f.orig) {
		t.Fatal("image changed")
	}
}

func TestWipeImageEndToEnd(t *testing.T) {
	f := newFixture(t, 3<<20+7*512)
	code, out, errs := runCLI(t, "wipe", "--execute", "--verify", "--chunk-mib", "1", "--sync-mib", "1",
		"--image", f.img, "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(out, "DONE") || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	code, out, _ = runCLI(t, "journal", "show", "--key", f.key, f.journal)
	if code != 0 || !strings.Contains(out, "status: COMPLETE") || !strings.Contains(out, "interruptions: 0") {
		t.Fatalf("journal show: %d\n%s", code, out)
	}
	code, out, _ = runCLI(t, "wipe", "--resume", "--execute", "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(out, "already complete") {
		t.Fatalf("resume of a finished wipe: %d %s", code, out)
	}
}

// startChild runs the CLI in a child process (the test binary, see TestMain).
func startChild(t *testing.T, args ...string) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "SHUNYA_TEST_CHILD=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd, &out
}

// waitCheckpoints polls the journal until it holds n checkpoint records.
func waitCheckpoints(t *testing.T, path string, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(path)
		if bytes.Count(b, []byte(`"type":"checkpoint"`)) >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("child never reached the checkpoint")
}

type shown struct {
	TornBytes int          `json:"torn_bytes"`
	State     engine.State `json:"state"`
}

func journalState(t *testing.T, f fixture) shown {
	t.Helper()
	code, out, errs := runCLI(t, "journal", "show", "--json", "--key", f.key, f.journal)
	var s shown
	if code != 0 || json.Unmarshal([]byte(out), &s) != nil {
		t.Fatalf("journal show: %d %s %s", code, out, errs)
	}
	return s
}

// The Milestone 3 acceptance test: kill -9 mid-wipe, resume, every byte correct, and
// the journal shows the interruption.
func TestKill9ThenResume(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: kill -9 semantics are Unix")
	}
	f := newFixture(t, 48<<20)
	cmd, out := startChild(t, "wipe", "--execute", "--chunk-mib", "1", "--sync-mib", "2",
		"--image", f.img, "--journal", f.journal, "--key", f.key)
	waitCheckpoints(t, f.journal, 3)
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if err == nil || !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child was not killed by SIGKILL (err %v), output:\n%s", err, out)
	}
	before := journalState(t, f)
	if before.State.Done || before.State.Pending() != engine.StopUnclean || before.State.Offset == 0 {
		t.Fatalf("after kill: %+v", before.State)
	}
	t.Logf("killed at synced offset %d of %d", before.State.Offset, before.State.Plan.SizeBytes)

	code, rout, errs := runCLI(t, "wipe", "--resume", "--execute", "--verify", "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(rout, "previous run: unclean-stop") || !strings.Contains(rout, "VERIFIED") {
		t.Fatalf("resume: %d\n%s\n%s", code, rout, errs)
	}
	after := journalState(t, f)
	if !after.State.Done || len(after.State.Interruptions) != 1 {
		t.Fatalf("final %+v", after.State)
	}
	in := after.State.Interruptions[0]
	if in.Kind != engine.StopUnclean || in.Offset != before.State.Offset || in.ResumedAt.IsZero() {
		t.Fatalf("interruption %+v", in)
	}
}

// SIGINT: the child stops cleanly, records "interrupted", exits 5, and resumes.
func TestSIGINTThenResume(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: SIGINT delivery is Unix")
	}
	f := newFixture(t, 32<<20)
	cmd, out := startChild(t, "wipe", "--execute", "--chunk-mib", "1", "--sync-mib", "4",
		"--image", f.img, "--journal", f.journal, "--key", f.key)
	waitCheckpoints(t, f.journal, 1)
	cmd.Process.Signal(os.Interrupt)
	cmd.Wait()
	if c := cmd.ProcessState.ExitCode(); c != exitInterrupted || !strings.Contains(out.String(), "INTERRUPTED") {
		t.Fatalf("exit %d:\n%s", c, out)
	}
	st := journalState(t, f).State
	if st.Pending() != engine.StopInterrupted || !strings.Contains(st.StopReason, "interrupt") {
		t.Fatalf("state %+v", st)
	}
	code, rout, errs := runCLI(t, "wipe", "--resume", "--execute", "--verify", "--journal", f.journal, "--key", f.key)
	if code != 0 || !strings.Contains(rout, "previous run: interrupted") {
		t.Fatalf("resume: %d\n%s\n%s", code, rout, errs)
	}
	if fin := journalState(t, f).State; !fin.Done || len(fin.Interruptions) != 1 || fin.Interruptions[0].Kind != engine.StopInterrupted {
		t.Fatalf("final %+v", fin)
	}
}

func TestResumeRefusesTamperedJournalAndChangedTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SKIPPED: needs SIGINT")
	}
	f := newFixture(t, 16<<20)
	cmd, _ := startChild(t, "wipe", "--execute", "--chunk-mib", "1", "--sync-mib", "1",
		"--image", f.img, "--journal", f.journal, "--key", f.key)
	waitCheckpoints(t, f.journal, 2)
	cmd.Process.Signal(os.Interrupt)
	cmd.Wait()
	good, _ := os.ReadFile(f.journal)

	bad := bytes.Replace(good, []byte(`"type":"checkpoint","prev"`), []byte(`"type":"checkpoinT","prev"`), 1)
	os.WriteFile(f.journal, bad, 0o600)
	if code, _, errs := runCLI(t, "wipe", "--resume", "--execute", "--journal", f.journal, "--key", f.key); code != 1 || !strings.Contains(errs, "tampered") {
		t.Fatalf("tampered journal: %d %s", code, errs)
	}

	os.WriteFile(f.journal, good, 0o600)
	os.WriteFile(f.img, make([]byte, 8<<20), 0o600) // a different (smaller) image at the same path
	if code, _, errs := runCLI(t, "wipe", "--resume", "--execute", "--journal", f.journal, "--key", f.key); code != 1 || !strings.Contains(errs, "refusing") {
		t.Fatalf("changed target: %d %s", code, errs)
	}
	other := filepath.Join(f.dir, "other.key")
	runCLI(t, "keys", "gen-dev", other)
	if code, _, errs := runCLI(t, "wipe", "--resume", "--execute", "--journal", f.journal, "--key", other); code != 1 || !strings.Contains(errs, "different key") {
		t.Fatalf("other key: %d %s", code, errs)
	}
}
