//go:build labtest && linux

package labtests

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pty is a pseudo-terminal pair: the test reads the TUI's screen from master and
// types into it, as an operator at a console would.
type pty struct {
	master, slave *os.File
	mu            sync.Mutex
	raw           strings.Builder
}

// openPTY opens /dev/ptmx (inside the lab VM only; the build tag and inLab ensure it).
func openPTY(t *testing.T) *pty {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetWinsize(int(s.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 60, Col: 200}); err != nil {
		t.Fatal(err)
	}
	p := &pty{master: m, slave: s}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, err := m.Read(buf)
			p.mu.Lock()
			p.raw.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return p
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;?<>=]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78DEHM]|\r`)

// screen is everything the TUI has drawn so far, without escape sequences.
func (p *pty) screen() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return ansi.ReplaceAllString(p.raw.String(), "")
}

// waitFor waits until the screen, after position from, shows want; it returns the
// position just after it.
func (p *pty) waitFor(t *testing.T, from int, want string, d time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s := p.screen()
		if from > len(s) {
			from = len(s)
		}
		if i := strings.Index(s[from:], want); i >= 0 {
			return from + i + len(want)
		}
		time.Sleep(100 * time.Millisecond)
	}
	s := p.screen()
	t.Fatalf("screen never showed %q; last 3000 bytes:\n%s", want, s[max(0, len(s)-3000):])
	return 0
}

func (p *pty) keys(t *testing.T, ks ...string) {
	t.Helper()
	for _, k := range ks {
		if _, err := p.master.Write([]byte(k)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

const (
	keyDown  = "\x1b[B"
	keyEnter = "\r"
	keySpace = " "
)

// startTUI runs "shunya tui" on the pty's slave side, as the controlling terminal.
func startTUI(t *testing.T, p *pty, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(shunyaBin(t), append([]string{"tui"}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = p.slave, p.slave, p.slave
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLUMNS=200", "LINES=60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return cmd
}

// Milestone 9 acceptance: three disks of different kinds (virtio-blk, SATA HDD, NVMe)
// are selected, confirmed and wiped in parallel from the TUI, driven only by keystrokes
// on a terminal; each gets a valid, logged certificate, and the batch manifest is valid,
// logged and complete.
func TestLabTUIFleet(t *testing.T) {
	env := inLab(t)
	disks := []string{pathOf(t, env, "SHUNYA-VIRTIO-01"), pathOf(t, env, "SHUNYA-SATA-HDD-01"), pathOf(t, env, "SHUNYA-NVME-01")}
	dir, key := workDir(t)
	verifyBin, _ := filepath.Abs("./shunya-verify")
	root, pass := filepath.Join(dir, "root"), filepath.Join(dir, "pass")
	os.WriteFile(pass, []byte("lab root passphrase, offline\n"), 0o600)
	shunya(t, 0, "keys", "init-root", "--passphrase-file", pass, root)
	sc := filepath.Join(dir, "station.cert.json")
	shunya(t, 0, "keys", "issue-station", "--root", filepath.Join(root, "root.key"), "--station-key", key,
		"--name", "lab-vm", "--out", sc, "--passphrase-file", pass)
	const addr = "127.0.0.1:8090"
	base := "http://" + addr
	tool(t, verifyBin, "log-key", "--origin", addr+"/log", "--out", dir)
	vkey := filepath.Join(dir, "log.vkey")
	srv := exec.Command(verifyBin, "serve", "--init", "--dir", filepath.Join(dir, "log"), "--log-key", filepath.Join(dir, "log.key"),
		"--root", filepath.Join(root, "root.pub"), "--revocations", filepath.Join(root, "revocations.json"), "--listen", addr)
	srvLog, _ := os.Create(filepath.Join(dir, "serve.log"))
	srv.Stdout, srv.Stderr = srvLog, srvLog
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { srv.Process.Signal(syscall.SIGTERM); srv.Wait() }()
	waitUp(t, base+"/checkpoint")

	out := filepath.Join(dir, "batch")
	os.Mkdir(out, 0o700)
	p := openPTY(t)
	start := time.Now()
	cmd := startTUI(t, p, append([]string{"--journal-dir", out, "--key", key, "--station-cert", sc, "--log", base, "--log-key", vkey}, disks...)...)
	at := p.waitFor(t, 0, "Choose the disks to wipe", 20*time.Second)
	for _, d := range disks {
		at = p.waitFor(t, 0, d, 5*time.Second)
	}
	p.keys(t, keySpace, keyDown, keySpace, keyDown, keySpace)
	at = p.waitFor(t, at, "[x]", 5*time.Second)
	p.keys(t, keyEnter)
	serialRE := regexp.MustCompile(`Serial number: (\S+)`)
	for i := 1; i <= 3; i++ {
		at = p.waitFor(t, at, fmt.Sprintf("CONFIRM %d of 3", i), 10*time.Second)
		at = p.waitFor(t, at, "Serial number: ", 5*time.Second)
		time.Sleep(200 * time.Millisecond)
		m := serialRE.FindStringSubmatch(p.screen()[at-len("Serial number: "):])
		if m == nil {
			t.Fatal("no serial on the confirmation screen")
		}
		serial := m[1]
		t.Logf("confirming %s", serial)
		p.keys(t, strings.Split(serial[len(serial)-4:], "")...)
		p.keys(t, keyEnter)
	}
	// Planned after the confirmations; nothing starts before Enter on the plan.
	at = p.waitFor(t, at, "PLAN — nothing has been written yet", 10*time.Second)
	at = p.waitFor(t, at, "nvme-format-user-data-erase — NIST SP 800-88", 30*time.Second)
	time.Sleep(time.Second) // every plan in
	p.keys(t, keyEnter)
	at = p.waitFor(t, at, "WIPING 3 disk(s)", 20*time.Second)
	at = p.waitFor(t, at, "RESULT — 3 disk(s)", 9*time.Minute)
	elapsed := time.Since(start)
	at = p.waitFor(t, at, "MANIFEST ", 10*time.Second)
	p.keys(t, keyEnter)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("tui exit: %v\n%s", err, tailOf(p.screen(), 4000))
	}
	final := p.screen()[at:]
	if n := strings.Count(final, "erased and verified"); n != 3 {
		t.Fatalf("%d of 3 disks erased and verified:\n%s", n, final)
	}
	t.Logf("three disks wiped in parallel from the TUI in %s", elapsed.Round(time.Second))

	// Each certificate verifies, logged; the manifest is complete and logged.
	certs, _ := filepath.Glob(filepath.Join(out, "*.cert.json"))
	if len(certs) != 3 {
		t.Fatalf("certificates: %v", certs)
	}
	methods := map[string]bool{}
	for _, c := range certs {
		vout, err := exec.Command(verifyBin, "--json", "--root", filepath.Join(root, "root.pub"), "--revocations", filepath.Join(root, "revocations.json"),
			"--log-key", vkey, "--require-log", c).CombinedOutput()
		var v struct {
			Valid bool `json:"valid"`
			Cert  struct {
				Device struct {
					Serial string `json:"serial"`
				} `json:"device"`
				Erasure struct {
					Method string `json:"method"`
				} `json:"erasure"`
			} `json:"certificate"`
		}
		if err != nil || json.Unmarshal(vout, &v) != nil || !v.Valid {
			t.Fatalf("%s: %v\n%s", c, err, vout)
		}
		methods[v.Cert.Device.Serial+" "+v.Cert.Erasure.Method] = true
	}
	t.Logf("certified: %v", methods)
	mfs, _ := filepath.Glob(filepath.Join(out, "batch-*.manifest.json"))
	if len(mfs) != 1 {
		t.Fatalf("manifests: %v", mfs)
	}
	mout := tool(t, verifyBin, "manifest", "--root", filepath.Join(root, "root.pub"), "--revocations", filepath.Join(root, "revocations.json"),
		"--log-key", vkey, "--require-log", "--certs", out, mfs[0])
	if !strings.Contains(mout, "BATCH COMPLETE") || !strings.Contains(mout, "3 certified, 0 not") || !strings.Contains(mout, "proof verified") {
		t.Fatalf("manifest:\n%s", mout)
	}
	os.WriteFile(filepath.Join(results(t), "tui-fleet-screen.txt"), []byte(final), 0o644)
	os.WriteFile(filepath.Join(results(t), "batch.manifest.json"), mustRead(t, mfs[0]), 0o644)
	os.WriteFile(filepath.Join(results(t), "manifest-verify.txt"), []byte(mout), 0o644)
}

// The one-click mode on the USB disk: one disk, the recommended method, one typed
// confirmation, big status text, a certificate.
func TestLabTUISimple(t *testing.T) {
	env := inLab(t)
	disk := pathOf(t, env, "SHUNYA-USB-01")
	dir, key := workDir(t)
	p := openPTY(t)
	cmd := startTUI(t, p, "--simple", "--journal-dir", dir, "--key", key, disk)
	at := p.waitFor(t, 0, "Which disk do you want to erase?", 20*time.Second)
	p.keys(t, keyEnter)
	at = p.waitFor(t, at, "LAST 4 CHARACTERS", 5*time.Second)
	p.keys(t, "-", "0", "1", keyEnter) // wrong first: nothing starts
	at = p.waitFor(t, at, "Nothing was wiped", 5*time.Second)
	p.keys(t, "B", "-", "0", "1", keyEnter)
	at = p.waitFor(t, at, "READY", 10*time.Second)
	at = p.waitFor(t, at, "cannot be undone", 30*time.Second)
	p.keys(t, keyEnter)
	at = p.waitFor(t, at, "WIPING", 20*time.Second)
	at = p.waitFor(t, at, "█", 5*time.Second)
	at = p.waitFor(t, at, "Press Enter to exit", 6*time.Minute)
	final := p.screen()[max(0, at-2000):]
	p.keys(t, keyEnter)
	cmd.Wait()
	// Without --station-cert the wipe is done and verified, but no certificate is issued:
	// the screen says so plainly.
	if !strings.Contains(final, "DONE") || !strings.Contains(final, "no station certificate was given") {
		t.Fatalf("simple mode result:\n%s", final)
	}
	os.WriteFile(filepath.Join(results(t), "tui-simple-screen.txt"), []byte(final), 0o644)
}

func tailOf(s string, n int) string { return s[max(0, len(s)-n):] }
