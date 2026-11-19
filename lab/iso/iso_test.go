//go:build labiso && linux

// Package iso boots the Shunya live image in QEMU and drives it over the serial
// console, as an operator at the machine would: Milestone 10's acceptance test.
//
// It runs in WSL/Linux (make lab-iso-test), not inside the lab VM. SAFETY: every disk it
// gives QEMU is a regular file under lab/images/ (checked before use, like lab.sh's
// assert_image_file); it opens no device node except /dev/kvm through QEMU.
package iso

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	repo   = mustAbs("../..")
	images = filepath.Join(repo, "lab", "images")
	live   = filepath.Join(images, "live")
	verify = filepath.Join(repo, "bin", "release-linux-amd64", "shunya-verify")
)

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		panic(err)
	}
	return a
}

// imageFile refuses anything that is not a regular file inside lab/images.
func imageFile(t *testing.T, p string) string {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Mode().IsRegular() {
		t.Fatalf("REFUSING %s: not a regular file (%v)", p, st.Mode())
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(real, images+string(os.PathSeparator)) {
		t.Fatalf("REFUSING %s: outside lab/images", real)
	}
	return real
}

func needKVM(t *testing.T) {
	t.Helper()
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("SKIPPED (not passed): /dev/kvm unavailable (%v); the ISO test needs KVM and never falls back", err)
	}
	f.Close()
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Skip("SKIPPED (not passed): qemu-system-x86_64 not installed")
	}
}

// vm is one QEMU run with its serial console on stdin/stdout.
type vm struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	mu  sync.Mutex
	raw bytes.Buffer
	end chan error
}

// The QEMU machine: q35 with KVM, 1 GiB, no display, serial on stdio, power-off exits.
func boot(t *testing.T, disks ...string) *vm {
	t.Helper()
	args := []string{"-machine", "q35,accel=kvm", "-cpu", "host", "-m", "1024", "-smp", "2",
		"-nodefaults", "-display", "none", "-serial", "stdio", "-no-reboot", "-device", "qemu-xhci,id=xhci"}
	args = append(args, disks...)
	v := &vm{cmd: exec.Command("qemu-system-x86_64", args...), end: make(chan error, 1)}
	var err error
	if v.in, err = v.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	out, err := v.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	v.cmd.Stderr = v.cmd.Stdout
	if err := v.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := out.Read(buf)
			v.mu.Lock()
			v.raw.Write(buf[:n])
			v.mu.Unlock()
			if err != nil {
				v.end <- v.cmd.Wait()
				return
			}
		}
	}()
	t.Cleanup(func() {
		if v.cmd.ProcessState == nil {
			v.cmd.Process.Kill()
		}
		v.mu.Lock()
		os.WriteFile(filepath.Join(images, "iso-run", t.Name(), "serial.log"), v.raw.Bytes(), 0o644)
		v.mu.Unlock()
		if t.Failed() {
			s := v.screen()
			t.Logf("serial console, last 4000 bytes:\n%s", s[max(0, len(s)-4000):])
		}
	})
	return v
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;?<>=]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78DEHMc]|\r`)

func (v *vm) screen() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return ansi.ReplaceAllString(v.raw.String(), "")
}

func (v *vm) waitFor(t *testing.T, from int, want string, d time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s := v.screen()
		from = min(from, len(s))
		if i := strings.Index(s[from:], want); i >= 0 {
			return from + i + len(want)
		}
		select {
		case err := <-v.end:
			v.end <- err
			t.Fatalf("QEMU exited (%v) before the console showed %q", err, want)
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Fatalf("console never showed %q", want)
	return 0
}

func (v *vm) keys(t *testing.T, ks ...string) {
	t.Helper()
	for _, k := range ks {
		if _, err := io.WriteString(v.in, k); err != nil {
			t.Fatal(err)
		}
		time.Sleep(120 * time.Millisecond)
	}
}

const (
	keyDown  = "\x1b[B"
	keyEnter = "\r"
	keySpace = " "
	canary   = "SHUNYA-ISO-CANARY-0123456789abcdef"
)

// target makes a fresh sparse image with canaries at the start, middle and end.
func target(t *testing.T, dir, name string, size int64) string {
	t.Helper()
	p := filepath.Join(dir, name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{0, size / 2, size - 4096} {
		if _, err := f.WriteAt([]byte(canary), off); err != nil {
			t.Fatal(err)
		}
	}
	return imageFile(t, p)
}

func runDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(images, "iso-run", t.Name())
	os.RemoveAll(d)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func copyFile(t *testing.T, from, to string) string {
	t.Helper()
	b, err := os.ReadFile(imageFile(t, from))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return imageFile(t, to)
}

// selectBoot answers isolinux's prompt: the serial-console entry.
func selectBoot(t *testing.T, v *vm) int {
	t.Helper()
	at := v.waitFor(t, 0, "boot:", 60*time.Second)
	v.keys(t, "serial", keyEnter)
	return at
}

type row struct {
	selectable bool
	line       string
}

// pickRows reads the picker's rows from the most recent frame after from.
func pickRows(t *testing.T, v *vm, from int) []row {
	t.Helper()
	s := v.screen()[from:]
	i := strings.LastIndex(s, "Choose the disks to wipe")
	j := strings.Index(s[i:], "Protected disks (")
	if i < 0 || j < 0 {
		t.Fatalf("no complete picker frame")
	}
	var rows []row
	for _, l := range strings.Split(s[i:i+j], "\n")[1:] {
		switch {
		case strings.HasPrefix(l, "[ ] /dev/"), strings.HasPrefix(l, "[x] /dev/"):
			rows = append(rows, row{true, l})
		case strings.HasPrefix(l, "    /dev/"):
			rows = append(rows, row{false, l})
		}
	}
	return rows
}

// The release ISO as a CD: it lists the disks, keeps no data on the medium (and says
// so), and the CD drive is not offered.
func TestISOBootCD(t *testing.T) {
	needKVM(t)
	iso := imageFile(t, filepath.Join(live, "shunya-live.iso"))
	d := runDir(t)
	disk := target(t, d, "t-virtio.raw", 64<<20)
	v := boot(t,
		"-drive", "if=none,id=cd,file="+iso+",format=raw,media=cdrom,readonly=on",
		"-device", "ide-cd,drive=cd,bus=ide.2,bootindex=0",
		"-drive", "if=none,id=t1,file="+disk+",format=raw",
		"-device", "virtio-blk-pci,drive=t1,serial=ISO-VIRTIO-01")
	at := selectBoot(t, v)
	at = v.waitFor(t, at, "Boot medium: /dev/sr0", 90*time.Second)
	at = v.waitFor(t, at, "IN RAM ONLY", 10*time.Second)
	at = v.waitFor(t, at, "Choose the disks to wipe", 30*time.Second)
	at = v.waitFor(t, at, "Protected disks (", 10*time.Second)
	rows := pickRows(t, v, max(0, at-2000))
	var sawTarget, sawCD bool
	for _, r := range rows {
		switch {
		case strings.Contains(r.line, "ISO-VIRTIO-01") && r.selectable:
			sawTarget = true
		case strings.Contains(r.line, "/dev/sr0"):
			sawCD = !r.selectable
		}
	}
	if !sawTarget || !sawCD {
		t.Fatalf("picker rows: target selectable %v, CD drive listed and not selectable %v\n%+v", sawTarget, sawCD, rows)
	}
	v.keys(t, "q")
	at = v.waitFor(t, at, "p      power off", 20*time.Second)
	v.keys(t, "p", keyEnter)
	select {
	case <-v.end:
	case <-time.After(60 * time.Second):
		t.Fatal("did not power off")
	}
	if b, _ := os.ReadFile(disk); !bytes.Contains(b, []byte(canary)) {
		t.Fatal("the target was written although nothing was selected")
	}
}

// The lab-test ISO (the release ISO plus a provisioned SHUNYA-KEYS partition) as a USB
// stick: it protects itself, wipes three disks of different kinds from its TUI, keeps the
// journals and certificates on the stick, and the certificates verify.
func TestISOBootUSBWipe(t *testing.T) {
	needKVM(t)
	rel := imageFile(t, filepath.Join(live, "shunya-live.iso"))
	labISO := imageFile(t, filepath.Join(live, "shunya-live-labtest.iso"))
	sameOutsideKeys(t, rel, labISO)

	d := runDir(t)
	stick := copyFile(t, labISO, filepath.Join(d, "stick.img")) // the run writes to SHUNYA-DATA
	tv := target(t, d, "t-virtio.raw", 256<<20)
	tn := target(t, d, "t-nvme.raw", 256<<20)
	ts := target(t, d, "t-sata.raw", 256<<20)
	v := boot(t,
		"-drive", "if=none,id=live,file="+stick+",format=raw",
		"-device", "usb-storage,bus=xhci.0,drive=live,bootindex=0,removable=on,serial=SHUNYA-STICK-01",
		"-drive", "if=none,id=tv,file="+tv+",format=raw",
		"-device", "virtio-blk-pci,drive=tv,serial=ISO-VIRTIO-01",
		"-drive", "if=none,id=tn,file="+tn+",format=raw",
		"-device", "nvme,id=nvme0,serial=ISO-NVME-01",
		"-device", "nvme-ns,drive=tn,bus=nvme0,nsid=1",
		"-drive", "if=none,id=ts,file="+ts+",format=raw",
		"-device", "ide-hd,drive=ts,bus=ide.0,serial=ISO-SATA-01,model=SHUNYA ISO SATA HDD,rotation_rate=7200")
	start := time.Now()
	at := selectBoot(t, v)
	at = v.waitFor(t, at, "Boot medium: /dev/", 90*time.Second)
	at = v.waitFor(t, at, "Station:     key and station certificate on /keys", 20*time.Second)
	at = v.waitFor(t, at, "Choose the disks to wipe", 30*time.Second)
	at = v.waitFor(t, at, "Protected disks (", 10*time.Second)
	rows := pickRows(t, v, max(0, at-3000))

	// The boot medium is listed, protected, and cannot be selected.
	want := map[string]bool{"ISO-VIRTIO-01": true, "ISO-NVME-01": true, "ISO-SATA-01": true}
	var stickRow string
	first := -1
	for i, r := range rows {
		if strings.Contains(r.line, "QEMU HARDDISK") || strings.Contains(r.line, "boot medium") {
			stickRow = r.line
			if r.selectable {
				t.Fatalf("the boot medium is selectable: %q", r.line)
			}
		}
		if r.selectable && first < 0 {
			first = i
		}
	}
	if !strings.Contains(stickRow, "boot medium of this Shunya live system") {
		t.Fatalf("boot medium row %q (rows %+v)", stickRow, rows)
	}
	// Select the three targets: the cursor starts on the first selectable row and moves
	// over every row.
	for i := first; i < len(rows); i++ {
		for s := range want {
			if strings.Contains(rows[i].line, s) {
				v.keys(t, keySpace)
			}
		}
		if i < len(rows)-1 {
			v.keys(t, keyDown)
		}
	}
	v.keys(t, keyEnter)
	serialRE := regexp.MustCompile(`Serial number: (\S+)`)
	for i := 1; i <= 3; i++ {
		at = v.waitFor(t, at, fmt.Sprintf("CONFIRM %d of 3", i), 15*time.Second)
		at = v.waitFor(t, at, "Serial number: ", 5*time.Second)
		time.Sleep(300 * time.Millisecond)
		m := serialRE.FindStringSubmatch(v.screen()[at-len("Serial number: "):])
		if m == nil || !want[m[1]] {
			t.Fatalf("confirmation for %v", m)
		}
		v.keys(t, strings.Split(m[1][len(m[1])-4:], "")...)
		v.keys(t, keyEnter)
	}
	// A release build plans after the confirmations, so it may identify the NVMe drive
	// and use its own erase.
	at = v.waitFor(t, at, "PLAN — nothing has been written yet", 20*time.Second)
	at = v.waitFor(t, at, "nvme-format-user-data-erase — NIST SP 800-88", 60*time.Second)
	time.Sleep(2 * time.Second)
	v.keys(t, keyEnter)
	at = v.waitFor(t, at, "WIPING 3 disk(s)", 30*time.Second)
	at = v.waitFor(t, at, "RESULT — 3 disk(s)", 10*time.Minute)
	at = v.waitFor(t, at, "MANIFEST ", 20*time.Second)
	t.Logf("booted and wiped three disks in %s", time.Since(start).Round(time.Second))
	v.keys(t, keyEnter)
	at = v.waitFor(t, at, "p      power off", 30*time.Second)
	result := v.screen()[max(0, at-6000):at]
	if n := strings.Count(result, "erased and verified"); n < 3 {
		t.Fatalf("%d of 3 disks erased and verified:\n%s", n, result)
	}

	// The certificates and the manifest, printed on the console by the live system.
	v.keys(t, "c", keyEnter)
	end := v.waitFor(t, at, "p      power off", 30*time.Second)
	files := dumpedFiles(t, v.screen()[at:end])
	out := filepath.Join(d, "certs")
	os.Mkdir(out, 0o755)
	var certs, manifests []string
	for name, body := range files {
		p := filepath.Join(out, name)
		os.WriteFile(p, []byte(body), 0o644)
		if strings.HasSuffix(name, ".cert.json") {
			certs = append(certs, p)
		} else {
			manifests = append(manifests, p)
		}
	}
	if len(certs) != 3 || len(manifests) != 1 {
		t.Fatalf("printed files: %d certificates, %d manifests", len(certs), len(manifests))
	}
	root := imageFile(t, filepath.Join(live, "labtest-root.pub"))
	crl := imageFile(t, filepath.Join(live, "labtest-revocations.json"))
	methods := map[string]bool{}
	for _, c := range certs {
		o, err := exec.Command(verify, "--root", root, "--revocations", crl, c).CombinedOutput()
		if err != nil || !strings.Contains(string(o), "VALID") {
			t.Fatalf("%s: %v\n%s", c, err, o)
		}
		for _, m := range []string{"nvme-format-user-data-erase", "overwrite"} {
			if strings.Contains(string(o), m) {
				methods[m] = true
			}
		}
	}
	if !methods["nvme-format-user-data-erase"] || !methods["overwrite"] {
		t.Errorf("methods certified: %v", methods)
	}
	mo, err := exec.Command(verify, "manifest", "--root", root, "--revocations", crl, "--certs", out, manifests[0]).CombinedOutput()
	if err != nil || !strings.Contains(string(mo), "BATCH COMPLETE") || !strings.Contains(string(mo), "3 certified, 0 not") {
		t.Fatalf("manifest: %v\n%s", err, mo)
	}

	v.keys(t, "p", keyEnter)
	select {
	case <-v.end:
	case <-time.After(60 * time.Second):
		t.Fatal("did not power off")
	}
	for _, p := range []string{tv, tn, ts} {
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(canary)) {
			t.Errorf("%s: canary survived", filepath.Base(p))
		}
	}
	// The stick itself: untouched outside SHUNYA-DATA (journals and certificates live
	// there), and its data partition now holds this session.
	sameOutside(t, labISO, stick, 3)
	if b, _ := os.ReadFile(stick); !bytes.Contains(b, []byte(".cert.json")) {
		t.Error("no certificate file name on the stick's data partition")
	}
	os.WriteFile(filepath.Join(d, "console.txt"), []byte(v.screen()), 0o644)
}

// dumpedFiles parses "----- BEGIN SHUNYA FILE name" … "----- END SHUNYA FILE" blocks.
func dumpedFiles(t *testing.T, s string) map[string]string {
	t.Helper()
	re := regexp.MustCompile(`(?s)----- BEGIN SHUNYA FILE (\S+)\n(.*?)\n+----- END SHUNYA FILE`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		out[m[1]] = strings.TrimSpace(m[2]) + "\n"
	}
	return out
}

// partition returns MBR partition n's byte range (1-based).
func partition(t *testing.T, b []byte, n int) (int64, int64) {
	t.Helper()
	if len(b) < 512 || b[510] != 0x55 || b[511] != 0xaa {
		t.Fatal("no MBR")
	}
	e := b[446+16*(n-1):]
	start := int64(binary.LittleEndian.Uint32(e[8:])) * 512
	size := int64(binary.LittleEndian.Uint32(e[12:])) * 512
	if size == 0 || start+size > int64(len(b)) {
		t.Fatalf("partition %d: start %d size %d in %d bytes", n, start, size, len(b))
	}
	return start, start + size
}

// sameOutside: a and b are identical except inside MBR partition n.
func sameOutside(t *testing.T, a, b string, n int) {
	t.Helper()
	x, _ := os.ReadFile(a)
	y, _ := os.ReadFile(b)
	if len(x) != len(y) {
		t.Fatalf("%s and %s differ in size", a, b)
	}
	s, e := partition(t, x, n)
	if !bytes.Equal(x[:s], y[:s]) || !bytes.Equal(x[e:], y[e:]) {
		t.Fatalf("%s and %s differ outside partition %d", filepath.Base(a), filepath.Base(b), n)
	}
}

// The tested ISO is the release ISO with only SHUNYA-KEYS (partition 2) provisioned.
func sameOutsideKeys(t *testing.T, rel, lab string) {
	t.Helper()
	sameOutside(t, rel, lab, 2)
	t.Logf("%s equals %s outside SHUNYA-KEYS", filepath.Base(lab), filepath.Base(rel))
}
