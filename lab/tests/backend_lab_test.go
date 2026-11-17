//go:build labtest && linux

package labtests

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"shunya/internal/backend"
	"shunya/internal/device"
)

// Serials attached by lab/lab.sh.
var targets = []string{"SHUNYA-VIRTIO-01", "SHUNYA-SATA-SSD-01", "SHUNYA-SATA-HDD-01", "SHUNYA-NVME-01", "SHUNYA-USB-01"}

const bootSerial = "SHUNYA-BOOT-0"

// inLab fails (inside the lab, SHUNYA_LAB=1) or skips (anywhere else) unless this is
// the lab VM running as root.
func inLab(t *testing.T) backend.Env {
	t.Helper()
	why := ""
	vendor, _ := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	switch {
	case !strings.Contains(string(vendor), "QEMU"):
		why = "not the QEMU lab VM"
	case os.Geteuid() != 0:
		why = "not root"
	}
	if why != "" {
		if os.Getenv("SHUNYA_LAB") == "1" {
			t.Fatal(why)
		}
		t.Skip("SKIPPED (lab only): " + why)
	}
	env, err := backend.LiveEnv()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func pathOf(t *testing.T, env backend.Env, serial string) string {
	t.Helper()
	rep, err := device.EnumerateWith(env.FS, device.Options{Protect: env.Protect})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range rep.Devices {
		if d.Serial == serial {
			return d.Path
		}
	}
	t.Fatalf("no device with serial %s", serial)
	return ""
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func mustRefuse(t *testing.T, err error, sub string) {
	t.Helper()
	if !errors.Is(err, backend.ErrRefused) || !strings.Contains(err.Error(), sub) {
		t.Fatalf("err = %v; want refusal containing %q", err, sub)
	}
}

func TestLabWriteReadEachTarget(t *testing.T) {
	env := inLab(t)
	for _, serial := range targets {
		t.Run(serial, func(t *testing.T) {
			p := pathOf(t, env, serial)
			b, err := backend.OpenBlock(env, p, backend.Options{Execute: true, Direct: true, Sync: true})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			buf := backend.AlignedBuffer(4096, 4096)
			for i := range buf {
				buf[i] = byte(i) ^ 0x5a
			}
			copy(buf, "shunya-m2 "+serial)
			const off = 1 << 20
			if _, err := b.WriteAt(buf, off); err != nil {
				t.Fatal(err)
			}
			if err := b.Sync(); err != nil {
				t.Fatal(err)
			}
			got := backend.AlignedBuffer(4096, 4096)
			if _, err := b.ReadAt(got, off); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, buf) {
				t.Fatal("read-back differs from what was written")
			}
			t.Logf("%s (%s): wrote+read 4 KiB at 1 MiB with O_DIRECT|O_SYNC|O_EXCL, size %d, sector %d/%d",
				p, serial, b.Size(), b.SectorSize(), b.PhysicalSectorSize())
			if err := b.Discard(off, 4096); err != nil {
				t.Logf("discard not supported here (expected on USB): %v", err)
			} else {
				t.Logf("BLKDISCARD accepted (not counted as erasure; M4 verifies)")
			}
		})
	}
}

func TestLabBootDiskRefused(t *testing.T) {
	env := inLab(t)
	p := pathOf(t, env, bootSerial)
	_, err := backend.OpenBlock(env, p, backend.Options{Execute: true})
	mustRefuse(t, err, "root filesystem /")
	mustRefuse(t, err, "holds the running shunya binary")
	t.Logf("%s refused: %v", p, err)
	for _, part := range []string{p + "1", p + "3"} {
		_, err := backend.OpenBlock(env, part, backend.Options{Execute: true})
		mustRefuse(t, err, "is a partition of")
	}
}

func TestLabMountedTargetRefusedTwice(t *testing.T) {
	env := inLab(t)
	p := pathOf(t, env, "SHUNYA-VIRTIO-01")
	run(t, "mkfs.ext4", "-F", "-q", p)
	mnt := "/mnt/shunya-m2"
	os.MkdirAll(mnt, 0o755)
	run(t, "mount", p, mnt)
	mounted := true
	defer func() {
		if mounted {
			exec.Command("umount", mnt).Run()
		}
	}()

	// Layer 1: the guard sees the mount in /proc/self/mountinfo.
	_, err := backend.OpenBlock(env, p, backend.Options{Execute: true})
	mustRefuse(t, err, "mounted at "+mnt)
	t.Logf("guard: %v", err)

	// Layer 2: even with the guard bypassed, the kernel refuses an exclusive open of a
	// mounted device. This is what protects against mounts Shunya cannot see.
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_EXCL|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
		t.Fatal("O_EXCL open of a mounted device succeeded")
	}
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("O_EXCL open: %v, want EBUSY", err)
	}
	t.Logf("kernel: O_EXCL open of mounted %s → %v", p, err)

	run(t, "umount", mnt)
	mounted = false
	b, err := backend.OpenBlock(env, p, backend.Options{Execute: true})
	if err != nil {
		t.Fatalf("after umount: %v", err)
	}
	b.Close()
}

func TestLabSecondExclusiveOpenerRefused(t *testing.T) {
	env := inLab(t)
	p := pathOf(t, env, "SHUNYA-SATA-SSD-01")
	a, err := backend.OpenBlock(env, p, backend.Options{Execute: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	_, err = backend.OpenBlock(env, p, backend.Options{Execute: true})
	if !errors.Is(err, unix.EBUSY) {
		t.Fatalf("second open: %v, want EBUSY", err)
	}
	t.Logf("second exclusive open of %s → %v", p, err)
}

// bindOver bind-mounts a file with content over target for the rest of the test.
func bindOver(t *testing.T, target, content string) bool {
	t.Helper()
	f := t.TempDir() + "/fake"
	os.WriteFile(f, []byte(content), 0o644)
	if out, err := exec.Command("mount", "--bind", f, target).CombinedOutput(); err != nil {
		t.Logf("bind mount over %s failed: %v %s", target, err, out)
		return false
	}
	t.Cleanup(func() { exec.Command("umount", target).Run() })
	return true
}

func TestLabWrongTokenRefused(t *testing.T) {
	env := inLab(t)
	p := pathOf(t, env, "SHUNYA-SATA-HDD-01")
	if !bindOver(t, "/etc/shunya-lab", strings.Repeat("ab", 32)+"\n") {
		t.Fatal("cannot bind-mount a fake token")
	}
	_, err := backend.OpenBlock(env, p, backend.Options{Execute: true})
	mustRefuse(t, err, "token in /etc/shunya-lab does not match")
	t.Logf("%v", err)
}

func TestLabNotVMRefused(t *testing.T) {
	env := inLab(t)
	p := pathOf(t, env, "SHUNYA-NVME-01")
	if !bindOver(t, "/sys/devices/virtual/dmi/id/sys_vendor", "LENOVO\n") ||
		!bindOver(t, "/sys/devices/virtual/dmi/id/product_name", "ThinkPad X1\n") {
		t.Skip("SKIPPED: cannot bind-mount over DMI attributes in this kernel; covered by unit tests")
	}
	_, err := backend.OpenBlock(env, p, backend.Options{Execute: true})
	mustRefuse(t, err, "not a QEMU/KVM machine")
	t.Logf("%v", err)
}
