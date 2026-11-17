package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/sys/unix"

	"shunya/internal/sysfs"
)

// fakeOps stands in for open(2), fstat and the size ioctls, so these tests never touch a
// device node. open is backed by a temp regular file sized like the fake disk.
type fakeOps struct {
	t      *testing.T
	opened []string
	flags  int
	info   probeInfo
	forbid bool // fail the test if open is reached
	disc   [][2]uint64
}

func (f *fakeOps) ops() blockOps {
	return blockOps{
		open: func(path string, flags int) (*os.File, error) {
			if f.forbid {
				f.t.Fatalf("open(%s) reached although the guard should have refused", path)
			}
			f.opened = append(f.opened, path)
			f.flags = flags
			p := filepath.Join(f.t.TempDir(), "fake-"+filepath.Base(path))
			fh, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o600)
			if err != nil {
				return nil, err
			}
			return fh, fh.Truncate(f.info.Size)
		},
		probe:   func(*os.File) (probeInfo, error) { return f.info, nil },
		discard: func(_ *os.File, off, n uint64) error { f.disc = append(f.disc, [2]uint64{off, n}); return nil },
	}
}

// sdbInfo matches /dev/sdb in lab-vm.spec (8:16, 1 GiB, 512/512).
func sdbInfo() probeInfo {
	return probeInfo{IsBlock: true, Rdev: sysfs.DevNum{Major: 8, Minor: 16}, Size: 2097152 * 512, Logical: 512, Physical: 512}
}

const sdbDir = "sys/devices/pci0000:00/0000:00:04.0/ata2/host1/target1:0:0/1:0:0:0"

func TestBlockRefusedNeverOpens(t *testing.T) {
	env, _ := labEnv(t)
	for _, p := range []string{"/dev/vda", "/dev/vda1", "/dev/sr0", "/dev/nope"} {
		fo := &fakeOps{t: t, forbid: true}
		_, err := openBlock(env, p, Options{Execute: true}, fo.ops())
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: err %v, want refusal", p, err)
		}
	}
}

func TestBlockOutsideLabNeverOpens(t *testing.T) {
	if BuildKind != "dev" {
		t.Skip("lab lock exists only in dev builds")
	}
	withLabToken(t, testToken)
	fo := &fakeOps{t: t, forbid: true}
	_, err := openBlock(Env{FS: spec(t, "workstation")}, "/dev/sda", Options{Execute: true}, fo.ops())
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "lab lock") {
		t.Fatalf("err %v", err)
	}
}

func openSDB(t *testing.T, opts Options) (*Block, *fakeOps, fstest.MapFS) {
	t.Helper()
	env, m := labEnv(t)
	fo := &fakeOps{t: t, info: sdbInfo()}
	if RequiresConfirmation() && opts.Confirm == nil {
		opts.Confirm = &Confirmation{Typed: "D-01"} // serial SHUNYA-SATA-SSD-01
	}
	b, err := openBlock(env, "/dev/sdb", opts, fo.ops())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b, fo, m
}

func TestBlockOpenFlagsAndWrite(t *testing.T) {
	b, fo, _ := openSDB(t, Options{Execute: true, Direct: true, Sync: true})
	if len(fo.opened) != 1 || fo.opened[0] != "/dev/sdb" {
		t.Fatalf("opened %v", fo.opened)
	}
	for name, fl := range map[string]int{"O_EXCL": unix.O_EXCL, "O_RDWR": unix.O_RDWR, "O_DIRECT": unix.O_DIRECT, "O_SYNC": unix.O_SYNC, "O_CLOEXEC": unix.O_CLOEXEC} {
		if fo.flags&fl != fl {
			t.Errorf("open flags %#x lack %s", fo.flags, name)
		}
	}
	if b.Size() != 2097152*512 || b.SectorSize() != 512 {
		t.Fatalf("geometry %d %d", b.Size(), b.SectorSize())
	}
	if id := b.Identity(); id.Serial != "SHUNYA-SATA-SSD-01" || id.DevNum != "8:16" {
		t.Fatalf("identity %+v", id)
	}
	buf := AlignedBuffer(4096, 4096)
	copy(buf, "shunya")
	if _, err := b.WriteAt(buf, 1<<20); err != nil {
		t.Fatal(err)
	}
	got := AlignedBuffer(4096, 4096)
	if _, err := b.ReadAt(got, 1<<20); err != nil || !bytes.Equal(got, buf) {
		t.Fatalf("read back: %v", err)
	}
	if _, err := b.WriteAt(buf[1:513], 0); !errors.Is(err, ErrUnaligned) {
		t.Fatalf("unaligned buffer with O_DIRECT: %v", err)
	}
	if err := b.Discard(0, 1<<20); err != nil || len(fo.disc) != 1 {
		t.Fatalf("discard: %v %v", err, fo.disc)
	}
}

func TestBlockDryRun(t *testing.T) {
	b, fo, _ := openSDB(t, Options{})
	if fo.flags&unix.O_EXCL == 0 || fo.flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("dry-run open flags %#x: want O_RDONLY|O_EXCL", fo.flags)
	}
	if _, err := b.WriteAt(make([]byte, 512), 0); !errors.Is(err, ErrDryRun) {
		t.Fatalf("write: %v", err)
	}
	if err := b.Discard(0, 512); !errors.Is(err, ErrDryRun) {
		t.Fatalf("discard: %v", err)
	}
}

func TestBlockProbeMismatch(t *testing.T) {
	tests := map[string]func(*probeInfo){
		"not a block device":      func(p *probeInfo) { p.IsBlock = false },
		"device number differs":   func(p *probeInfo) { p.Rdev = sysfs.DevNum{Major: 8, Minor: 0} },
		"size differs":            func(p *probeInfo) { p.Size -= 512 },
		"logical sector differs":  func(p *probeInfo) { p.Logical = 4096 },
		"physical sector differs": func(p *probeInfo) { p.Physical = 4096 },
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			env, _ := labEnv(t)
			fo := &fakeOps{t: t, info: sdbInfo()}
			mut(&fo.info)
			opts := Options{Execute: true, Confirm: &Confirmation{Typed: "D-01"}}
			if _, err := openBlock(env, "/dev/sdb", opts, fo.ops()); !errors.Is(err, ErrIdentityChanged) {
				t.Fatalf("err %v, want ErrIdentityChanged", err)
			}
		})
	}
}

// TOCTOU: the drive is swapped (or starts being used) after selection and open, before
// the first write. The re-check must refuse the write and kill the target.
func TestBlockTOCTOU(t *testing.T) {
	tests := map[string]func(m fstest.MapFS){
		"serial changed (drive swapped)": func(m fstest.MapFS) {
			m[sdbDir+"/vpd_pg80"].Data = append([]byte{0, 0x80, 0, 9}, "OTHERDISK"...)
		},
		"size changed": func(m fstest.MapFS) { m[sdbDir+"/block/sdb/size"].Data = []byte("4194304\n") },
		"wwid changed": func(m fstest.MapFS) { m[sdbDir+"/wwid"].Data = []byte("naa.5000000000000001\n") },
		"device number changed": func(m fstest.MapFS) {
			m[sdbDir+"/block/sdb/dev"].Data = []byte("8:48\n")
		},
		"now mounted": func(m fstest.MapFS) {
			m["proc/self/mountinfo"].Data = append(m["proc/self/mountinfo"].Data, "40 20 8:16 / /mnt rw - ext4 /dev/sdb rw\n"...)
		},
		"disappeared": func(m fstest.MapFS) {
			delete(m, "sys/block/sdb")
			delete(m, "sys/class/block/sdb")
		},
	}
	for name, mut := range tests {
		t.Run(name, func(t *testing.T) {
			b, _, m := openSDB(t, Options{Execute: true})
			mut(m)
			buf := AlignedBuffer(512, 512)
			if _, err := b.WriteAt(buf, 0); !errors.Is(err, ErrIdentityChanged) && !errors.Is(err, ErrRefused) {
				t.Fatalf("first write: %v, want identity/refusal error", err)
			}
			// The target is dead: later writes fail even if the change is undone.
			if _, err := b.WriteAt(buf, 0); err == nil {
				t.Fatal("second write succeeded on a dead target")
			}
		})
	}
}

func TestBlockRecheckOnlyBeforeFirstWrite(t *testing.T) {
	b, _, m := openSDB(t, Options{Execute: true})
	buf := AlignedBuffer(512, 512)
	if _, err := b.WriteAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	// After the first write the fd is the identity; sysfs is not re-read per write
	// (that would cost a full enumeration per block). Removing sysfs must not matter.
	delete(m, "proc/self/mountinfo")
	if _, err := b.WriteAt(buf, 512); err != nil {
		t.Fatalf("second write: %v", err)
	}
}

// Recheck is the mid-wipe identity check (the engine calls it at every checkpoint):
// after a swap it fails and the target is dead for every later write.
func TestBlockRecheckMidWipe(t *testing.T) {
	b, _, m := openSDB(t, Options{Execute: true})
	buf := AlignedBuffer(512, 512)
	if _, err := b.WriteAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.Recheck(); err != nil {
		t.Fatalf("unchanged device: %v", err)
	}
	m[sdbDir+"/vpd_pg80"].Data = append([]byte{0, 0x80, 0, 9}, "OTHERDISK"...)
	if err := b.Recheck(); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("swapped device: %v", err)
	}
	if _, err := b.WriteAt(buf, 512); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("write after failed recheck: %v", err)
	}
	if err := b.Recheck(); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("dead target recheck: %v", err)
	}
}

func TestBlockReleaseNeedsConfirmation(t *testing.T) {
	if !RequiresConfirmation() {
		t.Skip("dev builds rely on the lab lock instead")
	}
	env, _ := labEnv(t)
	fo := &fakeOps{t: t, info: sdbInfo(), forbid: true}
	for _, c := range []*Confirmation{nil, {Typed: "XXXX"}} {
		if _, err := openBlock(env, "/dev/sdb", Options{Execute: true, Confirm: c}, fo.ops()); !errors.Is(err, ErrRefused) {
			t.Fatalf("confirmation %+v: err %v", c, err)
		}
	}
}
