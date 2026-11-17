package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func newImage(t *testing.T, size int64) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "disk.img")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return p
}

func TestFileRoundTrip(t *testing.T) {
	for _, ss := range []int{512, 4096} {
		p := newImage(t, 64*1024)
		f, err := OpenFile(p, FileOptions{Options: Options{Execute: true}, SectorSize: ss})
		if err != nil {
			t.Fatal(err)
		}
		if f.Size() != 64*1024 || f.SectorSize() != ss || f.PhysicalSectorSize() != ss {
			t.Fatalf("geometry %d/%d/%d", f.Size(), f.SectorSize(), f.PhysicalSectorSize())
		}
		buf := AlignedBuffer(ss, ss)
		for i := range buf {
			buf[i] = byte(i * 7)
		}
		if _, err := f.WriteAt(buf, int64(3*ss)); err != nil {
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		got := AlignedBuffer(ss, ss)
		if _, err := f.ReadAt(got, int64(3*ss)); err != nil || !bytes.Equal(got, buf) {
			t.Fatalf("read back mismatch (%v)", err)
		}
		id := f.Identity()
		if id.SizeBytes != 64*1024 || id.Path != p || id.Fingerprint == "" {
			t.Fatalf("identity %+v", id)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt(buf, 0); !errors.Is(err, ErrClosed) {
			t.Fatalf("write after close: %v", err)
		}
	}
}

func TestFileRefusals(t *testing.T) {
	dir := t.TempDir()
	img := newImage(t, 4096)
	link := filepath.Join(dir, "link.img")
	if err := os.Symlink(img, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	odd := filepath.Join(dir, "odd.img")
	os.WriteFile(odd, make([]byte, 1000), 0o600)
	for name, p := range map[string]string{
		"symlink":     link,
		"directory":   dir,
		"missing":     filepath.Join(dir, "nope"),
		"device node": nullDevice(),
		"odd size":    odd,
	} {
		if _, err := OpenFile(p, FileOptions{Options: Options{Execute: true}}); err == nil {
			t.Errorf("%s: opened %s", name, p)
		}
	}
}

func TestFileBoundsAlignmentDryRun(t *testing.T) {
	p := newImage(t, 8192)
	f, err := OpenFile(p, FileOptions{Options: Options{Execute: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(make([]byte, 512), 8192); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("past end: %v", err)
	}
	if _, err := f.WriteAt(make([]byte, 1024), 7680); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("straddling end: %v", err)
	}
	if _, err := f.WriteAt(make([]byte, 512), -512); !errors.Is(err, ErrOutOfRange) {
		t.Errorf("negative: %v", err)
	}
	if _, err := f.WriteAt(make([]byte, 100), 0); !errors.Is(err, ErrUnaligned) {
		t.Errorf("short length: %v", err)
	}
	if _, err := f.WriteAt(make([]byte, 512), 10); !errors.Is(err, ErrUnaligned) {
		t.Errorf("odd offset: %v", err)
	}
	if st, _ := os.Stat(p); st.Size() != 8192 {
		t.Fatalf("file grew to %d", st.Size())
	}

	dry, err := OpenFile(p, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer dry.Close()
	if _, err := dry.WriteAt(make([]byte, 512), 0); !errors.Is(err, ErrDryRun) {
		t.Errorf("dry-run write: %v", err)
	}
	if _, err := dry.ReadAt(make([]byte, 512), 0); err != nil {
		t.Errorf("dry-run read: %v", err)
	}
}

func TestFileDiscard(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("hole punching is Linux-only")
	}
	p := newImage(t, 1<<20)
	f, err := OpenFile(p, FileOptions{Options: Options{Execute: true}, SectorSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data := bytes.Repeat([]byte{0xA5}, 1<<20)
	if _, err := f.WriteAt(data, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Discard(4096, 8192); err != nil {
		t.Skipf("filesystem does not support hole punching: %v", err)
	}
	got := make([]byte, 3*4096)
	if _, err := f.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:4096], data[:4096]) || !bytes.Equal(got[4096:], make([]byte, 8192)) {
		t.Fatal("discarded range not zero or neighbour damaged")
	}
	if err := f.Discard(100, 4096); !errors.Is(err, ErrUnaligned) {
		t.Errorf("unaligned discard: %v", err)
	}
}

func TestAlignedBuffer(t *testing.T) {
	for _, a := range []int{512, 4096} {
		b := AlignedBuffer(3*a, a)
		if len(b) != 3*a || !IsAligned(b, a) {
			t.Fatalf("align %d: len %d aligned %v", a, len(b), IsAligned(b, a))
		}
		if IsAligned(b[1:], a) {
			t.Fatalf("offset slice reported aligned")
		}
	}
	if IsAligned(nil, 512) {
		t.Fatal("nil buffer aligned")
	}
}

func nullDevice() string {
	if runtime.GOOS == "windows" {
		return "NUL"
	}
	// Lstat/stat only: OpenFile must reject it before opening (it is a char device).
	return "/dev/null"
}
