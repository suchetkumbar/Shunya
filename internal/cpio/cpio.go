// Package cpio writes the "newc" cpio format the Linux kernel unpacks as its initramfs
// (Documentation/driver-api/early-userspace/buffer-format.rst). It exists so the live
// image's initramfs is reproducible: entries are written in the caller's order with a
// fixed modification time, owner root:root, sequential inode numbers and no host
// metadata. Device nodes are header-only entries: writing one never touches a device.
package cpio

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	modeDir     = 0o040000
	modeFile    = 0o100000
	modeSymlink = 0o120000
	modeChar    = 0o020000
	trailer     = "TRAILER!!!"
)

// Entry is one archive member as the tests read it back.
type Entry struct {
	Name                 string
	Mode, MTime, Ino     uint32
	RDevMajor, RDevMinor uint32
	Data                 []byte
}

// Writer writes one archive.
type Writer struct {
	w      io.Writer
	mtime  uint32
	ino    uint32
	off    int64
	names  map[string]bool
	closed bool
	err    error
}

// NewWriter writes to w; every entry gets modification time mtime (seconds since the
// epoch; use SOURCE_DATE_EPOCH).
func NewWriter(w io.Writer, mtime uint32) *Writer {
	return &Writer{w: w, mtime: mtime, names: map[string]bool{}}
}

// Dir adds a directory (mode 0755).
func (w *Writer) Dir(name string) error { return w.entry(name, modeDir|0o755, 0, 0, nil) }

// File adds a regular file. perm is 0644 or 0755-style; setuid/setgid/sticky are refused.
func (w *Writer) File(name string, perm uint32, data []byte) error {
	if perm&^0o777 != 0 {
		return fmt.Errorf("cpio: %s: mode %o has bits beyond rwx", name, perm)
	}
	return w.entry(name, modeFile|perm, 0, 0, data)
}

// Symlink adds a symbolic link to target.
func (w *Writer) Symlink(name, target string) error {
	if target == "" || strings.ContainsRune(target, 0) {
		return fmt.Errorf("cpio: %s: bad link target %q", name, target)
	}
	return w.entry(name, modeSymlink|0o777, 0, 0, []byte(target))
}

// CharDev adds a character device node (e.g. dev/console 5:1).
func (w *Writer) CharDev(name string, perm, major, minor uint32) error {
	if perm&^0o777 != 0 {
		return fmt.Errorf("cpio: %s: mode %o has bits beyond rwx", name, perm)
	}
	return w.entry(name, modeChar|perm, major, minor, nil)
}

// Close writes the trailer. It does not close the underlying writer.
func (w *Writer) Close() error {
	if w.closed {
		return w.err
	}
	w.closed = true
	w.header(trailer, 0, 0, 0, 0, 0)
	return w.err
}

func validName(name string) error {
	switch {
	case name == "" || name == trailer || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/"):
	case strings.ContainsRune(name, 0):
	default:
		for _, part := range strings.Split(name, "/") {
			if part == "" || part == "." || part == ".." {
				return fmt.Errorf("cpio: bad name %q", name)
			}
		}
		return nil
	}
	return fmt.Errorf("cpio: bad name %q", name)
}

func (w *Writer) entry(name string, mode, major, minor uint32, data []byte) error {
	if w.closed {
		return errors.New("cpio: write after Close")
	}
	if err := validName(name); err != nil {
		return err
	}
	if w.names[name] {
		return fmt.Errorf("cpio: %s added twice", name)
	}
	if uint64(len(data)) > 1<<32-1 {
		return fmt.Errorf("cpio: %s is too large for newc", name)
	}
	w.names[name] = true
	w.ino++
	w.header(name, w.ino, mode, uint32(len(data)), major, minor)
	w.write(data)
	w.pad()
	return w.err
}

func (w *Writer) header(name string, ino, mode, size, major, minor uint32) {
	nlink := uint32(1)
	if mode&modeDir == modeDir && mode&modeFile == 0 {
		nlink = 2
	}
	if name == trailer {
		nlink = 1
	}
	mt := w.mtime
	if name == trailer {
		mt = 0
	}
	h := fmt.Sprintf("070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
		ino, mode, 0, 0, nlink, mt, size, 0, 0, major, minor, len(name)+1, 0)
	w.write([]byte(h))
	w.write([]byte(name))
	w.write([]byte{0})
	w.pad()
}

func (w *Writer) pad() {
	if n := w.off % 4; n != 0 {
		w.write(make([]byte, 4-n))
	}
}

func (w *Writer) write(b []byte) {
	if w.err != nil || len(b) == 0 {
		return
	}
	n, err := w.w.Write(b)
	w.off += int64(n)
	w.err = err
}
