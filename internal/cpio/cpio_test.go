package cpio

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// parse reads a newc archive back (an independent reader for the tests).
func parse(t *testing.T, b []byte) []Entry {
	t.Helper()
	var out []Entry
	for off := 0; ; {
		if len(b)-off < 110 {
			t.Fatalf("truncated header at %d", off)
		}
		h := string(b[off : off+110])
		if h[:6] != "070701" {
			t.Fatalf("magic %q at %d", h[:6], off)
		}
		field := func(i int) uint32 {
			v, err := strconv.ParseUint(h[6+8*i:14+8*i], 16, 32)
			if err != nil {
				t.Fatalf("field %d: %v", i, err)
			}
			return uint32(v)
		}
		mode, size, namesize := field(1), field(6), field(11)
		if field(2) != 0 || field(3) != 0 {
			t.Fatalf("uid/gid not 0")
		}
		name := string(b[off+110 : off+110+int(namesize)-1])
		off = pad4(off + 110 + int(namesize))
		data := b[off : off+int(size)]
		off = pad4(off + int(size))
		if name == "TRAILER!!!" {
			if off != len(b) {
				t.Fatalf("%d bytes after the trailer", len(b)-off)
			}
			return out
		}
		out = append(out, Entry{Name: name, Mode: mode, Data: bytes.Clone(data), MTime: field(5),
			RDevMajor: field(9), RDevMinor: field(10), Ino: field(0)})
	}
}

func pad4(n int) int { return (n + 3) &^ 3 }

func TestWriteRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf, 1700000000)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.Dir("bin"))
	must(w.File("bin/busybox", 0o755, []byte("ELF…")))
	must(w.File("init", 0o755, []byte("#!/bin/busybox sh\n")))
	must(w.CharDev("dev/console", 0o600, 5, 1))
	must(w.Symlink("bin/sh", "busybox"))
	must(w.Close())
	es := parse(t, buf.Bytes())
	if len(es) != 5 {
		t.Fatalf("%d entries", len(es))
	}
	want := []struct {
		name string
		mode uint32
	}{{"bin", 0o040755}, {"bin/busybox", 0o100755}, {"init", 0o100755}, {"dev/console", 0o020600}, {"bin/sh", 0o120777}}
	for i, e := range es {
		if e.Name != want[i].name || e.Mode != want[i].mode || e.MTime != 1700000000 || e.Ino != uint32(i+1) {
			t.Errorf("entry %d: %s %o mtime %d ino %d", i, e.Name, e.Mode, e.MTime, e.Ino)
		}
	}
	if es[3].RDevMajor != 5 || es[3].RDevMinor != 1 || string(es[4].Data) != "busybox" || string(es[1].Data) != "ELF…" {
		t.Fatalf("%+v", es)
	}
}

// The same input gives the same bytes: no host time, owner or inode leaks in.
func TestDeterministic(t *testing.T) {
	build := func() []byte {
		var buf bytes.Buffer
		w := NewWriter(&buf, 42)
		for i := range 20 {
			w.File(fmt.Sprintf("f%02d", i), 0o644, bytes.Repeat([]byte{byte(i)}, i*7))
		}
		w.Close()
		return buf.Bytes()
	}
	if !bytes.Equal(build(), build()) {
		t.Fatal("two identical builds differ")
	}
}

func TestRejects(t *testing.T) {
	for _, name := range []string{"", "/abs", "a/../b", "./x", "a//b", "TRAILER!!!", "bad\x00name", "dir/"} {
		var buf bytes.Buffer
		w := NewWriter(&buf, 0)
		if err := w.File(name, 0o644, nil); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	var buf bytes.Buffer
	w := NewWriter(&buf, 0)
	w.File("a", 0o644, nil)
	if err := w.File("a", 0o644, nil); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate: %v", err)
	}
	if err := w.File("b", 0o4755, nil); err == nil {
		t.Error("setuid file accepted")
	}
	w.Close()
	if err := w.File("c", 0o644, nil); err == nil {
		t.Error("write after Close accepted")
	}
}
