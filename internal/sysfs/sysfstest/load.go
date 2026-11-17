// Package sysfstest builds fake sysfs/procfs trees for tests from small text specs, so a
// scenario such as "root on LVM on LUKS" reads as a page of text in testdata/ instead of
// a hundred map literals. Test-only: it never touches the real file system except to
// read the spec file.
//
// Spec format, one directive per line ("#" starts a comment line):
//
//	disk NAME MAJ:MIN DEVDIR [DEVICE]   whole disk at DEVDIR (fs path); creates sys/block/NAME,
//	                                     sys/class/block/NAME and DEVDIR/device -> DEVICE
//	                                     (default "../..", "-" for none). Then cd DEVDIR.
//	part NAME N MAJ:MIN START SECTORS   partition N of the current disk. Then cd into it.
//	cd DIR                               set the directory for relative paths
//	PATH = TEXT                          regular file containing TEXT + "\n"
//	PATH =x HEX                          regular file with the given bytes
//	PATH =vpd80 SERIAL                   SCSI VPD page 0x80 (4-byte header + SERIAL)
//	PATH -> TARGET                       symlink
//	PATH <<EOF ... EOF                   multi-line file (here-document)
//
// PATH and DIR starting with "/" are relative to the fake root; others to the current dir.
package sysfstest

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing/fstest"
)

// Load reads a spec file and returns the fake tree.
func Load(specFile string) (fstest.MapFS, error) {
	b, err := os.ReadFile(specFile)
	if err != nil {
		return nil, err
	}
	return Parse(string(b))
}

// Parse builds a fake tree from spec text.
func Parse(spec string) (fstest.MapFS, error) {
	m := fstest.MapFS{}
	cwd := ""
	disk := ""
	abs := func(p string) string {
		if strings.HasPrefix(p, "/") {
			return strings.TrimPrefix(path.Clean(p), "/")
		}
		return path.Join(cwd, p)
	}
	file := func(p, s string) { m[p] = &fstest.MapFile{Data: []byte(s), Mode: 0o444} }
	link := func(p, t string) { m[p] = &fstest.MapFile{Data: []byte(t), Mode: fs.ModeSymlink | 0o777} }

	sc := bufio.NewScanner(strings.NewReader(spec))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		errf := func(format string, a ...any) error {
			return fmt.Errorf("spec line %d (%q): %s", n, line, fmt.Sprintf(format, a...))
		}
		switch {
		case f[0] == "disk":
			if len(f) < 4 || len(f) > 5 {
				return nil, errf("want: disk NAME MAJ:MIN DEVDIR [DEVICE]")
			}
			name, dir := f[1], abs(f[3])
			if path.Base(dir) != name {
				return nil, errf("DEVDIR must end in /%s", name)
			}
			link("sys/block/"+name, "../"+strings.TrimPrefix(dir, "sys/"))
			link("sys/class/block/"+name, "../../"+strings.TrimPrefix(dir, "sys/"))
			file(dir+"/dev", f[2])
			file(dir+"/uevent", "DEVNAME="+name+"\nDEVTYPE=disk")
			dev := "../.."
			if len(f) == 5 {
				dev = f[4]
			}
			if dev != "-" {
				link(dir+"/device", dev)
			}
			cwd, disk = dir, dir
		case f[0] == "part":
			if len(f) != 6 || disk == "" {
				return nil, errf("want: part NAME N MAJ:MIN START SECTORS (after a disk)")
			}
			dir := disk + "/" + f[1]
			link("sys/class/block/"+f[1], "../../"+strings.TrimPrefix(dir, "sys/"))
			file(dir+"/partition", f[2])
			file(dir+"/dev", f[3])
			file(dir+"/start", f[4])
			file(dir+"/size", f[5])
			file(dir+"/uevent", "DEVNAME="+f[1]+"\nDEVTYPE=partition\nPARTN="+f[2])
			cwd = dir
		case f[0] == "cd":
			if len(f) != 2 {
				return nil, errf("want: cd DIR")
			}
			cwd = abs(f[1])
		case len(f) >= 2 && f[1] == "->":
			if len(f) != 3 {
				return nil, errf("want: PATH -> TARGET")
			}
			link(abs(f[0]), f[2])
		case len(f) >= 2 && f[1] == "=":
			_, val, _ := strings.Cut(line, "=")
			file(abs(f[0]), strings.TrimPrefix(val, " ")+"\n")
		case len(f) >= 2 && f[1] == "=x":
			raw, err := hex.DecodeString(strings.Join(f[2:], ""))
			if err != nil {
				return nil, errf("bad hex: %v", err)
			}
			m[abs(f[0])] = &fstest.MapFile{Data: raw, Mode: 0o444}
		case len(f) >= 2 && f[1] == "=vpd80":
			// SCSI VPD page 0x80 (unit serial number) with the 4-byte header, as in sysfs.
			_, val, _ := strings.Cut(line, "=vpd80")
			s := strings.TrimPrefix(val, " ")
			m[abs(f[0])] = &fstest.MapFile{Data: append([]byte{0, 0x80, byte(len(s) >> 8), byte(len(s))}, s...), Mode: 0o444}
		case len(f) == 2 && strings.HasPrefix(f[1], "<<"):
			term := strings.TrimPrefix(f[1], "<<")
			var body strings.Builder
			closed := false
			for sc.Scan() {
				n++
				if strings.TrimSpace(sc.Text()) == term {
					closed = true
					break
				}
				body.WriteString(strings.TrimLeft(sc.Text(), " \t"))
				body.WriteByte('\n')
			}
			if !closed {
				return nil, errf("unterminated here-document")
			}
			file(abs(f[0]), body.String())
		default:
			return nil, errf("unknown directive")
		}
	}
	return m, sc.Err()
}
