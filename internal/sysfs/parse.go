// Package sysfs reads Linux sysfs and procfs through an fs.FS, so the same code runs
// against the real "/" (os.DirFS("/")) and against fake trees in tests.
//
// Everything here is read-only text parsing. Nothing in this package opens a device
// node, issues an ioctl or runs a command.
package sysfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DevNum is a Linux device number (major:minor), as in sysfs "dev" files and mountinfo.
type DevNum struct {
	Major, Minor uint32
}

func (d DevNum) String() string { return fmt.Sprintf("%d:%d", d.Major, d.Minor) }

// ParseDevNum parses "MAJOR:MINOR" (surrounding whitespace allowed).
func ParseDevNum(s string) (DevNum, error) {
	s = strings.TrimSpace(s)
	maj, min, ok := strings.Cut(s, ":")
	if !ok {
		return DevNum{}, fmt.Errorf("device number %q: missing ':'", s)
	}
	a, err1 := strconv.ParseUint(maj, 10, 32)
	b, err2 := strconv.ParseUint(min, 10, 32)
	if err1 != nil || err2 != nil {
		return DevNum{}, fmt.Errorf("device number %q: not two unsigned integers", s)
	}
	return DevNum{uint32(a), uint32(b)}, nil
}

// ParseUint parses a sysfs numeric attribute such as "size" or "queue/rotational".
func ParseUint(s string) (uint64, error) {
	return strconv.ParseUint(strings.TrimSpace(s), 10, 64)
}

// Mount is one line of /proc/<pid>/mountinfo (see proc(5)); only the fields Shunya needs.
type Mount struct {
	Dev        DevNum // st_dev of the filesystem; 0:N for anonymous devices (btrfs, overlay, tmpfs …)
	Root       string // path within the filesystem that forms the root of this mount
	MountPoint string
	FSType     string
	Source     string // e.g. /dev/sda1, /dev/mapper/vg-root, "none"
}

// ErrMalformed is wrapped by all parse errors.
var ErrMalformed = errors.New("malformed")

// ParseMountInfo parses /proc/<pid>/mountinfo. A single bad line fails the whole parse:
// silently skipping mounts could make a mounted disk look free.
func ParseMountInfo(b []byte) ([]Mount, error) {
	var out []Mount
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		// id parent maj:min root mountpoint opts [optional...] - fstype source superopts
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 7 || sep < 0 || len(f) < sep+3 {
			return nil, fmt.Errorf("mountinfo line %d: %w: %q", n, ErrMalformed, line)
		}
		dev, err := ParseDevNum(f[2])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: %w: %v", n, ErrMalformed, err)
		}
		m := Mount{
			Dev:        dev,
			Root:       unescapeOctal(f[3]),
			MountPoint: unescapeOctal(f[4]),
			FSType:     unescapeOctal(f[sep+1]),
			Source:     unescapeOctal(f[sep+2]),
		}
		if m.MountPoint == "" {
			return nil, fmt.Errorf("mountinfo line %d: %w: empty mount point", n, ErrMalformed)
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

// Swap is one active swap area from /proc/swaps.
type Swap struct {
	Path string // device node (/dev/sdc, /dev/dm-1) or a swap file path
	Type string // "partition" or "file"
}

// ParseSwaps parses /proc/swaps (header line first).
func ParseSwaps(b []byte) ([]Swap, error) {
	var out []Swap
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		f := strings.Fields(sc.Text())
		if n == 1 || len(f) == 0 {
			continue // header / blank
		}
		if len(f) < 2 {
			return nil, fmt.Errorf("swaps line %d: %w", n, ErrMalformed)
		}
		p := unescapeOctal(f[0])
		if p == "" {
			return nil, fmt.Errorf("swaps line %d: %w: empty path", n, ErrMalformed)
		}
		out = append(out, Swap{Path: p, Type: f[1]})
	}
	return out, sc.Err()
}

// ParseVPD80 extracts the unit serial number from a SCSI VPD page 0x80 (Unit Serial Number),
// as exposed in sysfs "device/vpd_pg80". Layout (SPC-4 7.8.18): byte 1 = page code 0x80,
// bytes 2-3 = big-endian page length, then ASCII serial, often space/NUL padded.
func ParseVPD80(b []byte) (string, error) {
	if len(b) < 4 {
		return "", fmt.Errorf("vpd 0x80: %w: %d bytes", ErrMalformed, len(b))
	}
	if b[1] != 0x80 {
		return "", fmt.Errorf("vpd 0x80: %w: page code %#x", ErrMalformed, b[1])
	}
	n := int(b[2])<<8 | int(b[3])
	if 4+n > len(b) {
		return "", fmt.Errorf("vpd 0x80: %w: length %d exceeds data %d", ErrMalformed, n, len(b)-4)
	}
	return strings.Trim(string(b[4:4+n]), " \x00\t\r\n"), nil
}

// unescapeOctal undoes the kernel's \ooo escaping of space, tab, newline and backslash
// in mountinfo and swaps (seq_escape). Invalid escapes are kept literally.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && isOct(s, i+1) {
			v, _ := strconv.ParseUint(s[i+1:i+4], 8, 8)
			b.WriteByte(byte(v))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOct(s string, i int) bool {
	if i+3 > len(s) {
		return false
	}
	for _, c := range []byte(s[i : i+3]) {
		if c < '0' || c > '7' {
			return false
		}
	}
	// \400..\777 do not fit in a byte; keep them literal.
	return s[i] <= '3'
}
