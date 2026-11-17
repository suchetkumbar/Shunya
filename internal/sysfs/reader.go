package sysfs

import (
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// Reader reads sysfs attributes from an fs.FS rooted at "/". Paths are fs.FS paths:
// relative, slash-separated, no leading "/" (e.g. "sys/block/sda/size").
type Reader struct {
	fsys fs.FS
}

// New returns a Reader over fsys. For the live system use New(os.DirFS("/")).
func New(fsys fs.FS) *Reader { return &Reader{fsys: fsys} }

// FS returns the underlying file system.
func (r *Reader) FS() fs.FS { return r.fsys }

// Bytes returns the raw content of name.
func (r *Reader) Bytes(name string) ([]byte, error) { return fs.ReadFile(r.fsys, name) }

// String returns the attribute with surrounding whitespace and NULs removed, or "" if it
// cannot be read. Use it only for descriptive attributes (model, vendor); use Uint/Bool
// for anything a safety decision depends on, so read errors are not mistaken for values.
func (r *Reader) String(name string) string {
	b, err := fs.ReadFile(r.fsys, name)
	if err != nil {
		return ""
	}
	return strings.Trim(string(b), " \t\r\n\x00")
}

// Uint reads a numeric attribute.
func (r *Reader) Uint(name string) (uint64, error) {
	b, err := fs.ReadFile(r.fsys, name)
	if err != nil {
		return 0, err
	}
	v, err := ParseUint(string(b))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return v, nil
}

// Bool reads a 0/1 attribute.
func (r *Reader) Bool(name string) (bool, error) {
	v, err := r.Uint(name)
	if err != nil {
		return false, err
	}
	if v > 1 {
		return false, fmt.Errorf("%s: %w: boolean value %d", name, ErrMalformed, v)
	}
	return v == 1, nil
}

// Exists reports whether name exists (following symlinks).
func (r *Reader) Exists(name string) bool {
	_, err := fs.Stat(r.fsys, name)
	return err == nil
}

// Names lists the entry names of directory dir, sorted. A missing directory yields nil.
func (r *Reader) Names(dir string) []string {
	es, err := fs.ReadDir(r.fsys, dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// Resolve returns the target of the symlink name as a clean fs.FS path. sysfs entries
// such as /sys/block/sda are symlinks into /sys/devices; the resolved path reveals the
// bus a disk sits on. Only the final element is resolved; /sys/devices itself has no links.
func (r *Reader) Resolve(name string) (string, error) {
	fi, err := fs.Lstat(r.fsys, name)
	if err != nil {
		return "", err
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		return "", fmt.Errorf("%s: not a symlink", name)
	}
	target, err := fs.ReadLink(r.fsys, name)
	if err != nil {
		return "", err
	}
	if path.IsAbs(target) {
		target = strings.TrimPrefix(path.Clean(target), "/")
	} else {
		target = path.Join(path.Dir(name), target)
	}
	if !fs.ValidPath(target) || target == "." || strings.HasPrefix(target, "../") || target == ".." {
		return "", fmt.Errorf("%s: link target %q escapes root", name, target)
	}
	return target, nil
}
