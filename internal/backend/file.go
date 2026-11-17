package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"shunya/internal/device"
)

// FileOptions configures a FileBackend.
type FileOptions struct {
	Options
	SectorSize         int // logical sector size to emulate (default 512)
	PhysicalSectorSize int // default: SectorSize
}

// File is the FileBackend: a regular image file presented as a disk. It is the only
// backend destructive code may use on the development host (brief §2.1.2).
type File struct {
	mu     sync.Mutex
	f      *os.File
	opts   FileOptions
	size   int64
	id     Identity
	closed bool
}

var _ Target = (*File)(nil)
var _ Discarder = (*File)(nil)

// OpenFile opens a regular image file. Symlinks, devices, directories, and files whose
// size is not a whole number of sectors are refused. The file type is checked before
// opening (so a device node is never opened) and again on the open descriptor, which
// must be the same file (no swap between the two checks).
func OpenFile(path string, opts FileOptions) (*File, error) {
	if opts.SectorSize == 0 {
		opts.SectorSize = 512
	}
	if opts.PhysicalSectorSize == 0 {
		opts.PhysicalSectorSize = opts.SectorSize
	}
	if opts.SectorSize < 512 || opts.SectorSize&(opts.SectorSize-1) != 0 || opts.PhysicalSectorSize%opts.SectorSize != 0 {
		return nil, fmt.Errorf("file backend: bad sector sizes %d/%d", opts.SectorSize, opts.PhysicalSectorSize)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	pre, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !pre.Mode().IsRegular() {
		return nil, fmt.Errorf("file backend: %s is not a regular file (%s): %w", abs, pre.Mode().Type(), ErrRefused)
	}
	flags := os.O_RDONLY
	if opts.Execute {
		flags = os.O_RDWR
	}
	if opts.Direct {
		if directFlag == 0 {
			return nil, fmt.Errorf("file backend: O_DIRECT: %w on this OS", ErrUnsupported)
		}
		flags |= directFlag
	}
	if opts.Sync {
		flags |= os.O_SYNC
	}
	f, err := os.OpenFile(abs, flags|noFollowFlag, 0)
	if err != nil {
		return nil, err
	}
	post, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !post.Mode().IsRegular() || !os.SameFile(pre, post) {
		f.Close()
		return nil, fmt.Errorf("file backend: %s changed while opening: %w", abs, ErrIdentityChanged)
	}
	size := post.Size()
	if size == 0 || size%int64(opts.SectorSize) != 0 {
		f.Close()
		return nil, fmt.Errorf("file backend: size %d is not a positive multiple of %d", size, opts.SectorSize)
	}
	fp := device.ComputeFingerprint(device.FingerprintInput{Model: "image-file", Serial: abs, CapacityBytes: uint64(size)})
	return &File{f: f, opts: opts, size: size, id: Identity{
		Path: abs, Model: "image-file", Serial: abs, SizeBytes: uint64(size), Fingerprint: fp.Value,
	}}, nil
}

func (t *File) Size() int64             { return t.size }
func (t *File) SectorSize() int         { return t.opts.SectorSize }
func (t *File) PhysicalSectorSize() int { return t.opts.PhysicalSectorSize }
func (t *File) Identity() Identity      { return t.id }
func (t *File) live() error {
	if t.closed {
		return ErrClosed
	}
	return nil
}

func (t *File) ReadAt(p []byte, off int64) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.live(); err != nil {
		return 0, err
	}
	if err := checkIO(p, off, t.size, t.opts.SectorSize, t.opts.Direct); err != nil {
		return 0, err
	}
	return t.f.ReadAt(p, off)
}

func (t *File) WriteAt(p []byte, off int64) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.live(); err != nil {
		return 0, err
	}
	if !t.opts.Execute {
		return 0, ErrDryRun
	}
	if err := checkIO(p, off, t.size, t.opts.SectorSize, t.opts.Direct); err != nil {
		return 0, err
	}
	return t.f.WriteAt(p, off)
}

// Discard punches a hole (Linux fallocate PUNCH_HOLE|KEEP_SIZE); the range reads as zeros.
func (t *File) Discard(off, length int64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.live(); err != nil {
		return err
	}
	if !t.opts.Execute {
		return ErrDryRun
	}
	if err := checkIO(nil, off, t.size, t.opts.SectorSize, false); err != nil {
		return err
	}
	if length <= 0 || length%int64(t.opts.SectorSize) != 0 {
		return fmt.Errorf("%w: discard length %d", ErrUnaligned, length)
	}
	if length > t.size-off {
		return fmt.Errorf("%w: discard [%d,+%d)", ErrOutOfRange, off, length)
	}
	return punchHole(t.f, off, length)
}

func (t *File) Sync() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.live(); err != nil {
		return err
	}
	return t.f.Sync()
}

func (t *File) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.f.Close()
}
