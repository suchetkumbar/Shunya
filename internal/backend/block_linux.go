package backend

import (
	"fmt"
	"io"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"shunya/internal/device"
	"shunya/internal/sysfs"
)

// probeInfo is what the open descriptor says about itself.
type probeInfo struct {
	IsBlock           bool
	Rdev              sysfs.DevNum
	Size              int64
	Logical, Physical int
}

// blockOps are the system calls BlockBackend makes. Tests replace them so guard logic
// runs on the development host without any device node being opened.
type blockOps struct {
	open    func(path string, flags int) (*os.File, error)
	probe   func(f *os.File) (probeInfo, error)
	discard func(f *os.File, off, length uint64) error
}

var liveOps = blockOps{open: sysOpen, probe: sysProbe, discard: sysDiscard}

// Block is the BlockBackend: a whole block device opened exclusively.
type Block struct {
	mu       sync.Mutex
	f        *os.File
	env      Env
	path     string
	opts     Options
	ops      blockOps
	selected device.Device
	info     probeInfo
	checked  bool  // TOCTOU re-check done (before the first write)
	dead     error // set once the target must not be used again
}

var _ Target = (*Block)(nil)
var _ Discarder = (*Block)(nil)

// OpenBlock opens a whole block device as a wipe target:
//
//  1. Check: every guard and (dev builds) the lab lock, from a fresh enumeration.
//  2. Confirmation: required in release builds, checked whenever given.
//  3. open(2) with O_EXCL (the kernel refuses it for a device that is mounted or claimed
//     by dm/md/another exclusive opener, in any namespace) and O_CLOEXEC.
//  4. The descriptor must be a block device whose device number, size and sector sizes
//     match what was selected; /dev/NAME could have been replaced in between.
//
// Writes additionally re-check identity once, just before the first write (see WriteAt).
func OpenBlock(env Env, path string, opts Options) (*Block, error) {
	return openBlock(env, path, opts, liveOps)
}

func openBlock(env Env, path string, opts Options, ops blockOps) (*Block, error) {
	v, err := Check(env, path)
	if err != nil {
		return nil, err
	}
	if !v.Allowed {
		return nil, &RefusalError{Path: v.Path, Reasons: v.Reasons}
	}
	if opts.Confirm != nil || RequiresConfirmation() {
		if err := opts.Confirm.Check(v.Device); err != nil {
			return nil, err
		}
	}
	flags := unix.O_RDONLY
	if opts.Execute {
		flags = unix.O_RDWR
	}
	flags |= unix.O_EXCL | unix.O_CLOEXEC
	if opts.Direct {
		flags |= unix.O_DIRECT
	}
	if opts.Sync {
		flags |= unix.O_SYNC
	}
	f, err := ops.open(v.Path, flags)
	if err != nil {
		return nil, fmt.Errorf("open %s exclusively: %w", v.Path, err)
	}
	b := &Block{f: f, env: env, path: v.Path, opts: opts, ops: ops, selected: *v.Device}
	if err := b.verifyDescriptor(); err != nil {
		f.Close()
		return nil, err
	}
	return b, nil
}

// verifyDescriptor checks that the open fd is the selected device.
func (b *Block) verifyDescriptor() error {
	info, err := b.ops.probe(b.f)
	if err != nil {
		return fmt.Errorf("probe %s: %w", b.path, err)
	}
	d := b.selected
	var why []string
	if !info.IsBlock {
		why = append(why, "not a block device")
	}
	if info.Rdev.String() != d.DevNum {
		why = append(why, fmt.Sprintf("device number %s, selected %s", info.Rdev, d.DevNum))
	}
	if info.Size < 0 || uint64(info.Size) != d.SizeBytes {
		why = append(why, fmt.Sprintf("size %d, selected %d", info.Size, d.SizeBytes))
	}
	if d.LogicalSectorSize != 0 && info.Logical != int(d.LogicalSectorSize) {
		why = append(why, fmt.Sprintf("logical sector %d, sysfs %d", info.Logical, d.LogicalSectorSize))
	}
	if d.PhysicalSectorSize != 0 && info.Physical != int(d.PhysicalSectorSize) {
		why = append(why, fmt.Sprintf("physical sector %d, sysfs %d", info.Physical, d.PhysicalSectorSize))
	}
	if info.Logical < 512 || info.Logical&(info.Logical-1) != 0 {
		why = append(why, fmt.Sprintf("unusable logical sector size %d", info.Logical))
	}
	if len(why) > 0 {
		return fmt.Errorf("%s: %w: %v", b.path, ErrIdentityChanged, why)
	}
	b.info = info
	return nil
}

// recheck is the TOCTOU defence: a fresh enumeration must still allow the device and
// show the same identity as at selection, and the descriptor must still match.
func (b *Block) recheck() error {
	v, err := Check(b.env, b.path)
	if err != nil {
		return err
	}
	if !v.Allowed {
		return &RefusalError{Path: b.path, Reasons: append([]string{"re-check before first write"}, v.Reasons...)}
	}
	s, n := b.selected, v.Device
	var why []string
	if s.DevNum != n.DevNum {
		why = append(why, "device number "+s.DevNum+" → "+n.DevNum)
	}
	if s.Serial != n.Serial {
		why = append(why, fmt.Sprintf("serial %q → %q", s.Serial, n.Serial))
	}
	if s.WWID != n.WWID {
		why = append(why, fmt.Sprintf("wwid %q → %q", s.WWID, n.WWID))
	}
	if s.SizeBytes != n.SizeBytes {
		why = append(why, fmt.Sprintf("size %d → %d", s.SizeBytes, n.SizeBytes))
	}
	if s.Fingerprint.Value != n.Fingerprint.Value {
		why = append(why, "fingerprint "+s.Fingerprint.Value+" → "+n.Fingerprint.Value)
	}
	if len(why) > 0 {
		return fmt.Errorf("%s: %w: %v", b.path, ErrIdentityChanged, why)
	}
	return b.verifyDescriptor()
}

// beforeWrite runs under b.mu for every mutating call.
func (b *Block) beforeWrite() error {
	if b.dead != nil {
		return b.dead
	}
	if !b.opts.Execute {
		return ErrDryRun
	}
	if !b.checked {
		if err := b.recheck(); err != nil {
			b.kill(err)
			return err
		}
		b.checked = true
	}
	return nil
}

// kill closes the descriptor and makes every later call fail with err.
func (b *Block) kill(err error) {
	b.dead = err
	b.f.Close()
}

func (b *Block) Size() int64             { return b.info.Size }
func (b *Block) SectorSize() int         { return b.info.Logical }
func (b *Block) PhysicalSectorSize() int { return b.info.Physical }

func (b *Block) Identity() Identity {
	d := b.selected
	return Identity{Path: b.path, DevNum: d.DevNum, Model: d.Model, Serial: d.Serial, WWID: d.WWID,
		SizeBytes: d.SizeBytes, Fingerprint: d.Fingerprint.Value}
}

func (b *Block) ReadAt(p []byte, off int64) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dead != nil {
		return 0, b.dead
	}
	if err := checkIO(p, off, b.info.Size, b.info.Logical, b.opts.Direct); err != nil {
		return 0, err
	}
	return b.f.ReadAt(p, off)
}

func (b *Block) WriteAt(p []byte, off int64) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := checkIO(p, off, b.info.Size, b.info.Logical, b.opts.Direct); err != nil {
		return 0, err
	}
	if err := b.beforeWrite(); err != nil {
		return 0, err
	}
	return b.f.WriteAt(p, off)
}

// Discard issues BLKDISCARD for the range. Devices may ignore it or return old data
// afterwards; callers must not count a discard as erasure without verification.
func (b *Block) Discard(off, length int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := checkIO(nil, off, b.info.Size, b.info.Logical, false); err != nil {
		return err
	}
	if length <= 0 || length%int64(b.info.Logical) != 0 || length > b.info.Size-off {
		return fmt.Errorf("%w: discard [%d,+%d)", ErrUnaligned, off, length)
	}
	if err := b.beforeWrite(); err != nil {
		return err
	}
	return b.ops.discard(b.f, uint64(off), uint64(length))
}

func (b *Block) Sync() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dead != nil {
		return b.dead
	}
	return b.f.Sync()
}

func (b *Block) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dead != nil {
		return nil
	}
	b.dead = ErrClosed
	return b.f.Close()
}

// ---- real system calls (reached only after every guard passed) ----

func sysOpen(path string, flags int) (*os.File, error) {
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func sysProbe(f *os.File) (probeInfo, error) {
	var info probeInfo
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return info, err
	}
	info.IsBlock = st.Mode&unix.S_IFMT == unix.S_IFBLK
	info.Rdev = sysfs.DevNum{Major: unix.Major(st.Rdev), Minor: unix.Minor(st.Rdev)}
	if !info.IsBlock {
		return info, nil
	}
	// The size of a block device is where its end is; no ioctl needed.
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return info, err
	}
	info.Size = size
	if info.Logical, err = unix.IoctlGetInt(int(f.Fd()), unix.BLKSSZGET); err != nil {
		return info, fmt.Errorf("BLKSSZGET: %w", err)
	}
	if info.Physical, err = unix.IoctlGetInt(int(f.Fd()), unix.BLKPBSZGET); err != nil {
		return info, fmt.Errorf("BLKPBSZGET: %w", err)
	}
	return info, nil
}

func sysDiscard(f *os.File, off, length uint64) error {
	r := [2]uint64{off, length}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKDISCARD, uintptr(unsafe.Pointer(&r[0])))
	if errno != 0 {
		return fmt.Errorf("BLKDISCARD: %w", errno)
	}
	return nil
}
