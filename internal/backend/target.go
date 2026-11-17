// Package backend provides the storage targets wipe methods write to: FileBackend for
// regular image files (used on the development host and in tests) and BlockBackend for
// real block devices (Linux; lab VM or release builds only), plus the guards that
// decide whether a device may be opened at all.
//
// Safety model (design/SAFETY.md):
//   - Guards that apply in every build refuse the root and boot disks, the disk holding the
//     running binary, anything mounted, swapped on, or held by dm/md/btrfs, partitions,
//     read-only and logical devices, and drives whose identity can't be pinned down.
//   - Dev builds (no "release" tag) add the lab lock: QEMU/KVM DMI plus /etc/shunya-lab
//     matching a token compiled into lab builds only.
//   - Release builds drop the lab lock and require typed confirmation instead.
//   - BlockBackend opens with O_EXCL, checks the fd is the selected device, and re-checks
//     identity and use just before the first write (TOCTOU).
//   - Without Options.Execute every target is a dry run: writes return ErrDryRun.
package backend

import (
	"errors"
	"fmt"
	"strings"
)

// Target is a sector-addressed storage device. Offsets and lengths of ReadAt/WriteAt
// must be multiples of SectorSize; targets never grow.
type Target interface {
	Size() int64
	SectorSize() int         // logical sector size
	PhysicalSectorSize() int // physical sector size (alignment hint)
	ReadAt(p []byte, off int64) (int, error)
	WriteAt(p []byte, off int64) (int, error)
	Sync() error
	Identity() Identity
	Close() error
}

// Discarder is implemented by targets that can discard (TRIM/UNMAP/deallocate or punch
// holes in) a range. Reading a discarded range is not guaranteed to return zeros on real
// devices; callers must verify.
type Discarder interface {
	Discard(off, length int64) error
}

// Identity is what binds a target to one physical drive (or image file).
type Identity struct {
	Path        string `json:"path"`
	DevNum      string `json:"dev,omitempty"`
	Model       string `json:"model,omitempty"`
	Serial      string `json:"serial,omitempty"`
	WWID        string `json:"wwid,omitempty"`
	SizeBytes   uint64 `json:"size_bytes"`
	Fingerprint string `json:"fingerprint"`
}

// Options controls how a target is opened.
type Options struct {
	// Execute enables writes. Without it the target is a dry run (brief §2.3.5).
	Execute bool
	// Direct opens with O_DIRECT (bypass the page cache); buffers must then be aligned
	// to the logical sector size (see AlignedBuffer).
	Direct bool
	// Sync opens with O_SYNC: every write reaches the device before returning.
	Sync bool
	// Confirm is the operator's confirmation. Release builds require it; dev builds
	// check it only if given.
	Confirm *Confirmation
}

var (
	// ErrRefused is wrapped by every guard refusal (see RefusalError).
	ErrRefused = errors.New("refused by safety guard")
	// ErrIdentityChanged: the device is no longer the one that was selected.
	ErrIdentityChanged = errors.New("device identity changed since selection")
	ErrDryRun          = errors.New("dry run: writes need --execute")
	ErrUnaligned       = errors.New("offset, length or buffer not sector-aligned")
	ErrOutOfRange      = errors.New("access outside the target")
	ErrClosed          = errors.New("target closed")
	ErrUnsupported     = errors.ErrUnsupported
)

// RefusalError lists every reason a device was refused.
type RefusalError struct {
	Path    string
	Reasons []string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("%s: %v: %s", e.Path, ErrRefused, strings.Join(e.Reasons, "; "))
}

func (e *RefusalError) Unwrap() error { return ErrRefused }

// checkIO validates one ReadAt/WriteAt against target geometry.
func checkIO(p []byte, off, size int64, sector int, direct bool) error {
	n := int64(len(p))
	if off < 0 || n < 0 || off > size || n > size-off {
		return fmt.Errorf("%w: [%d, +%d) on %d bytes", ErrOutOfRange, off, n, size)
	}
	if off%int64(sector) != 0 || n%int64(sector) != 0 {
		return fmt.Errorf("%w: offset %d length %d, sector %d", ErrUnaligned, off, n, sector)
	}
	if direct && n > 0 && !IsAligned(p, sector) {
		return fmt.Errorf("%w: O_DIRECT buffer address not %d-aligned", ErrUnaligned, sector)
	}
	return nil
}
