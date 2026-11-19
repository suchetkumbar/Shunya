//go:build windows

package backend

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing/fstest"
	"time"

	"golang.org/x/sys/windows"

	"shunya/internal/device"
	"shunya/internal/nvme"
	"shunya/internal/winstorage"
	"shunya/internal/winstorage/winata"
)

// ErrWindowsWrite: Shunya does not write to physical disks on Windows. The Windows code
// lists disks, applies every guard and identifies drives (ATA IDENTIFY, NVMe Identify),
// so a plan can be shown; the wipe itself is done from the Shunya live image. It has
// been compiled and its parsers tested, but never run against a disk (design/SAFETY.md).
var ErrWindowsWrite = errors.New("writing to physical disks is not supported on Windows: boot the Shunya live image (design/IMAGE.md) to wipe it; image files can be wiped on Windows")

// LiveEnv is the running Windows system: its disks come from the storage IOCTLs, and FS
// carries only the firmware's DMI strings, so the lab lock of dev builds sees a
// non-QEMU machine without /etc/shunya-lab and refuses every disk.
func LiveEnv() (Env, error) {
	fs := fstest.MapFS{}
	rep, err := device.EnumerateWindowsLive()
	if err == nil {
		fs["sys/class/dmi/id/sys_vendor"] = &fstest.MapFile{Data: []byte(rep.System.DMIVendor + "\n")}
		fs["sys/class/dmi/id/product_name"] = &fstest.MapFile{Data: []byte(rep.System.DMIProduct + "\n")}
	}
	return Env{FS: fs, Enumerate: device.EnumerateWindowsLive}, nil
}

// Block is a physical disk on Windows, opened for identification only.
type Block struct {
	mu       sync.Mutex
	h        windows.Handle
	path     string
	selected device.Device
	closed   bool
}

// OpenBlock applies the same guards as on Linux (fresh enumeration, status, lab lock,
// confirmation) and opens the disk for pass-through queries. Execute is refused.
func OpenBlock(env Env, path string, opts Options) (*Block, error) {
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
	if opts.Execute {
		return nil, &RefusalError{Path: v.Path, Reasons: []string{ErrWindowsWrite.Error()}}
	}
	// IOCTL_ATA_PASS_THROUGH needs read/write access to the handle; no write is issued
	// through it (every mutating ATA command is refused below, as Execute is false).
	h, err := winstorage.Open(v.Device.Path, windows.GENERIC_READ|windows.GENERIC_WRITE)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", v.Device.Path, err)
	}
	return &Block{h: h, path: v.Device.Path, selected: *v.Device}, nil
}

func (b *Block) Size() int64             { return int64(b.selected.SizeBytes) }
func (b *Block) SectorSize() int         { return int(b.selected.LogicalSectorSize) }
func (b *Block) PhysicalSectorSize() int { return int(b.selected.PhysicalSectorSize) }
func (b *Block) Identity() Identity      { return IdentityOf(b.path, &b.selected) }

// ReadAt is not offered on Windows: verification runs in the live image with the wipe.
func (b *Block) ReadAt([]byte, int64) (int, error) {
	return 0, fmt.Errorf("%w: reading sectors", ErrWindowsWrite)
}

// WriteAt is refused on Windows.
func (b *Block) WriteAt([]byte, int64) (int, error) { return 0, ErrWindowsWrite }

// Sync has nothing to flush.
func (b *Block) Sync() error { return nil }

// Recheck: there are no writes to re-check before.
func (b *Block) Recheck() error { return nil }

func (b *Block) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	return windows.CloseHandle(b.h)
}

// PassThrough sends one allowlisted, non-mutating ATA command with
// IOCTL_ATA_PASS_THROUGH, translated from the same SAT CDB as on Linux; the registers
// come back as SAT sense data, so the ata package works unchanged.
func (b *Block) PassThrough(ctx context.Context, cdb [16]byte, data []byte, timeout time.Duration) ([]byte, error) {
	c, err := CheckATA(cdb, data)
	if err != nil {
		return nil, err
	}
	if c.Mutating {
		return nil, fmt.Errorf("%w: %s changes the drive", ErrWindowsWrite, c.Name)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !ATATransports[b.selected.Transport] {
		return nil, fmt.Errorf("%w: %s is a %s device, not ATA", ErrATARefused, b.path, b.selected.Transport)
	}
	r, err := winata.FromCDB(cdb)
	if err != nil {
		return nil, err
	}
	buf, err := winata.Encode(r, data, timeout)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	out, err := winstorage.InOut(b.h, winstorage.IOCTLATAPassThrough, buf)
	if err != nil {
		return nil, err
	}
	return winata.Decode(r, out, data)
}

// AdminCommand supports NVMe Identify only, through the protocol-specific property
// query (StorNVMe does not pass other admin commands from applications).
func (b *Block) AdminCommand(ctx context.Context, c nvme.AdminCmd, data []byte) (uint32, nvme.Status, error) {
	k, err := CheckNVMe(c, data)
	if err != nil {
		return 0, 0, err
	}
	if k.Mutating {
		return 0, 0, fmt.Errorf("%w: NVMe opcode %#02x changes the drive", ErrWindowsWrite, c.Opcode)
	}
	if c.Opcode != nvme.OpIdentify || len(data) != winstorage.NVMeIdentifyBytes {
		return 0, 0, fmt.Errorf("%w: NVMe opcode %#02x is not available to applications on Windows (StorNVMe); only Identify is", ErrNVMeRefused, c.Opcode)
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	if b.selected.Transport != device.TransportNVMe {
		return 0, 0, fmt.Errorf("%w: %s is a %s device, not NVMe", ErrNVMeRefused, b.path, b.selected.Transport)
	}
	q, err := winstorage.NVMeIdentifyQuery(uint8(c.CDW10), c.NSID)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %v", ErrNVMeRefused, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, 0, ErrClosed
	}
	out, err := winstorage.InOut(b.h, winstorage.IOCTLStorageQueryProperty, q)
	if err != nil {
		return 0, 0, err
	}
	id, err := winstorage.ParseNVMeIdentify(out)
	if err != nil {
		return 0, 0, err
	}
	copy(data, id)
	return 0, 0, nil
}
