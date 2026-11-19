//go:build windows

package winstorage

import (
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IOCTL codes (winioctl.h, ntddscsi.h). Only read-only queries and ATA pass-through
// are used; the ATA commands themselves are filtered by backend.CheckATA.
const (
	IOCTLStorageQueryProperty      = 0x002D1400
	IOCTLDiskGetDriveGeometryEx    = 0x000700A0
	IOCTLDiskGetDriveLayoutEx      = 0x00070050
	IOCTLDiskIsWritable            = 0x00070024
	IOCTLVolumeGetVolumeDiskExtent = 0x00560000
	IOCTLATAPassThrough            = 0x0004D02C
)

// DiskPath is the Win32 device path of physical disk n.
func DiskPath(n uint32) string { return `\\.\PhysicalDrive` + strconv.FormatUint(uint64(n), 10) }

// Open opens a device path for IOCTLs. access 0 is enough for the storage queries (it
// grants no read or write access to the medium); IOCTL_ATA_PASS_THROUGH needs
// GENERIC_READ|GENERIC_WRITE, which still writes nothing by itself.
func Open(path string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

// IOCTL issues one DeviceIoControl. If out is 0 the call has no output buffer. Output
// buffers that are too small are retried larger (up to 1 MiB).
func IOCTL(h windows.Handle, code uint32, in []byte, out int) ([]byte, error) {
	for {
		var inp, outp *byte
		if len(in) > 0 {
			inp = &in[0]
		}
		buf := make([]byte, out)
		if out > 0 {
			outp = &buf[0]
		}
		var n uint32
		err := windows.DeviceIoControl(h, code, inp, uint32(len(in)), outp, uint32(out), &n, nil)
		if (errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || errors.Is(err, windows.ERROR_MORE_DATA)) && out > 0 && out < 1<<20 {
			out *= 4
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("DeviceIoControl %#08x: %w", code, err)
		}
		return buf[:n], nil
	}
}

// InOut issues an IOCTL whose input buffer is also its output (the double-buffered
// pass-through IOCTLs and the protocol-specific property query).
func InOut(h windows.Handle, code uint32, buf []byte) ([]byte, error) {
	var n uint32
	if err := windows.DeviceIoControl(h, code, &buf[0], uint32(len(buf)), &buf[0], uint32(len(buf)), &n, nil); err != nil {
		return nil, fmt.Errorf("DeviceIoControl %#08x: %w", code, err)
	}
	return buf[:n], nil
}

// QueryProperty runs IOCTL_STORAGE_QUERY_PROPERTY for a standard property.
func QueryProperty(h windows.Handle, id uint32) ([]byte, error) {
	return IOCTL(h, IOCTLStorageQueryProperty, PropertyQuery(id), 1024)
}

// Volumes lists volume GUID paths (\\?\Volume{…}\).
func Volumes() ([]string, error) {
	buf := make([]uint16, windows.MAX_PATH+1)
	h, err := windows.FindFirstVolume(&buf[0], uint32(len(buf)))
	if err != nil {
		return nil, fmt.Errorf("FindFirstVolume: %w", err)
	}
	defer windows.FindVolumeClose(h)
	var out []string
	for {
		out = append(out, windows.UTF16ToString(buf))
		if err := windows.FindNextVolume(h, &buf[0], uint32(len(buf))); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				return out, nil
			}
			return nil, fmt.Errorf("FindNextVolume: %w", err)
		}
	}
}

// MountPoints lists a volume's drive letters and folder mount points.
func MountPoints(volume string) ([]string, error) {
	v, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return nil, err
	}
	buf := make([]uint16, 1024)
	var n uint32
	for {
		err = windows.GetVolumePathNamesForVolumeName(v, &buf[0], uint32(len(buf)), &n)
		if errors.Is(err, windows.ERROR_MORE_DATA) && len(buf) < 1<<16 {
			buf = make([]uint16, n)
			continue
		}
		if err != nil {
			return nil, err
		}
		break
	}
	var out []string
	for i := 0; i < len(buf) && buf[i] != 0; {
		s := windows.UTF16ToString(buf[i:])
		out = append(out, s)
		i += len(s) + 1
	}
	return out, nil
}

// VolumeOf returns the volume GUID path that holds path.
func VolumeOf(path string) (string, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	mount := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumePathName(p, &mount[0], uint32(len(mount))); err != nil {
		return "", fmt.Errorf("GetVolumePathName %s: %w", path, err)
	}
	vol := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumeNameForVolumeMountPoint(&mount[0], &vol[0], uint32(len(vol))); err != nil {
		return "", fmt.Errorf("GetVolumeNameForVolumeMountPoint %s: %w", windows.UTF16ToString(mount), err)
	}
	return windows.UTF16ToString(vol), nil
}

// VolumeExtents returns the raw VOLUME_DISK_EXTENTS of a volume GUID path.
func VolumeExtents(volume string) ([]byte, error) {
	// CreateFile wants the volume without its trailing backslash.
	name := volume
	if n := len(name); n > 0 && name[n-1] == '\\' {
		name = name[:n-1]
	}
	h, err := Open(name, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	return IOCTL(h, IOCTLVolumeGetVolumeDiskExtent, nil, int(unsafe.Sizeof(uint64(0)))+24*4)
}
