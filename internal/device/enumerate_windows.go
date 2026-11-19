//go:build windows

package device

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"shunya/internal/winstorage"
)

// maxPhysicalDrive bounds the \\.\PhysicalDriveN scan (numbers can have gaps).
const maxPhysicalDrive = 128

// EnumerateWindowsLive asks the running Windows for its disks and volumes and builds the
// report with EnumerateWindows. Every call it makes is a query: disks are opened with
// no read or write access. It has been compiled but never run (no Windows VM was
// available; the developer's own Windows machine is off limits).
func EnumerateWindowsLive() (*Report, error) {
	var disks []WinDisk
	for n := uint32(0); n < maxPhysicalDrive; n++ {
		h, err := winstorage.Open(winstorage.DiskPath(n), 0)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", winstorage.DiskPath(n), err)
		}
		w := WinDisk{Number: n}
		w.Descriptor, _ = winstorage.QueryProperty(h, winstorage.PropDevice)
		w.Alignment, _ = winstorage.QueryProperty(h, winstorage.PropAccessAlignment)
		w.SeekPenalty, _ = winstorage.QueryProperty(h, winstorage.PropSeekPenalty)
		w.Geometry, _ = winstorage.IOCTL(h, winstorage.IOCTLDiskGetDriveGeometryEx, nil, 256)
		w.Layout, _ = winstorage.IOCTL(h, winstorage.IOCTLDiskGetDriveLayoutEx, nil, 48+144*16)
		if _, err := winstorage.IOCTL(h, winstorage.IOCTLDiskIsWritable, nil, 0); errors.Is(err, windows.ERROR_WRITE_PROTECT) {
			w.ReadOnly = true
		}
		windows.CloseHandle(h)
		disks = append(disks, w)
	}

	sysVol, err := systemVolume()
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exeVol, err := winstorage.VolumeOf(exe)
	if err != nil {
		return nil, err
	}
	names, err := winstorage.Volumes()
	if err != nil {
		return nil, err
	}
	var vols []WinVolume
	for _, name := range names {
		v := WinVolume{Name: name, System: strings.EqualFold(name, sysVol), Exe: strings.EqualFold(name, exeVol)}
		v.Mounts, _ = winstorage.MountPoints(name)
		v.Extents, _ = winstorage.VolumeExtents(name)
		vols = append(vols, v)
	}
	return EnumerateWindows(windowsSystem(), disks, vols)
}

func systemVolume() (string, error) {
	dir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", fmt.Errorf("the Windows directory: %w", err)
	}
	return winstorage.VolumeOf(dir)
}

// windowsSystem reads the firmware's manufacturer and product (the DMI strings Linux
// shows in /sys/class/dmi) from the registry, read-only.
func windowsSystem() System {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		return System{}
	}
	defer k.Close()
	vendor, _, _ := k.GetStringValue("SystemManufacturer")
	product, _, _ := k.GetStringValue("SystemProductName")
	return System{DMIVendor: vendor, DMIProduct: product}
}
