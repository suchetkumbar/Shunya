package backend

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"

	"shunya/internal/nvme"
)

// nvmeIoctlAdminCmd is NVME_IOCTL_ADMIN_CMD = _IOWR('N', 0x41, struct nvme_admin_cmd).
const nvmeIoctlAdminCmd = 0xc0484e41

// The ioctl struct must be exactly struct nvme_passthru_cmd (72 bytes).
var _ [72]byte = [unsafe.Sizeof(nvme.AdminCmd{})]byte{}

// sysNVMeAdmin issues one admin command. The ioctl returns 0, a positive NVMe status,
// or -1 with errno.
func sysNVMeAdmin(f *os.File, c nvme.AdminCmd, data []byte) (uint32, nvme.Status, error) {
	if len(data) > 0 {
		c.Addr = uint64(uintptr(unsafe.Pointer(&data[0])))
	}
	r, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), nvmeIoctlAdminCmd, uintptr(unsafe.Pointer(&c)))
	runtime.KeepAlive(data)
	if errno != 0 {
		return 0, 0, fmt.Errorf("NVME_IOCTL_ADMIN_CMD: %w", errno)
	}
	return c.Result, nvme.Status(r), nil
}
