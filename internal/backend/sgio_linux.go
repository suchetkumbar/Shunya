package backend

import (
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sgIOHdr is struct sg_io_hdr from <scsi/sg.h>. Pointer fields are unsafe.Pointer so
// the layout matches the C struct on every architecture and the garbage collector
// keeps the buffers alive.
type sgIOHdr struct {
	interfaceID    int32
	dxferDirection int32
	cmdLen         uint8
	mxSbLen        uint8
	iovecCount     uint16
	dxferLen       uint32
	dxferp         unsafe.Pointer
	cmdp           unsafe.Pointer
	sbp            unsafe.Pointer
	timeout        uint32
	flags          uint32
	packID         int32
	usrPtr         unsafe.Pointer
	status         uint8
	maskedStatus   uint8
	msgStatus      uint8
	sbLenWr        uint8
	hostStatus     uint16
	driverStatus   uint16
	resid          int32
	duration       uint32
	info           uint32
}

const (
	sgIO         = 0x2285
	sgDxferNone  = -1
	sgDxferToDev = -2
	sgDxferFrom  = -3
	scsiGood     = 0x00
	scsiCheck    = 0x02
	driverSense  = 0x08
)

// sysSGIO issues one SG_IO ioctl and returns the sense data on CHECK CONDITION.
func sysSGIO(f *os.File, cdb [16]byte, dir int, data []byte, timeout time.Duration) ([]byte, error) {
	sense := make([]byte, 64)
	h := sgIOHdr{interfaceID: 'S', cmdLen: 16, mxSbLen: uint8(len(sense)),
		cmdp: unsafe.Pointer(&cdb[0]), sbp: unsafe.Pointer(&sense[0])}
	switch dir {
	case 0:
		h.dxferDirection = sgDxferNone
	case 1:
		h.dxferDirection = sgDxferFrom
	default:
		h.dxferDirection = sgDxferToDev
	}
	if len(data) > 0 {
		h.dxferp, h.dxferLen = unsafe.Pointer(&data[0]), uint32(len(data))
	}
	ms := timeout.Milliseconds()
	h.timeout = uint32(min(max(ms, 1000), 1<<32-1))
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), sgIO, uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(data)
	runtime.KeepAlive(&cdb)
	runtime.KeepAlive(sense)
	if errno != 0 {
		return nil, fmt.Errorf("SG_IO: %w", errno)
	}
	if h.hostStatus != 0 || h.driverStatus&^driverSense != 0 {
		return nil, fmt.Errorf("SG_IO: host status %#x, driver status %#x", h.hostStatus, h.driverStatus)
	}
	switch h.status &^ 1 {
	case scsiGood:
		if h.sbLenWr > 0 { // some SATLs return the ATA registers without CHECK CONDITION
			return sense[:h.sbLenWr], nil
		}
		return nil, nil
	case scsiCheck:
		return sense[:h.sbLenWr], nil
	}
	return nil, fmt.Errorf("SG_IO: SCSI status %#x", h.status)
}
