// Package nvmefake is a simulated NVMe controller for tests. It starts from recorded
// Identify Controller and Identify Namespace data (internal/nvme/testdata: the lab's
// QEMU drive), rewrites the capability fields from Options, and implements Identify,
// the Sanitize Status log, Format NVM and Sanitize with a state machine and sector
// storage. QEMU emulates no Sanitize at all (design/LAB_CAPABILITIES.md), so results
// proven only here are labelled pending-real-hardware.
package nvmefake

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"shunya/internal/backend"
	"shunya/internal/nvme"
)

// Options configures a controller.
type Options struct {
	Blocks     uint64 // namespace 1 size in logical blocks
	BlockBytes int    // 512 (LBA format 0) or 4096 (format 4)
	// Capabilities.
	SanitizeCrypto, SanitizeBlock, SanitizeOverwrite bool
	NoFormat                                         bool // OACS bit 1 clear
	FNA                                              uint8
	// CryptoLies: Format with SES=2 succeeds even without FNA bit 2 (QEMU does this).
	CryptoLies bool
	// ExtraNamespaces adds active namespaces 2..n+1.
	ExtraNamespaces int
	MultiController bool // CMIC bit 1
	DeallocRead     int  // DLFEAT bits 2:0 (QEMU: 1, zeros)
	// SanitizePolls: Sanitize Status reads until the sanitize completes (default 2).
	SanitizePolls int
	SanitizeFails bool
	// NoSanitizeLog: the log page is refused with Invalid Field (as QEMU does).
	NoSanitizeLog bool
	// FormatResizes: a buggy controller comes back from Format NVM with a smaller namespace.
	FormatResizes bool
}

// Controller is the simulated controller with one namespace of storage.
type Controller struct {
	mu        sync.Mutex
	o         Options
	ctrl, ns1 []byte

	data   map[uint64][]byte
	filled []fill

	sanStatus  int // nvme.Sanitize*
	sanLeft    int
	sanCDW10   uint32
	sanProg    uint16
	gde        bool // global data erased
	pendingFil byte

	// Log lists every command (by name).
	Log []string
	// Before runs before each command; an error fails it at the transport (power loss).
	Before func(opcode uint8) error
	// Formats and Sanitizes count accepted erase commands.
	Formats, Sanitizes int
}

type fill struct{ b byte }

// New builds a controller from recorded Identify Controller and Namespace data.
func New(idCtrl, idNS []byte, o Options) (*Controller, error) {
	if len(idCtrl) != nvme.IdentifyBytes || len(idNS) != nvme.IdentifyBytes {
		return nil, errors.New("nvmefake: Identify templates must be 4096 bytes")
	}
	if o.Blocks == 0 {
		return nil, errors.New("nvmefake: Blocks required")
	}
	if o.BlockBytes == 0 {
		o.BlockBytes = 512
	}
	if o.BlockBytes != 512 && o.BlockBytes != 4096 {
		return nil, errors.New("nvmefake: BlockBytes 512 or 4096")
	}
	if o.SanitizePolls == 0 {
		o.SanitizePolls = 2
	}
	c := &Controller{o: o, ctrl: bytes.Clone(idCtrl), ns1: bytes.Clone(idNS), data: map[uint64][]byte{}}
	b := c.ctrl
	var oacs uint16 = binary.LittleEndian.Uint16(b[256:])
	oacs |= 2
	if o.NoFormat {
		oacs &^= 2
	}
	binary.LittleEndian.PutUint16(b[256:], oacs)
	var san uint32
	if o.SanitizeCrypto {
		san |= 1
	}
	if o.SanitizeBlock {
		san |= 2
	}
	if o.SanitizeOverwrite {
		san |= 4
	}
	binary.LittleEndian.PutUint32(b[328:], san)
	b[524] = o.FNA
	if o.MultiController {
		b[76] |= 2
	}
	n := c.ns1
	binary.LittleEndian.PutUint64(n[0:], o.Blocks)
	binary.LittleEndian.PutUint64(n[8:], o.Blocks)
	binary.LittleEndian.PutUint64(n[16:], o.Blocks)
	n[26] = 0 // LBA format 0 (512 B) …
	if o.BlockBytes == 4096 {
		n[26] = 4 // … or 4 (4 KiB), as in the QEMU template
	}
	n[33] = byte(o.DeallocRead & 7)
	return c, nil
}

// OldBlock is what a block holds before anything wrote it: "OLD!" and the LBA.
func OldBlock(lba uint64, size int) []byte {
	b := make([]byte, size)
	for i := 0; i < size; i += 16 {
		copy(b[i:], "OLD!nvme")
		binary.BigEndian.PutUint64(b[i+8:], lba)
	}
	return b
}

// Block returns the current contents of a block of namespace 1.
func (c *Controller) Block(lba uint64) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.block(lba)
}

func (c *Controller) block(lba uint64) []byte {
	if b, ok := c.data[lba]; ok {
		return bytes.Clone(b)
	}
	if len(c.filled) > 0 {
		return bytes.Repeat([]byte{c.filled[len(c.filled)-1].b}, c.o.BlockBytes)
	}
	return OldBlock(lba, c.o.BlockBytes)
}

// PowerCycle: a sanitize in progress continues after power-on (the controller resumes
// it), so nothing changes but the polls already counted.
func (c *Controller) PowerCycle() {}

// SanitizeState reports the log status (nvme.Sanitize*) and Global Data Erased.
func (c *Controller) SanitizeState() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sanStatus, c.gde
}

const (
	scInvalidOpcode = 0x001
	scInvalidField  = 0x002
	scInvalidNS     = 0x00b
	scSanFailed     = 0x01c
	scSanInProgress = 0x01d
	dnr             = 0x4000
)

var _ nvme.Transport = (*Controller)(nil)

// AdminCommand implements nvme.Transport.
func (c *Controller) AdminCommand(ctx context.Context, a nvme.AdminCmd, data []byte) (uint32, nvme.Status, error) {
	if len(data) != int(a.DataLen) || a.Addr != 0 || a.Metadata != 0 || a.MetadataLen != 0 {
		return 0, 0, fmt.Errorf("nvmefake: bad command buffer (data %d, DataLen %d)", len(data), a.DataLen)
	}
	if a.TimeoutMS == 0 {
		return 0, 0, errors.New("nvmefake: no timeout")
	}
	if c.Before != nil {
		if err := c.Before(a.Opcode); err != nil {
			return 0, 0, err
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.exec(a, data)
	return 0, nvme.Status(st), nil
}

func (c *Controller) exec(a nvme.AdminCmd, data []byte) uint16 {
	name := fmt.Sprintf("op %02X", a.Opcode)
	defer func() { c.Log = append(c.Log, name) }()
	switch a.Opcode {
	case nvme.OpIdentify:
		name = fmt.Sprintf("IDENTIFY CNS %d", a.CDW10&0xff)
		if len(data) != nvme.IdentifyBytes {
			return scInvalidField | dnr
		}
		clear(data)
		switch a.CDW10 & 0xff {
		case nvme.CNSController:
			copy(data, c.ctrl)
		case nvme.CNSNamespace:
			if a.NSID == 1 {
				copy(data, c.ns1)
			} else if a.NSID >= 2 && int(a.NSID) <= 1+c.o.ExtraNamespaces {
				copy(data, c.ns1)
			} else {
				return scInvalidNS | dnr
			}
		case nvme.CNSActiveNamespace:
			for i := 0; i <= c.o.ExtraNamespaces; i++ {
				binary.LittleEndian.PutUint32(data[4*i:], uint32(i+1))
			}
		default:
			return scInvalidField | dnr
		}
		return 0
	case nvme.OpGetLogPage:
		name = fmt.Sprintf("GET LOG PAGE %02X", a.CDW10&0xff)
		if a.CDW10&0xff != nvme.LogSanitize || c.o.NoSanitizeLog || len(data) != nvme.SanitizeLogBytes {
			return scInvalidField | dnr
		}
		if c.sanStatus == nvme.SanitizeInProgress {
			if c.sanLeft--; c.sanLeft <= 0 {
				c.finishSanitize()
			} else {
				c.sanProg += 0x4000
			}
		}
		clear(data)
		binary.LittleEndian.PutUint16(data[0:], c.sanProg)
		ss := uint16(c.sanStatus)
		if c.gde {
			ss |= 1 << 8
		}
		binary.LittleEndian.PutUint16(data[2:], ss)
		binary.LittleEndian.PutUint32(data[4:], c.sanCDW10)
		for o := 8; o < 20; o += 4 {
			binary.LittleEndian.PutUint32(data[o:], 0xffffffff)
		}
		return 0
	case nvme.OpFormatNVM:
		ses := int(a.CDW10 >> 9 & 7)
		name = fmt.Sprintf("FORMAT NVM SES=%d", ses)
		switch {
		case c.o.NoFormat:
			return scInvalidOpcode | dnr
		case c.sanStatus == nvme.SanitizeInProgress:
			return scSanInProgress | dnr
		case a.NSID != 1:
			return scInvalidNS | dnr
		case ses == nvme.SESCryptoErs && c.o.FNA&4 == 0 && !c.o.CryptoLies, ses > 2:
			return scInvalidField | dnr
		}
		lbaf := int(a.CDW10&0xf) | int(a.CDW10>>12&3)<<4
		cur := int(c.ns1[26] & 0xf)
		if lbaf != cur {
			name += " (LBA format change: refused by the simulator)"
			return scInvalidField | dnr
		}
		c.Formats++
		c.erase(0x00) // user-data and crypto erase both read back as zeros here
		if c.o.FormatResizes {
			for _, o := range []int{0, 8, 16} {
				binary.LittleEndian.PutUint64(c.ns1[o:], c.o.Blocks/2)
			}
		}
		return 0
	case nvme.OpSanitize:
		act := int(a.CDW10 & 7)
		name = fmt.Sprintf("SANITIZE SANACT=%d", act)
		ok := map[int]bool{nvme.SanactCryptoErase: c.o.SanitizeCrypto, nvme.SanactBlockErase: c.o.SanitizeBlock, nvme.SanactOverwrite: c.o.SanitizeOverwrite}[act]
		switch {
		case c.sanStatus == nvme.SanitizeInProgress:
			return scSanInProgress | dnr
		case !ok:
			return scInvalidField | dnr
		case a.CDW10&(1<<9) != 0: // no-deallocate
			return scInvalidField | dnr
		}
		c.Sanitizes++
		c.sanStatus, c.sanLeft, c.sanCDW10, c.sanProg, c.gde = nvme.SanitizeInProgress, c.o.SanitizePolls, a.CDW10, 0, false
		c.pendingFil = map[int]byte{nvme.SanactCryptoErase: 0x00, nvme.SanactBlockErase: 0x00, nvme.SanactOverwrite: byte(a.CDW11)}[act]
		return 0
	}
	return scInvalidOpcode | dnr
}

func (c *Controller) erase(b byte) {
	clear(c.data)
	c.filled = append(c.filled, fill{b: b})
}

func (c *Controller) finishSanitize() {
	c.sanProg = 0xffff
	if c.o.SanitizeFails {
		c.sanStatus = nvme.SanitizeFailed
		return
	}
	c.erase(c.pendingFil)
	c.sanStatus, c.gde = nvme.SanitizeCompleted, true
}

// Visible is the namespace block device /dev/nvme0n1 over the same storage.
type Visible struct {
	c       *Controller
	id      backend.Identity
	execute bool
}

var _ backend.Target = (*Visible)(nil)

// Visible returns namespace 1 as a block target.
func (c *Controller) Visible(id backend.Identity, execute bool) *Visible {
	id.SizeBytes = c.o.Blocks * uint64(c.o.BlockBytes)
	return &Visible{c: c, id: id, execute: execute}
}

func (v *Visible) Size() int64                { return int64(v.c.o.Blocks) * int64(v.c.o.BlockBytes) }
func (v *Visible) SectorSize() int            { return v.c.o.BlockBytes }
func (v *Visible) PhysicalSectorSize() int    { return v.c.o.BlockBytes }
func (v *Visible) Identity() backend.Identity { return v.id }
func (v *Visible) Sync() error                { return nil }
func (v *Visible) Close() error               { return nil }

func (v *Visible) rw(p []byte, off int64, write bool) (int, error) {
	bs := int64(v.c.o.BlockBytes)
	if off < 0 || off%bs != 0 || int64(len(p))%bs != 0 || off+int64(len(p)) > v.Size() {
		return 0, backend.ErrOutOfRange
	}
	if write && !v.execute {
		return 0, backend.ErrDryRun
	}
	v.c.mu.Lock()
	defer v.c.mu.Unlock()
	if v.c.sanStatus == nvme.SanitizeInProgress {
		return 0, errors.New("nvmefake: I/O error (Sanitize In Progress)")
	}
	for i := int64(0); i < int64(len(p)); i += bs {
		lba := uint64((off + i) / bs)
		if write {
			v.c.data[lba] = bytes.Clone(p[i : i+bs])
			v.c.gde = false // user data written since the sanitize
		} else {
			copy(p[i:], v.c.block(lba))
		}
	}
	return len(p), nil
}

func (v *Visible) ReadAt(p []byte, off int64) (int, error)  { return v.rw(p, off, false) }
func (v *Visible) WriteAt(p []byte, off int64) (int, error) { return v.rw(p, off, true) }
