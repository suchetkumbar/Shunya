// Package atafake is a simulated SATA drive for tests. It answers ATA PASS-THROUGH(16)
// CDBs (decoding the bytes internal/ata builds), keeps the state the ATA feature sets
// define — HPA maximum, DCO maximum, the Security state machine (ACS-3 §4.19, states
// SEC0–SEC6), the attempt counter, freeze lock — and stores sector contents, so
// HPA removal, hidden-range writes and Security Erase can be tested where QEMU emulates
// none of them (design/LAB_CAPABILITIES.md). Results proven only here are labelled
// pending-real-hardware.
//
// Its IDENTIFY data starts from a recorded dump (internal/ata/testdata/identify) with
// the capacity, feature and security words rewritten from the simulated state.
package atafake

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"shunya/internal/ata"
	"shunya/internal/backend"
)

// Options configures a drive.
type Options struct {
	Sectors       uint64 // user-addressable at power-on (with the HPA, if any)
	NativeSectors uint64 // READ NATIVE MAX + 1; default Sectors (no HPA)
	DCOSectors    uint64 // factory size; default NativeSectors (no DCO restriction)
	HPA           bool   // HPA feature set supported (default: from the template)
	DCO           bool   // DCO supported
	DCOFrozen     bool   // DCO IDENTIFY aborts (DCO FREEZE LOCK)
	Security      bool   // Security feature set supported
	Enhanced      bool   // enhanced erase supported
	FreezeOnBoot  bool   // the "BIOS" freezes security at every power-on
	// OneSetMax: a second SET MAX in one power cycle is aborted (common real behaviour).
	OneSetMax bool
	// EnhancedFill is the vendor pattern of an enhanced erase (normal erase writes 0).
	EnhancedFill byte
	// NoSAT: the bridge has no ATA pass-through; every CDB gets ILLEGAL REQUEST.
	NoSAT bool
	// FixedSense: answer with fixed-format sense, as libata does by default.
	FixedSense bool
	// EraseMinutes: IDENTIFY words 89/90 (0: not reported).
	EraseMinutes int
}

// Drive is the simulated drive.
type Drive struct {
	mu       sync.Mutex
	o        Options
	template []uint16
	checksum bool

	current      uint64 // current max (sectors)
	powerOnMax   uint64 // what current returns to at power-on
	setMaxDone   bool
	lastWasRNMA  bool
	enabled      bool
	locked       bool
	frozen       bool
	countExpired bool
	attempts     int
	prepared     bool
	password     []byte

	data   map[uint64][]byte
	erased []fill // later entries win

	// Log lists every command executed, by ATA name.
	Log []string
	// Before, if set, runs before each command; returning an error makes the command
	// fail at the transport (as if the machine lost power mid-command; call PowerCycle).
	Before func(cmd uint8) error
	// NonVolatileAttempts counts SET MAX commands with the volatile bit set (Shunya must
	// never send one; backend's allowlist should stop it before it gets here).
	NonVolatileAttempts int
}

type fill struct {
	from, to uint64
	b        byte
}

// New builds a drive from a recorded IDENTIFY dump (hdparm --Istdout text or 512 bytes).
func New(dump []byte, o Options) (*Drive, error) {
	raw := dump
	if len(dump) != 512 {
		var err error
		if raw, err = ata.ParseHdparmDump(dump); err != nil {
			return nil, err
		}
	}
	if o.Sectors == 0 {
		return nil, errors.New("atafake: Sectors required")
	}
	if o.NativeSectors == 0 {
		o.NativeSectors = o.Sectors
	}
	if o.DCOSectors == 0 {
		o.DCOSectors = o.NativeSectors
	}
	if o.NativeSectors < o.Sectors || o.DCOSectors < o.NativeSectors {
		return nil, errors.New("atafake: need Sectors <= NativeSectors <= DCOSectors")
	}
	if o.NativeSectors > o.Sectors {
		o.HPA = true
	}
	d := &Drive{o: o, template: make([]uint16, 256), current: o.Sectors, powerOnMax: o.Sectors, data: map[uint64][]byte{}}
	for i := range d.template {
		d.template[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	d.checksum = d.template[255]&0xff == 0xa5
	d.frozen = o.FreezeOnBoot
	return d, nil
}

// PowerCycle simulates power loss and power-on: a volatile SET MAX is lost, a drive
// with a password comes up locked, the "BIOS" may freeze it again.
func (d *Drive) PowerCycle() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.current = d.powerOnMax
	d.setMaxDone, d.lastWasRNMA, d.prepared = false, false, false
	d.locked = d.enabled
	d.frozen = d.o.FreezeOnBoot
	d.attempts, d.countExpired = 0, false
}

// Freeze sends SECURITY FREEZE LOCK (as a BIOS would).
func (d *Drive) Freeze() { d.mu.Lock(); d.frozen = true; d.mu.Unlock() }

// SetPassword puts a user password on the drive (someone else's, for refusal tests).
func (d *Drive) SetPassword(pw string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.password = pad(pw)
	d.enabled = true
}

// State reports (current max sectors, security enabled, locked, frozen).
func (d *Drive) State() (current uint64, enabled, locked, frozen bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.current, d.enabled, d.locked, d.frozen
}

// OldSector is the content a sector holds before anything wrote it: "OLD!" and the
// LBA, repeated, so a test can see whether a sector was overwritten.
func OldSector(lba uint64) []byte {
	b := make([]byte, ata.SectorBytes)
	for i := 0; i < len(b); i += 16 {
		copy(b[i:], "OLD!data")
		binary.BigEndian.PutUint64(b[i+8:], lba)
	}
	return b
}

// Sector returns the current contents of a sector.
func (d *Drive) Sector(lba uint64) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sector(lba)
}

func (d *Drive) sector(lba uint64) []byte {
	if b, ok := d.data[lba]; ok {
		return bytes.Clone(b)
	}
	for i := len(d.erased) - 1; i >= 0; i-- {
		if f := d.erased[i]; lba >= f.from && lba < f.to {
			return bytes.Repeat([]byte{f.b}, ata.SectorBytes)
		}
	}
	return OldSector(lba)
}

func (d *Drive) write(lba uint64, b []byte) {
	d.data[lba] = bytes.Clone(b)
}

func pad(pw string) []byte {
	b := make([]byte, ata.PasswordBytes)
	copy(b, pw)
	return b
}

// identify builds IDENTIFY data from the template and the current state.
func (d *Drive) identify() []byte {
	w := append([]uint16(nil), d.template...)
	set := func(i int, bit uint, on bool) {
		if on {
			w[i] |= 1 << bit
		} else {
			w[i] &^= 1 << bit
		}
	}
	w[83] = w[83]&^0xc000 | 0x4000
	w[86] = w[86]&^0xc000 | 0x4000
	set(83, 10, true) // 48-bit
	set(86, 10, true)
	set(82, 10, d.o.HPA)
	set(85, 10, d.o.HPA)
	set(83, 11, d.o.DCO)
	set(86, 11, d.o.DCO)
	set(82, 1, d.o.Security)
	set(85, 1, d.enabled)
	lba28 := min(d.current, 0x0fffffff)
	w[60], w[61] = uint16(lba28), uint16(lba28>>16)
	for i := range 4 {
		w[100+i] = uint16(d.current >> (16 * i))
	}
	w[106] = 0x4000 // 512-byte logical and physical sectors
	var s uint16
	if d.o.Security {
		s |= 1
		if d.enabled {
			s |= 1 << 1
		}
		if d.locked {
			s |= 1 << 2
		}
		if d.frozen {
			s |= 1 << 3
		}
		if d.countExpired {
			s |= 1 << 4
		}
		if d.o.Enhanced {
			s |= 1 << 5
		}
	}
	w[128] = s
	em := uint16(min(d.o.EraseMinutes/2, 254))
	w[89], w[90] = em, em
	b := make([]byte, 512)
	for i, x := range w {
		binary.LittleEndian.PutUint16(b[2*i:], x)
	}
	if d.checksum {
		b[510] = 0xa5
		var sum byte
		for _, c := range b[:511] {
			sum += c
		}
		b[511] = -sum
	}
	return b
}

func (d *Drive) dcoData() []byte {
	b := make([]byte, 512)
	binary.LittleEndian.PutUint16(b[0:], 2)
	max := d.o.DCOSectors - 1
	for i := range 4 {
		binary.LittleEndian.PutUint16(b[2*(3+i):], uint16(max>>(16*i)))
	}
	b[510] = 0xa5
	var sum byte
	for _, c := range b[:511] {
		sum += c
	}
	b[511] = -sum
	return b
}

// regs is the outcome of one command.
type regs struct {
	status, err uint8
	lba         uint64
}

var ok = regs{status: ata.StatusDRDY}

func abort() regs { return regs{status: ata.StatusDRDY | ata.StatusERR, err: ata.ErrorABRT} }
func idnf() regs  { return regs{status: ata.StatusDRDY | ata.StatusERR, err: ata.ErrorIDNF} }

var _ ata.Transport = (*Drive)(nil)

// PassThrough implements ata.Transport.
func (d *Drive) PassThrough(ctx context.Context, cdb [16]byte, data []byte, timeout time.Duration) ([]byte, error) {
	if d.o.NoSAT {
		return illegalRequest(), nil
	}
	dc, err := ata.DecodeCDB(cdb)
	if err != nil {
		return illegalRequest(), nil
	}
	if len(data) != dc.Sectors*ata.SectorBytes {
		return nil, fmt.Errorf("atafake: CDB says %s %d sectors, caller passed %d bytes", dc.Dir, dc.Sectors, len(data))
	}
	if timeout <= 0 {
		return nil, errors.New("atafake: no timeout")
	}
	if d.Before != nil {
		if err := d.Before(dc.TF.Command); err != nil {
			return nil, err
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.exec(dc, data)
	if dc.TF.Command != ata.CmdReadNativeMaxExt {
		d.lastWasRNMA = false
	}
	if r.status&ata.StatusERR == 0 && !dc.CkCond {
		return nil, nil
	}
	return d.sense(r, dc.Ext), nil
}

func (d *Drive) exec(dc ata.Decoded, data []byte) regs {
	tf := dc.TF
	name := fmt.Sprintf("%02X", tf.Command)
	defer func() { d.Log = append(d.Log, name) }()
	lockedOK := func() bool { return !d.locked }
	switch tf.Command {
	case ata.CmdIdentifyDevice:
		name = "IDENTIFY"
		copy(data, d.identify())
		return ok
	case ata.CmdReadNativeMaxExt:
		name = "READ NATIVE MAX EXT"
		if !d.o.HPA || !dc.Ext {
			return abort()
		}
		d.lastWasRNMA = true
		return regs{status: ata.StatusDRDY, lba: d.o.NativeSectors - 1}
	case ata.CmdSetMaxAddressExt:
		name = "SET MAX EXT"
		if tf.Count&1 != 0 {
			d.NonVolatileAttempts++
			name += " (NON-VOLATILE)"
		}
		switch {
		case !d.o.HPA, !d.lastWasRNMA, !lockedOK(), d.o.OneSetMax && d.setMaxDone:
			return abort()
		case tf.LBA+1 > d.o.NativeSectors:
			return idnf()
		}
		d.current = tf.LBA + 1
		if tf.Count&1 != 0 {
			d.powerOnMax = d.current
		}
		d.setMaxDone = true
		return ok
	case ata.CmdDeviceConfiguration:
		name = fmt.Sprintf("DCO %02X", tf.Feature)
		if tf.Feature != ata.FeatureDCOIdentify || !d.o.DCO || d.o.DCOFrozen {
			return abort()
		}
		copy(data, d.dcoData())
		return ok
	case ata.CmdReadDMAExt, ata.CmdWriteDMAExt:
		write := tf.Command == ata.CmdWriteDMAExt
		name = "READ DMA EXT"
		if write {
			name = "WRITE DMA EXT"
		}
		if !lockedOK() {
			return abort()
		}
		if tf.LBA+uint64(dc.Sectors) > d.current {
			return idnf()
		}
		for i := range dc.Sectors {
			s := data[i*ata.SectorBytes : (i+1)*ata.SectorBytes]
			if write {
				d.write(tf.LBA+uint64(i), s)
			} else {
				copy(s, d.sector(tf.LBA+uint64(i)))
			}
		}
		return ok
	case ata.CmdFlushCacheExt:
		name = "FLUSH CACHE EXT"
		return ok
	case ata.CmdSecuritySetPassword:
		name = "SECURITY SET PASSWORD"
		if !d.o.Security || d.frozen || d.locked {
			return abort()
		}
		if data[0]&1 != 0 || data[1]&1 != 0 {
			name += " (master/maximum: refused by the simulator)"
			return abort()
		}
		d.password = bytes.Clone(data[2 : 2+ata.PasswordBytes])
		d.enabled = true
		return ok
	case ata.CmdSecurityUnlock:
		name = "SECURITY UNLOCK"
		if !d.o.Security || d.frozen || d.countExpired {
			return abort()
		}
		if !d.enabled {
			return ok
		}
		if !d.checkPW(data) {
			return abort()
		}
		d.locked = false
		return ok
	case ata.CmdSecurityErasePrep:
		name = "SECURITY ERASE PREPARE"
		if !d.o.Security || d.frozen {
			return abort()
		}
		d.prepared = true
		return ok
	case ata.CmdSecurityEraseUnit:
		name = "SECURITY ERASE UNIT"
		prepared := d.prepared
		d.prepared = false
		enhanced := data[0]&2 != 0
		switch {
		case !d.o.Security || d.frozen || !prepared || d.countExpired:
			return abort()
		case enhanced && !d.o.Enhanced:
			return abort()
		case d.enabled && !d.checkPW(data):
			return abort()
		}
		f := fill{from: 0, to: d.current}
		if enhanced {
			f.b = d.o.EnhancedFill
			name += " (enhanced)"
		}
		// Real drives differ on whether the erase reaches beyond the current max;
		// the simulator takes the worst case: only [0, current max) is erased.
		for lba := range d.data {
			if lba < f.to {
				delete(d.data, lba)
			}
		}
		d.erased = append(d.erased, f)
		d.enabled, d.locked, d.password = false, false, nil
		return ok
	case ata.CmdSecurityDisablePass:
		name = "SECURITY DISABLE PASSWORD"
		if !d.o.Security || d.frozen || d.locked {
			return abort()
		}
		if !d.enabled {
			return ok
		}
		if !d.checkPW(data) {
			return abort()
		}
		d.enabled, d.password = false, nil
		return ok
	}
	return abort()
}

func (d *Drive) checkPW(data []byte) bool {
	if bytes.Equal(data[2:2+ata.PasswordBytes], d.password) {
		return true
	}
	d.attempts++
	if d.attempts >= 5 {
		d.countExpired = true
	}
	return false
}

func illegalRequest() []byte {
	// Descriptor sense: ILLEGAL REQUEST, INVALID COMMAND OPERATION CODE (20/00).
	return []byte{0x72, ata.SenseIllegalRequest, 0x20, 0x00, 0, 0, 0, 0}
}

func (d *Drive) sense(r regs, ext bool) []byte {
	key := byte(ata.SenseRecovered)
	asc, ascq := byte(0), byte(0x1d)
	if r.status&ata.StatusERR != 0 {
		key, ascq = ata.SenseAborted, 0
	}
	if d.o.FixedSense {
		b := make([]byte, 18)
		b[0], b[2], b[7] = 0xf0, key, 10
		b[3], b[4], b[5], b[6] = r.err, r.status, 0x40, 0
		if ext {
			b[8] |= 0x80
		}
		if r.lba>>24 != 0 {
			b[8] |= 0x20
		}
		b[9], b[10], b[11] = byte(r.lba), byte(r.lba>>8), byte(r.lba>>16)
		b[12], b[13] = asc, ascq
		return b
	}
	b := []byte{0x72, key, asc, ascq, 0, 0, 0, 14,
		0x09, 0x0c, 0, r.err, 0, 0,
		byte(r.lba >> 24), byte(r.lba), byte(r.lba >> 32), byte(r.lba >> 8), byte(r.lba >> 40), byte(r.lba >> 16),
		0x40, r.status}
	if ext {
		b[10] = 1
	}
	return b
}

// Visible is the kernel's block device view of the drive: the size it had at power-on
// (the kernel does not rescan after SET MAX), read and written through the same storage.
type Visible struct {
	d       *Drive
	sectors uint64
	id      backend.Identity
	execute bool
}

var _ backend.Target = (*Visible)(nil)

// Visible returns the block-device view: the size the drive had at power-on, which the
// kernel keeps after a SET MAX (it does not rescan).
func (d *Drive) Visible(id backend.Identity, execute bool) *Visible {
	d.mu.Lock()
	cur := d.powerOnMax
	d.mu.Unlock()
	id.SizeBytes = cur * ata.SectorBytes
	return &Visible{d: d, sectors: cur, id: id, execute: execute}
}

func (v *Visible) Size() int64                { return int64(v.sectors) * ata.SectorBytes }
func (v *Visible) SectorSize() int            { return ata.SectorBytes }
func (v *Visible) PhysicalSectorSize() int    { return ata.SectorBytes }
func (v *Visible) Identity() backend.Identity { return v.id }
func (v *Visible) Sync() error                { return nil }
func (v *Visible) Close() error               { return nil }

func (v *Visible) rw(p []byte, off int64, write bool) (int, error) {
	if off < 0 || off%ata.SectorBytes != 0 || len(p)%ata.SectorBytes != 0 || off+int64(len(p)) > v.Size() {
		return 0, backend.ErrOutOfRange
	}
	if write && !v.execute {
		return 0, backend.ErrDryRun
	}
	v.d.mu.Lock()
	defer v.d.mu.Unlock()
	if v.d.locked {
		return 0, errors.New("atafake: I/O error (drive locked)")
	}
	for i := 0; i < len(p); i += ata.SectorBytes {
		lba := uint64(off)/ata.SectorBytes + uint64(i/ata.SectorBytes)
		if write {
			v.d.write(lba, p[i:i+ata.SectorBytes])
		} else {
			copy(p[i:], v.d.sector(lba))
		}
	}
	return len(p), nil
}

func (v *Visible) ReadAt(p []byte, off int64) (int, error)  { return v.rw(p, off, false) }
func (v *Visible) WriteAt(p []byte, off int64) (int, error) { return v.rw(p, off, true) }
