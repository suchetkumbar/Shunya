package ata

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func cdbHex(c Command) string {
	b := c.CDB()
	return hex.EncodeToString(b[:])
}

func mustCmd(c Command, err error) Command {
	if err != nil {
		panic(err)
	}
	return c
}

func mustCmdData(c Command, _ []byte, err error) Command {
	if err != nil {
		panic(err)
	}
	return c
}

// Golden CDBs. IDENTIFY matches sg_sat_identify(8) byte for byte (sg3_utils builds
// "85 08 0e 00 00 00 01 00 00 00 00 00 00 00 ec 00"); the others follow SAT-4 table 166
// with the register layout of hdparm's sgio.c (non-data commands with CK_COND, LBA mode
// device byte 0x40).
func TestGoldenCDBs(t *testing.T) {
	sm := mustCmd(SetMaxAddressExtVolatile(0x12_3456_789a))
	rd := mustCmd(ReadDMAExt(0x0000_0102_0304, 8))
	wr := mustCmd(WriteDMAExt(0x7fff_ffff_ffff, 256))
	tests := []struct {
		c    Command
		want string
	}{
		{IdentifyCmd(), "85080e00000001000000000000 00ec00"},
		{ReadNativeMaxExt(), "8507200000000000000000000040 2700"},
		{sm, "85072000000000349a12780056 403700"},
		{DCOIdentify(), "85080e00c20001000000000000 00b100"},
		{rd, "850d0e000000080104000300 02402500"},
		{wr, "850d06000001 00ffffffff7fff403500"},
		{FlushCacheExt(), "8507200000000000000000000040ea00"},
		{SecurityErasePrepare(), "8506200000000000000000000000f300"},
		{mustCmdData(SecurityEraseUnit("x", true, time.Hour)), "850a0600000001000000000000 00f400"},
		{mustCmdData(SecuritySetUserPassword("x")), "850a0600000001000000000000 00f100"},
	}
	for _, tc := range tests {
		want := strings.ReplaceAll(tc.want, " ", "")
		if got := cdbHex(tc.c); got != want {
			t.Errorf("%s:\n got %s\nwant %s", tc.c.Name, got, want)
		}
	}
	// Count 256 sectors is encoded as 0x0100 in a 48-bit command.
	if b := wr.CDB(); b[5] != 0x01 || b[6] != 0x00 {
		t.Errorf("256-sector count bytes %02x %02x", b[5], b[6])
	}
}

func TestDecodeRoundTrip(t *testing.T) {
	sm := mustCmd(SetMaxAddressExtVolatile(MaxLBA48))
	rd := mustCmd(ReadDMAExt(1<<40, 256))
	cmds := []Command{IdentifyCmd(), ReadNativeMaxExt(), sm, DCOIdentify(), rd, FlushCacheExt(), SecurityErasePrepare(),
		mustCmdData(SecurityEraseUnit("p", false, time.Hour)), mustCmdData(SecurityUnlockUser("p")),
		mustCmdData(SecurityDisableUserPassword("p"))}
	for _, c := range cmds {
		d, err := DecodeCDB(c.CDB())
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if d.TF != c.TF || d.Proto != c.Proto || d.Dir != c.Dir || d.Ext != c.Ext || d.Sectors != c.Sectors || d.CkCond != (c.Dir == DirNone) {
			t.Errorf("%s: decoded %+v from %+v", c.Name, d, c)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	good := IdentifyCmd().CDB()
	mut := func(f func(*[16]byte)) [16]byte { b := good; f(&b); return b }
	for name, b := range map[string][16]byte{
		"opcode":          mut(func(b *[16]byte) { b[0] = 0xa1 }),
		"multiple count":  mut(func(b *[16]byte) { b[1] |= 0x20 }),
		"off-line":        mut(func(b *[16]byte) { b[2] |= 0x40 }),
		"T_TYPE":          mut(func(b *[16]byte) { b[2] |= 0x10 }),
		"control":         mut(func(b *[16]byte) { b[15] = 4 }),
		"28-bit high LBA": mut(func(b *[16]byte) { b[7] = 1 }),
		"PIO-in out":      mut(func(b *[16]byte) { b[2] &^= cdb2TDirIn }),
		"bad protocol":    mut(func(b *[16]byte) { b[1] = 0x1e }),
		"no-data length":  mut(func(b *[16]byte) { b[1] = byte(ProtoNonData) << 1 }),
	} {
		if _, err := DecodeCDB(b); !errors.Is(err, ErrBadCDB) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCommandArguments(t *testing.T) {
	if _, err := SetMaxAddressExtVolatile(MaxLBA48 + 1); err == nil {
		t.Error("SET MAX beyond 48 bits accepted")
	}
	for _, n := range []int{0, -1, MaxTransferSectors + 1} {
		if _, err := WriteDMAExt(0, n); !errors.Is(err, ErrTransfer) {
			t.Errorf("WRITE %d sectors: %v", n, err)
		}
	}
	if _, err := ReadDMAExt(MaxLBA48, 2); !errors.Is(err, ErrTransfer) {
		t.Error("read past LBA 2^48 accepted")
	}
	if _, _, err := SecuritySetUserPassword(strings.Repeat("a", 33)); err == nil {
		t.Error("33-byte password accepted")
	}
	if _, _, err := SecuritySetUserPassword(""); err == nil {
		t.Error("empty password accepted")
	}
	_, data, _ := SecurityEraseUnit("abc", true, time.Hour)
	if data[0] != 2 || data[1] != 0 || string(data[2:5]) != "abc" || data[5] != 0 || len(data) != 512 {
		t.Errorf("erase unit block % x", data[:8])
	}
	_, data, _ = SecuritySetUserPassword("abc")
	if data[0] != 0 || data[1] != 0 {
		t.Errorf("set password must be user, level high: % x", data[:2])
	}
}

func FuzzDecodeCDB(f *testing.F) {
	a, b := IdentifyCmd().CDB(), ReadNativeMaxExt().CDB()
	f.Add(a[:])
	f.Add(b[:])
	f.Fuzz(func(t *testing.T, in []byte) {
		var b [16]byte
		copy(b[:], in)
		d, err := DecodeCDB(b)
		if err != nil {
			return
		}
		// Anything accepted re-encodes to the same bytes.
		c := Command{TF: d.TF, Proto: d.Proto, Dir: d.Dir, Ext: d.Ext}
		got := c.CDB()
		if d.CkCond != (d.Dir == DirNone) {
			return // CK_COND on a data command: valid SAT, not something Command builds
		}
		if got != b {
			t.Fatalf("decode/encode mismatch:\n in  % x\n out % x", b, got)
		}
	})
}
