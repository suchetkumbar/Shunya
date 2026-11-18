package backend

import (
	"errors"
	"testing"
)

func cdb(proto byte, ext bool, b2, feat, count, cmd byte) [16]byte {
	var c [16]byte
	c[0], c[1], c[2], c[4], c[6], c[14] = 0x85, proto<<1, b2, feat, count, cmd
	if ext {
		c[1] |= 1
	}
	return c
}

const (
	nonData = 0x20 // CK_COND, no transfer
	pioIn   = 0x0e
	pioOut  = 0x06
)

// Commands that must never pass, whatever layer above asked for them.
func TestCheckATARefuses(t *testing.T) {
	block := make([]byte, 512)
	master := make([]byte, 512)
	master[0] = 1
	levelMax := make([]byte, 512)
	levelMax[1] = 1
	nvSetMax := cdb(3, true, nonData, 0, 1, 0x37)
	tests := []struct {
		name string
		cdb  [16]byte
		data []byte
	}{
		{"DCO SET", cdb(5, false, pioOut, 0xc3, 1, 0xb1), block},
		{"DCO RESTORE", cdb(3, false, nonData, 0xc0, 0, 0xb1), nil},
		{"DCO FREEZE LOCK", cdb(3, false, nonData, 0xc1, 0, 0xb1), nil},
		{"non-volatile SET MAX", nvSetMax, nil},
		{"28-bit SET MAX", cdb(3, false, nonData, 0, 0, 0xf9), nil},
		{"SECURITY FREEZE LOCK", cdb(3, false, nonData, 0, 0, 0xf5), nil},
		{"master password", cdb(5, false, pioOut, 0, 1, 0xf1), master},
		{"security level maximum", cdb(5, false, pioOut, 0, 1, 0xf1), levelMax},
		{"DOWNLOAD MICROCODE", cdb(5, false, pioOut, 7, 1, 0x92), block},
		{"SANITIZE", cdb(3, true, nonData, 0x12, 0, 0xb4), nil},
		{"WRITE SECTORS (PIO)", cdb(5, false, pioOut, 0, 1, 0x30), block},
		{"vendor specific", cdb(3, false, nonData, 0, 0, 0xff), nil},
		{"not ATA PASS-THROUGH", [16]byte{0xa1, 14: 0xec}, block},
		{"IDENTIFY as PIO out", cdb(4, false, pioOut, 0, 1, 0xec), block},
		{"IDENTIFY 2 blocks", cdb(4, false, pioIn, 0, 2, 0xec), make([]byte, 1024)},
		{"IDENTIFY short buffer", cdb(4, false, pioIn, 0, 1, 0xec), make([]byte, 100)},
		{"IDENTIFY 48-bit", cdb(4, true, pioIn, 0, 1, 0xec), block},
		{"WRITE DMA EXT wrong length", cdb(6, true, pioOut, 0, 2, 0x35), block},
		{"WRITE DMA EXT zero length", cdb(6, true, pioOut, 0, 0, 0x35), nil},
		{"READ NATIVE MAX with data", cdb(3, true, pioIn, 0, 1, 0x27), block},
		{"off-line bits", cdb(3, true, nonData|0x40, 0, 0, 0x27), nil},
	}
	hi := cdb(4, false, pioIn, 0, 1, 0xec)
	hi[7] = 1
	tests = append(tests, struct {
		name string
		cdb  [16]byte
		data []byte
	}{"28-bit with upper LBA byte", hi, block})
	for _, tc := range tests {
		if c, err := CheckATA(tc.cdb, tc.data); !errors.Is(err, ErrATARefused) {
			t.Errorf("%s: allowed as %+v", tc.name, c)
		}
	}
}

// Found by FuzzDecodeCDB: a non-data command with BYT_BLOK set is not a CDB Shunya
// builds; the backend refuses it too.
func TestCheckATAStrayTransferBits(t *testing.T) {
	for _, b2 := range []byte{nonData | 0x04, nonData | 0x08} {
		if _, err := CheckATA(cdb(3, true, b2, 0, 0, 0x27), nil); !errors.Is(err, ErrATARefused) {
			t.Errorf("byte 2 %#02x accepted", b2)
		}
	}
}

// DCO subcommands other than IDENTIFY are refused even when shaped exactly like IDENTIFY
// (PIO data-in, one block): only the feature byte differs.
func TestCheckATADCOSubcommands(t *testing.T) {
	for _, feat := range []byte{0xc0, 0xc1, 0xc3, 0x00} {
		if _, err := CheckATA(cdb(4, false, pioIn, feat, 1, 0xb1), make([]byte, 512)); !errors.Is(err, ErrATARefused) {
			t.Errorf("DCO feature %#02x accepted", feat)
		}
	}
	if _, err := CheckATA(cdb(4, false, pioIn, 0xc2, 1, 0xb1), make([]byte, 512)); err != nil {
		t.Errorf("DCO IDENTIFY refused: %v", err)
	}
}

func TestCheckATASanitize(t *testing.T) {
	mk := func(feat uint16, lba uint64, count byte) [16]byte {
		c := cdb(3, true, nonData, byte(feat), count, 0xb4)
		c[3] = byte(feat >> 8)
		c[8], c[10], c[12], c[7], c[9], c[11] = byte(lba), byte(lba>>8), byte(lba>>16), byte(lba>>24), byte(lba>>32), byte(lba>>40)
		return c
	}
	for name, tc := range map[string]struct {
		c   [16]byte
		ok  bool
		mut bool
	}{
		"status":                {mk(0, 0, 0), true, false},
		"status clear failure":  {mk(0, 0, 1), false, false},
		"crypto":                {mk(0x11, 0x43727970, 0), true, true},
		"crypto wrong key":      {mk(0x11, 0x12345678, 0), false, false},
		"block":                 {mk(0x12, 0x426b4572, 0), true, true},
		"overwrite":             {mk(0x14, 0x4f57_00000000, 1), true, true},
		"overwrite failure bit": {mk(0x14, 0x4f57_00000000, 0x11), false, false},
		"freeze lock":           {mk(0x20, 0x46724c6b, 0), false, false},
		"antifreeze":            {mk(0x40, 0x416e7469, 0), false, false},
	} {
		c, err := CheckATA(tc.c, nil)
		if (err == nil) != tc.ok || (tc.ok && c.Mutating != tc.mut) {
			t.Errorf("%s: %+v %v", name, c, err)
		}
	}
}
