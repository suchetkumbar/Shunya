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
