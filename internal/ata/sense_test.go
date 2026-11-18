package ata

import (
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Real sense buffers.
func TestParseSenseRecorded(t *testing.T) {
	// Descriptor format, from hdparm's verbose output of IDENTIFY on an OWC Mercury
	// Extreme Pro SSD (testdata/identify/owc-mercury-extreme-pro-ssd.txt, same source):
	// "ATA_16 stat=50 err=00 nsect=01 ... dev=e0".
	owc := unhex(t, "72 00 00 00 00 00 00 0e 09 0c 00 00 00 01 00 00 00 00 00 00 e0 50 00 00 00 00 00 00 00 00 00 00")
	s, err := ParseSense(owc)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Regs; !r.HaveRegs || r.Status != 0x50 || r.Error != 0 || r.Count != 1 || r.Device != 0xe0 || r.Failed() {
		t.Errorf("owc: %+v", s)
	}
	// Fixed format, recorded in the lab (QEMU AHCI, DCO IDENTIFY, which QEMU aborts;
	// lab/results/20261117T084638Z/capabilities.txt): sense key ABORTED COMMAND,
	// error 04 (ABRT), status 41 (DRDY|ERR), device 40, count 01.
	qemu := unhex(t, "f0 00 0b 04 41 40 01 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
	s, err = ParseSense(qemu)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Regs; s.Key != SenseAborted || !r.HaveRegs || r.Status != 0x41 || r.Error != ErrorABRT || r.Device != 0x40 || r.Count != 1 || !r.Aborted() {
		t.Errorf("qemu: %+v", s)
	}
}

func TestParseSenseDescriptor48(t *testing.T) {
	// READ NATIVE MAX EXT answer for LBA 0x0000_2542_eaaf (the Samsung HD321KJ's last
	// sector), extend bit set: LBA pairs (31:24, 7:0), (39:32, 15:8), (47:40, 23:16).
	b := unhex(t, "72 01 00 1d 00 00 00 0e 09 0c 01 00 00 00 25 af 00 ea 00 42 40 50")
	s, err := ParseSense(b)
	if err != nil {
		t.Fatal(err)
	}
	if s.Regs.LBA != 0x2542eaaf || s.Key != SenseRecovered || s.ASCQ != 0x1d || s.Regs.Status != 0x50 {
		t.Errorf("%+v", s)
	}
	// Without the extend bit the upper bytes are ignored.
	b[10] = 0
	s, _ = ParseSense(b)
	if s.Regs.LBA != 0x42eaaf {
		t.Errorf("non-extended LBA %#x", s.Regs.LBA)
	}
}

func TestParseSenseNotRegisters(t *testing.T) {
	// ILLEGAL REQUEST / INVALID FIELD IN CDB, fixed format: no registers.
	b := unhex(t, "70 00 05 00 00 00 00 0a 00 00 00 00 24 00 00 00 00 00")
	s, err := ParseSense(b)
	if err != nil || s.Regs.HaveRegs || s.Key != SenseIllegalRequest || s.ASC != 0x24 {
		t.Errorf("%+v %v", s, err)
	}
	// Fixed format with the "upper LBA non-zero" flag: LBA is partial.
	b = unhex(t, "70 00 01 00 50 40 00 0a a0 ff ff ff 00 1d 00 00 00 00")
	s, _ = ParseSense(b)
	if !s.Regs.HaveRegs || !s.Regs.LBAPartial || s.Regs.LBA != 0xffffff {
		t.Errorf("%+v", s)
	}
	for _, bad := range []string{"71", "72 00", "7f 00 00 00 00 00 00 00", "72 00 00 00 00 00 00 10 09 0c 00"} {
		if _, err := ParseSense(unhex(t, bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if s, err := ParseSense(nil); err != nil || s.Regs.HaveRegs {
		t.Errorf("empty: %+v %v", s, err)
	}
}

func FuzzParseSense(f *testing.F) {
	f.Add(unhex(f, "72 00 00 00 00 00 00 0e 09 0c 00 00 00 01 00 00 00 00 00 00 e0 50"))
	f.Add(unhex(f, "f0 00 0b 04 41 40 01 0a 00 00 00 00 00 00 00 00 00 00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseSense(b)
		if err == nil && s.Regs.LBA > MaxLBA48 {
			t.Fatalf("LBA %#x beyond 48 bits", s.Regs.LBA)
		}
	})
}
