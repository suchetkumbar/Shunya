package ata

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func loadDump(t testing.TB, name string) []byte {
	t.Helper()
	txt, err := os.ReadFile(filepath.Join("testdata", "identify", name))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseHdparmDump(txt)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

// Real-world IDENTIFY dumps (sources in testdata/identify/SOURCES.md). Expected values
// marked "oracle" come from the tool output published next to the dump (hdparm -I or
// hdparm -i on the same drive), not from this parser; the rest were checked by hand
// against the raw words.
func TestParseIdentifyRealDumps(t *testing.T) {
	tests := []struct {
		file                    string
		model, serial, firmware string // oracle
		sectors                 uint64 // oracle where noted
		lba28                   uint64
		wwn                     string
		hpa, dco, sec, enh      bool
		frozen                  bool
		normalMin, enhancedMin  int
		solid                   bool
		trim                    bool
	}{
		{
			// hdparm -I in the source: model, serial, firmware, "supported, not enabled,
			// not locked, not frozen, not expired, supported: enhanced erase, 112min for
			// SECURITY ERASE UNIT. 112min for ENHANCED SECURITY ERASE UNIT."
			file: "samsung-hd321kj.txt", model: "SAMSUNG HD321KJ", serial: "S0ZEJ1NP601353", firmware: "CP100-11",
			sectors: 625142448, lba28: 268435455, wwn: "50000f000b0e0100",
			hpa: true, dco: true, sec: true, enh: true, normalMin: 112, enhancedMin: 112,
		},
		{
			// hdparm -i in the source: Model=OWC Mercury Extreme Pro SSD, FwRev=340A13F0,
			// SerialNo=MXE24010E45A7581, LBAsects=468862128.
			file: "owc-mercury-extreme-pro-ssd.txt", model: "OWC Mercury Extreme Pro SSD", serial: "MXE24010E45A7581", firmware: "340A13F0",
			sectors: 468862128, lba28: 268435455,
			wwn: "5000000000007581",
			hpa: true, dco: false, sec: true, enh: false, normalMin: 400, enhancedMin: 400, solid: true, trim: true,
		},
		{
			// Model "INTEL SSDSA2CT040G3" is quoted in the bug report (hdparm -I).
			file: "intel-ssdsa2ct040g3.txt", model: "INTEL SSDSA2CT040G3", serial: "CVPR1254021V040AGN", firmware: "4PC10302",
			sectors: 78165360, lba28: 78165360, wwn: "50015179595af88f",
			// Frozen: this machine's BIOS had sent SECURITY FREEZE LOCK (word 128 bit 3).
			hpa: true, dco: true, sec: true, enh: true, frozen: true, normalMin: 2, enhancedMin: 2, solid: true, trim: true,
		},
		{
			// A RAID volume presented by an external enclosure: no Security, no HPA.
			file: "sil-external-raid.txt", model: "External Disk 0", // The serial matches the one quoted in the thread, underscores included.
			serial: "070C05F_879391___0_8", firmware: "RGL10403",
			sectors: 1953546336, lba28: 268435455, sec: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			id, err := ParseIdentify(loadDump(t, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if id.Model != tc.model || id.Serial != tc.serial || id.Firmware != tc.firmware {
				t.Errorf("strings: %q %q %q", id.Model, id.Serial, id.Firmware)
			}
			if id.Sectors() != tc.sectors || id.LBA28Sectors != tc.lba28 || !id.Supports48 {
				t.Errorf("capacity: %d sectors, lba28 %d, 48-bit %v", id.Sectors(), id.LBA28Sectors, id.Supports48)
			}
			if id.WWN != tc.wwn {
				t.Errorf("wwn %q", id.WWN)
			}
			if id.HPASupported != tc.hpa || id.DCOSupported != tc.dco {
				t.Errorf("hpa %v dco %v", id.HPASupported, id.DCOSupported)
			}
			s := id.Security
			if s.Supported != tc.sec || s.EnhancedSupported != tc.enh || s.Enabled || s.Locked || s.Frozen != tc.frozen || s.CountExpired {
				t.Errorf("security %+v", s)
			}
			if s.NormalEraseMinutes != tc.normalMin || s.EnhancedEraseMinutes != tc.enhancedMin {
				t.Errorf("erase minutes %d/%d", s.NormalEraseMinutes, s.EnhancedEraseMinutes)
			}
			if id.SolidState() != tc.solid || id.TRIM != tc.trim {
				t.Errorf("rpm %d trim %v", id.RotationRPM, id.TRIM)
			}
			if id.Checksum != "valid" || id.LogicalSectorBytes != 512 {
				t.Errorf("checksum %s logical %d physical %d", id.Checksum, id.LogicalSectorBytes, id.PhysicalSectorBytes)
			}
			// Round trip through the hdparm text form.
			raw := loadDump(t, tc.file)
			again, err := ParseHdparmDump([]byte(FormatHdparmDump(raw)))
			if err != nil || string(again) != string(raw) {
				t.Errorf("hdparm format round trip: %v", err)
			}
		})
	}
}

func setWord(b []byte, i int, v uint16) { binary.LittleEndian.PutUint16(b[2*i:], v) }

func fixChecksum(b []byte) {
	b[510] = 0xa5
	var s byte
	for _, c := range b[:511] {
		s += c
	}
	b[511] = -s
}

func TestParseIdentifyChecksumAndErrors(t *testing.T) {
	raw := loadDump(t, "samsung-hd321kj.txt")
	bad := append([]byte(nil), raw...)
	bad[20] ^= 1
	if _, err := ParseIdentify(bad); !errors.Is(err, ErrIdentifyChecksum) {
		t.Errorf("flipped byte: %v", err)
	}
	if _, err := ParseIdentify(make([]byte, 512)); !errors.Is(err, ErrNotATA) {
		t.Errorf("all zeros: %v", err)
	}
	if _, err := ParseIdentify(raw[:510]); !errors.Is(err, ErrIdentifyLength) {
		t.Errorf("short: %v", err)
	}
	atapi := append([]byte(nil), raw...)
	setWord(atapi, 0, 0x85c0)
	fixChecksum(atapi)
	if _, err := ParseIdentify(atapi); !errors.Is(err, ErrNotATA) {
		t.Errorf("ATAPI: %v", err)
	}
	// No signature: checksum "absent", data still parsed.
	nosig := append([]byte(nil), raw...)
	setWord(nosig, 255, 0)
	if id, err := ParseIdentify(nosig); err != nil || id.Checksum != "absent" || id.Model != "SAMSUNG HD321KJ" {
		t.Errorf("no signature: %v", err)
	}
	// Invalid word-83 signature: feature bits are not trusted.
	inv := append([]byte(nil), raw...)
	setWord(inv, 83, 0x3f01)
	fixChecksum(inv)
	if id, err := ParseIdentify(inv); err != nil || id.Supports48 || id.HPASupported || id.Sectors() != 268435455 {
		t.Errorf("invalid word 83: %+v %v", id, err)
	}
}

func TestParseIdentifyStates(t *testing.T) {
	raw := loadDump(t, "samsung-hd321kj.txt")
	b := append([]byte(nil), raw...)
	setWord(b, 128, 0x013f) // supported, enabled, locked, frozen, expired, enhanced, level max
	setWord(b, 89, 0x80ff)  // extended format: 255 × 2 min
	setWord(b, 90, 0xffff)  // extended, maximum: "longer"
	setWord(b, 106, 0x7003) // valid; logical > 256 words; 8 logical per physical
	setWord(b, 117, 0x0800) // 2048 words = 4096 bytes
	setWord(b, 118, 0)      //
	setWord(b, 217, 7200)   // 7200 rpm
	setWord(b, 59, 0xf000)  // sanitize: all three
	fixChecksum(b)
	id, err := ParseIdentify(b)
	if err != nil {
		t.Fatal(err)
	}
	s := id.Security
	if !(s.Supported && s.Enabled && s.Locked && s.Frozen && s.CountExpired && s.EnhancedSupported && s.LevelMaximum) {
		t.Errorf("security %+v", s)
	}
	if s.NormalEraseMinutes != 510 || s.EnhancedEraseMinutes != -1 {
		t.Errorf("erase minutes %d %d", s.NormalEraseMinutes, s.EnhancedEraseMinutes)
	}
	if id.LogicalSectorBytes != 4096 || id.PhysicalSectorBytes != 32768 {
		t.Errorf("sectors %d/%d", id.LogicalSectorBytes, id.PhysicalSectorBytes)
	}
	if id.RotationRPM != 7200 || id.SolidState() {
		t.Errorf("rpm %d", id.RotationRPM)
	}
	if !(id.Sanitize.Supported && id.Sanitize.CryptoScramble && id.Sanitize.Overwrite && id.Sanitize.BlockErase) {
		t.Errorf("sanitize %+v", id.Sanitize)
	}
	setWord(b, 89, 0x00ff) // short format 255: "longer than 508 min"
	fixChecksum(b)
	if id, _ := ParseIdentify(b); id.Security.NormalEraseMinutes != -1 {
		t.Errorf("short-format 255: %d", id.Security.NormalEraseMinutes)
	}
}

func TestParseHdparmDumpErrors(t *testing.T) {
	for name, s := range map[string]string{
		"short":   "0040 3fff",
		"bad hex": "zzzz",
		"5 digit": "00400",
	} {
		if _, err := ParseHdparmDump([]byte(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	raw := loadDump(t, "samsung-hd321kj.txt")
	long := FormatHdparmDump(raw) + "0000\n"
	if _, err := ParseHdparmDump([]byte(long)); err == nil {
		t.Error("257 words accepted")
	}
	// The "/dev/sdb:" header hdparm prints is skipped.
	if _, err := ParseHdparmDump([]byte("/dev/sdb:\n" + FormatHdparmDump(raw))); err != nil {
		t.Error(err)
	}
}

func TestParseDCO(t *testing.T) {
	b := make([]byte, 512)
	setWord(b, 0, 2)
	setWord(b, 3, 0xeaaf)
	setWord(b, 4, 0x2542)
	fixChecksum(b)
	d, err := ParseDCO(b)
	if err != nil || d.MaxSectors != 0x2542eab0 || d.Checksum != "valid" {
		t.Fatalf("%+v %v", d, err)
	}
	b[6] ^= 1
	if _, err := ParseDCO(b); err == nil {
		t.Error("bad checksum accepted")
	}
	if _, err := ParseDCO(make([]byte, 512)); err == nil {
		t.Error("max LBA 0 accepted")
	}
}

func FuzzParseIdentify(f *testing.F) {
	for _, n := range []string{"samsung-hd321kj.txt", "owc-mercury-extreme-pro-ssd.txt", "intel-ssdsa2ct040g3.txt", "sil-external-raid.txt"} {
		f.Add(loadDump(f, n))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		id, err := ParseIdentify(b)
		if err != nil {
			return
		}
		if id.LogicalSectorBytes < 512 || id.PhysicalSectorBytes < id.LogicalSectorBytes {
			t.Fatalf("sector sizes %d/%d", id.LogicalSectorBytes, id.PhysicalSectorBytes)
		}
		if id.Sectors() > 1<<48 {
			t.Fatalf("sectors %d beyond 48 bits", id.Sectors())
		}
	})
}

func FuzzParseHdparmDump(f *testing.F) {
	f.Add([]byte("0040 3fff\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		raw, err := ParseHdparmDump(b)
		if err == nil && len(raw) != 512 {
			t.Fatalf("%d bytes", len(raw))
		}
	})
}
