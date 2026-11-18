package nvme

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func load(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// oracle reads nvme-cli's decoded text ("key : value") recorded next to the raw data
// from the same QEMU drive: an independent implementation to compare against.
func oracle(t *testing.T, name string) map[string]string {
	t.Helper()
	m := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(load(t, name)))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

func num(t *testing.T, s string) uint64 {
	t.Helper()
	s = strings.Fields(s)[0]
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return v
}

func TestParseControllerQEMU(t *testing.T) {
	c, err := ParseController(load(t, "qemu-id-ctrl.bin"))
	if err != nil {
		t.Fatal(err)
	}
	o := oracle(t, "qemu-id-ctrl.nvme-cli.txt")
	checks := []struct {
		name      string
		got, want uint64
	}{
		{"vid", uint64(c.VID), num(t, o["vid"])},
		{"ssvid", uint64(c.SSVID), num(t, o["ssvid"])},
		{"cmic", uint64(c.CMIC), num(t, o["cmic"])},
		{"mdts", uint64(c.MDTS), num(t, o["mdts"])},
		{"cntlid", uint64(c.CNTLID), num(t, o["cntlid"])},
		{"oacs", uint64(c.OACS), num(t, o["oacs"])},
		{"sanicap", uint64(c.Sanicap.Raw), num(t, o["sanicap"])},
		{"nn", uint64(c.NN), num(t, o["nn"])},
		{"fna", uint64(c.FNA.Raw), num(t, o["fna"])},
		{"tnvmcap", c.TotalCapacity, num(t, o["tnvmcap"])},
	}
	for _, ck := range checks {
		if ck.got != ck.want {
			t.Errorf("%s: %#x, nvme-cli %#x", ck.name, ck.got, ck.want)
		}
	}
	if c.Serial != o["sn"] || c.Model != o["mn"] || c.Firmware != o["fr"] || c.IEEE != o["ieee"] || c.SubNQN != o["subnqn"] {
		t.Errorf("strings: %q %q %q %q %q", c.Serial, c.Model, c.Firmware, c.IEEE, c.SubNQN)
	}
	if c.Version != "1.4.0" || !c.FormatSupported || c.Sanicap.Any() || c.FNA.CryptoErase {
		t.Errorf("%+v", c)
	}
}

func TestParseNamespaceQEMU(t *testing.T) {
	n, err := ParseNamespace(1, load(t, "qemu-id-ns.bin"))
	if err != nil {
		t.Fatal(err)
	}
	o := oracle(t, "qemu-id-ns.nvme-cli.txt")
	if n.Size != num(t, o["nsze"]) || n.Capacity != num(t, o["ncap"]) || n.Utilization != num(t, o["nuse"]) ||
		uint64(n.NLBAF) != num(t, o["nlbaf"]) || uint64(n.LBAF) != num(t, o["flbas"])&0xf || uint64(n.DeallocRead) != num(t, o["dlfeat"])&7 {
		t.Errorf("%+v", n)
	}
	if n.EUI64 != o["eui64"] || n.NGUID != "" || !n.Shared != (num(t, o["nmic"])&1 == 0) {
		t.Errorf("ids: %q %q shared %v", n.EUI64, n.NGUID, n.Shared)
	}
	// "lbaf  4 : ms:0   lbads:12 rp:0"
	for i, f := range n.Formats {
		line := o["lbaf  "+strconv.Itoa(i)]
		want := "ms:" + strconv.Itoa(f.MetadataBytes)
		lbads := 0
		for s := f.DataBytes; s > 1; s >>= 1 {
			lbads++
		}
		if !strings.HasPrefix(line, want) || !strings.Contains(line, "lbads:"+strconv.Itoa(lbads)+" ") {
			t.Errorf("lbaf %d: %+v vs %q", i, f, line)
		}
	}
	if n.BlockBytes() != 512 || n.SizeBytes() != 1<<30 {
		t.Errorf("%d %d", n.BlockBytes(), n.SizeBytes())
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := ParseController(make([]byte, 100)); !errors.Is(err, ErrLength) {
		t.Error(err)
	}
	if _, err := ParseController(make([]byte, IdentifyBytes)); !errors.Is(err, ErrInvalid) {
		t.Error("empty controller accepted")
	}
	ns := load(t, "qemu-id-ns.bin")
	inactive := bytes.Clone(ns)
	clear(inactive[0:8])
	if _, err := ParseNamespace(1, inactive); !errors.Is(err, ErrInvalid) {
		t.Error("size 0 accepted")
	}
	badFmt := bytes.Clone(ns)
	badFmt[26] = 9 // format 9 of 8
	if _, err := ParseNamespace(1, badFmt); !errors.Is(err, ErrInvalid) {
		t.Error("format beyond NLBAF accepted")
	}
	badLBADS := bytes.Clone(ns)
	badLBADS[130] = 3 // 2^3-byte blocks
	if _, err := ParseNamespace(1, badLBADS); !errors.Is(err, ErrInvalid) {
		t.Error("lbads 3 accepted")
	}
	list := make([]byte, IdentifyBytes)
	binary.LittleEndian.PutUint32(list[0:], 2)
	binary.LittleEndian.PutUint32(list[4:], 1)
	if _, err := ParseNamespaceList(list); err == nil {
		t.Error("decreasing list accepted")
	}
	binary.LittleEndian.PutUint32(list[4:], 7)
	if ids, err := ParseNamespaceList(list); err != nil || len(ids) != 2 {
		t.Errorf("%v %v", ids, err)
	}
}

func TestParseSanitizeLog(t *testing.T) {
	b := make([]byte, SanitizeLogBytes)
	binary.LittleEndian.PutUint16(b[0:], 0x8000)
	binary.LittleEndian.PutUint16(b[2:], 2|3<<3|1<<8)
	binary.LittleEndian.PutUint32(b[4:], SanactCryptoErase)
	binary.LittleEndian.PutUint32(b[8:], 0xffffffff)
	binary.LittleEndian.PutUint32(b[16:], 90)
	l, err := ParseSanitizeLog(b)
	if err != nil || l.Progress != 0.5 || l.Status != SanitizeInProgress || l.Passes != 3 || !l.GlobalDataErased ||
		l.Action() != SanactCryptoErase || l.EstOverwrite != -1 || l.EstCrypto != 90 {
		t.Fatalf("%+v %v", l, err)
	}
	binary.LittleEndian.PutUint16(b[2:], 5)
	if _, err := ParseSanitizeLog(b); err == nil {
		t.Error("status 5 accepted")
	}
}

// Command encodings follow libnvme's nvme_format_nvm / nvme_sanitize_nvm /
// nvme_get_log (cdw10 field shifts in ioctl.h).
func TestCommands(t *testing.T) {
	c := IdentifyController()
	if c.Cmd.Opcode != 0x06 || c.Cmd.CDW10 != 1 || c.Cmd.DataLen != 4096 || c.Cmd.NSID != 0 || c.Cmd.TimeoutMS != 30000 {
		t.Errorf("%+v", c.Cmd)
	}
	l := SanitizeStatusLog()
	if l.Cmd.Opcode != 0x02 || l.Cmd.CDW10 != 0x81|127<<16 || l.Cmd.CDW11 != 0 || l.Cmd.NSID != NSIDAll || l.Cmd.DataLen != 512 {
		t.Errorf("%+v", l.Cmd)
	}
	f, err := FormatNVM(1, 17, SESCryptoErs, true, 1, true, FormatTimeout)
	// lbaf 17: low 4 bits 1, upper 2 bits 1 at 13:12; mset bit 4; pi 1 at 7:5; pil bit 8; ses 2 at 11:9.
	if err != nil || f.Cmd.Opcode != 0x80 || f.Cmd.NSID != 1 || f.Cmd.CDW10 != 1|1<<4|1<<5|1<<8|2<<9|1<<12 {
		t.Errorf("%#x %v", f.Cmd.CDW10, err)
	}
	for _, bad := range []func() error{
		func() error { _, e := FormatNVM(0, 0, 1, false, 0, false, 0); return e },
		func() error { _, e := FormatNVM(NSIDAll, 0, 1, false, 0, false, 0); return e },
		func() error { _, e := FormatNVM(1, 64, 1, false, 0, false, 0); return e },
		func() error { _, e := FormatNVM(1, 0, 0, false, 0, false, 0); return e },
		func() error { _, e := FormatNVM(1, 0, 3, false, 0, false, 0); return e },
		func() error { _, e := Sanitize(SanactExitFailure, 0, 0); return e },
		func() error { _, e := Sanitize(5, 0, 0); return e },
		func() error { _, e := Sanitize(SanactOverwrite, 0, 0); return e },
		func() error { _, e := Sanitize(SanactOverwrite, 17, 0); return e },
	} {
		if err := bad(); !errors.Is(err, ErrArgs) {
			t.Errorf("accepted: %v", err)
		}
	}
	s, _ := Sanitize(SanactOverwrite, 16, 0xdeadbeef)
	if s.Cmd.Opcode != 0x84 || s.Cmd.CDW10 != 3 || s.Cmd.CDW11 != 0xdeadbeef { // 16 passes encode as 0
		t.Errorf("%+v", s.Cmd)
	}
	s, _ = Sanitize(SanactCryptoErase, 0, 0)
	if s.Cmd.CDW10 != 4 || s.Cmd.CDW11 != 0 {
		t.Errorf("%+v", s.Cmd)
	}
}

func TestStatus(t *testing.T) {
	// The QEMU drive answered the Sanitize Status log with 0x4002 (nvme-cli: "Invalid
	// Field in Command ... (0x4002)").
	s := Status(0x4002)
	if s.Code() != StatusInvalidField || !s.DNR() || !strings.Contains(s.String(), "Invalid Field") {
		t.Errorf("%s", s)
	}
	err := error(&CommandError{Cmd: "X", Status: Status(0x401d)})
	if !HasStatus(err, StatusSanitizeInProgress) || HasStatus(err, StatusInvalidField) {
		t.Error("HasStatus")
	}
}

func FuzzParseController(f *testing.F) {
	f.Add(load(f, "qemu-id-ctrl.bin"))
	f.Fuzz(func(t *testing.T, b []byte) { ParseController(b) })
}

func FuzzParseNamespace(f *testing.F) {
	f.Add(load(f, "qemu-id-ns.bin"))
	f.Fuzz(func(t *testing.T, b []byte) {
		n, err := ParseNamespace(1, b)
		if err == nil && (n.BlockBytes() < 512 || n.SizeBytes()/uint64(n.BlockBytes()) != n.Size) {
			t.Fatalf("%+v", n)
		}
	})
}

func FuzzParseSanitizeLog(f *testing.F) {
	f.Add(make([]byte, SanitizeLogBytes))
	f.Fuzz(func(t *testing.T, b []byte) { ParseSanitizeLog(b) })
}

// FLBAS bits 6:5 are the upper bits of the format index (NVMe 2.0, up to 64 formats).
func TestParseNamespaceHighFormatIndex(t *testing.T) {
	b := bytes.Clone(load(t, "qemu-id-ns.bin"))
	b[25] = 19                                          // 20 formats
	b[26] = 1 | 1<<5                                    // index 17: low 4 bits 1, bits 6:5 = 1
	binary.LittleEndian.PutUint32(b[128+4*17:], 12<<16) // format 17: 4 KiB, no metadata
	n, err := ParseNamespace(1, b)
	if err != nil || n.LBAF != 17 || n.BlockBytes() != 4096 {
		t.Fatalf("%+v %v", n, err)
	}
}
