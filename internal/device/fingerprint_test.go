package device

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestFingerprintV1Encoding(t *testing.T) {
	in := FingerprintInput{
		Model:         "Samsung SSD 980 PRO 1TB",
		Serial:        "S5GXNF0R123456",
		WWID:          "eui.002538b511a2c3d4",
		Firmware:      "5B2QGXA7",
		CapacityBytes: 1000204886016,
	}
	// Independent re-implementation of the documented encoding (design/FINGERPRINT.md):
	// tag, then for each field in fixed order: name, 0x00, uint32 big-endian length, value.
	h := sha256.New()
	h.Write([]byte("shunya-fingerprint-v1\n"))
	for _, kv := range [][2]string{
		{"model", in.Model}, {"serial", in.Serial}, {"wwid", in.WWID},
		{"firmware", in.Firmware}, {"capacity_bytes", "1000204886016"},
	} {
		h.Write([]byte(kv[0]))
		h.Write([]byte{0})
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(kv[1]))))
		h.Write([]byte(kv[1]))
	}
	wantHex := "fp1:" + hex.EncodeToString(h.Sum(nil))

	got := ComputeFingerprint(in)
	if got.Value != wantHex {
		t.Fatalf("fingerprint %s, want %s", got.Value, wantHex)
	}
	// Golden value pinned so an accidental encoding change is caught even if the
	// re-implementation above were changed along with it. Computed with sha256sum.
	const golden = "fp1:0e3705f4a7458d83857e28cfdfce8c4abac208f02d8abec5d40f9e9549ad3f77"
	if got.Value != golden {
		t.Logf("NOTE: golden mismatch: %s (update golden only after verifying with sha256sum)", got.Value)
		t.Fail()
	}
	if got.Version != 1 || got.Weak || got.CapacitySource != "sysfs" {
		t.Fatalf("metadata %+v", got)
	}
}

func TestFingerprintSensitivity(t *testing.T) {
	base := FingerprintInput{Model: "M", Serial: "S", WWID: "naa.1", Firmware: "F", CapacityBytes: 512}
	seen := map[string]string{ComputeFingerprint(base).Value: "base"}
	mut := map[string]FingerprintInput{}
	m := base
	m.Model = "M2"
	mut["model"] = m
	m = base
	m.Serial = "S2"
	mut["serial"] = m
	m = base
	m.WWID = "naa.2"
	mut["wwid"] = m
	m = base
	m.Firmware = "F2"
	mut["firmware"] = m
	m = base
	m.CapacityBytes = 1024
	mut["capacity"] = m
	// Field boundaries are length-prefixed, so moving bytes between fields must change it.
	m = base
	m.Model, m.Serial = "MS", ""
	mut["boundary"] = m
	for name, in := range mut {
		v := ComputeFingerprint(in).Value
		if prev, dup := seen[v]; dup {
			t.Errorf("%s collides with %s", name, prev)
		}
		seen[v] = name
	}
}

func TestFingerprintWeak(t *testing.T) {
	if !ComputeFingerprint(FingerprintInput{Model: "virtio", CapacityBytes: 1}).Weak {
		t.Error("no serial and no WWID must be weak")
	}
	if ComputeFingerprint(FingerprintInput{Serial: "X", CapacityBytes: 1}).Weak {
		t.Error("serial present must not be weak")
	}
	// Whitespace-only serial is no serial.
	if !ComputeFingerprint(FingerprintInput{Serial: "   ", CapacityBytes: 1}).Weak {
		t.Error("blank serial must be weak")
	}
}

func FuzzFingerprint(f *testing.F) {
	f.Add("m", "s", "w", "f", uint64(1))
	f.Fuzz(func(t *testing.T, model, serial, wwid, fw string, c uint64) {
		in := FingerprintInput{Model: model, Serial: serial, WWID: wwid, Firmware: fw, CapacityBytes: c}
		a, b := ComputeFingerprint(in), ComputeFingerprint(in)
		if a != b || len(a.Value) != 4+64 {
			t.Fatalf("unstable or bad length: %v %v", a, b)
		}
	})
}
