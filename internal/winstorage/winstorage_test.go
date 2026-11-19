package winstorage

import (
	"bytes"
	"errors"
	"testing"
)

// descriptor builds a STORAGE_DEVICE_DESCRIPTOR the way the Windows SDK lays it out:
// Version, Size, DeviceType, DeviceTypeModifier, RemovableMedia, CommandQueueing,
// Vendor/Product/Revision/Serial offsets, BusType, RawPropertiesLength, then the strings.
func descriptor(removable bool, bus BusType, strs ...string) []byte {
	b := make([]byte, descriptorFixed)
	var tail []byte
	offs := make([]uint32, 4)
	for i, s := range strs {
		if s == "" {
			continue
		}
		offs[i] = uint32(descriptorFixed + len(tail))
		tail = append(append(tail, s...), 0)
	}
	b = append(b, tail...)
	le.PutUint32(b[0:], uint32(descriptorFixed)) // Version is sizeof the structure
	le.PutUint32(b[4:], uint32(len(b)))
	if removable {
		b[10] = 1
	}
	for i, o := range offs {
		le.PutUint32(b[12+4*i:], o)
	}
	le.PutUint32(b[28:], uint32(bus))
	return b
}

func TestParseDeviceDescriptor(t *testing.T) {
	b := descriptor(false, BusNVMe, "", "Samsung SSD 980 PRO 1TB                 ", "5B2QGXA7", "0025_38B5_11A2_C3D4.")
	b = append(b, make([]byte, 64)...) // the caller's buffer is larger than what was filled
	d, err := ParseDeviceDescriptor(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Product != "Samsung SSD 980 PRO 1TB" || d.Vendor != "" || d.Revision != "5B2QGXA7" || d.Serial != "0025_38B5_11A2_C3D4." || d.Bus != BusNVMe || d.Removable {
		t.Fatalf("%+v", d)
	}
	u, err := ParseDeviceDescriptor(descriptor(true, BusUSB, "SanDisk ", "Cruzer Blade", "1.00", "4C530001230616118063"))
	if err != nil || !u.Removable || u.Bus.String() != "usb" || u.Vendor != "SanDisk" {
		t.Fatalf("%+v %v", u, err)
	}
}

func TestParseDeviceDescriptorRejects(t *testing.T) {
	good := descriptor(false, BusSATA, "ATA", "CT500MX500SSD1", "046", "2117E1A2B3C4")
	cases := map[string]func([]byte) []byte{
		"short":            func(b []byte) []byte { return b[:20] },
		"size below fixed": func(b []byte) []byte { le.PutUint32(b[4:], 8); return b },
		"offset outside":   func(b []byte) []byte { le.PutUint32(b[24:], uint32(len(b)+5)); return b },
		"offset in header": func(b []byte) []byte { le.PutUint32(b[16:], 4); return b },
		"no terminator":    func(b []byte) []byte { return b[:len(b)-1] },
		"size cuts string": func(b []byte) []byte { le.PutUint32(b[4:], uint32(len(b)-3)); return b },
		"control bytes":    func(b []byte) []byte { b[len(b)-3] = 0x07; return b },
	}
	for name, mut := range cases {
		b := mut(bytes.Clone(good))
		if _, err := ParseDeviceDescriptor(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseGeometryAndAlignment(t *testing.T) {
	g := make([]byte, 32+8)
	le.PutUint64(g[0:], 121601) // Cylinders
	le.PutUint32(g[8:], 12)     // FixedMedia
	le.PutUint32(g[12:], 255)
	le.PutUint32(g[16:], 63)
	le.PutUint32(g[20:], 512)
	le.PutUint64(g[24:], 1000204886016)
	got, err := ParseGeometryEx(g)
	if err != nil || got.BytesPerSector != 512 || got.DiskSize != 1000204886016 {
		t.Fatalf("%+v %v", got, err)
	}
	le.PutUint32(g[20:], 520)
	if _, err := ParseGeometryEx(g); err == nil {
		t.Error("520-byte sectors accepted")
	}
	if _, err := ParseGeometryEx(g[:30]); !errors.Is(err, ErrShort) {
		t.Errorf("short geometry: %v", err)
	}

	a := make([]byte, 28)
	for i, v := range []uint32{28, 28, 64, 0, 512, 4096, 0} {
		le.PutUint32(a[4*i:], v)
	}
	al, err := ParseAccessAlignment(a)
	if err != nil || al.LogicalSector != 512 || al.PhysicalSector != 4096 {
		t.Fatalf("%+v %v", al, err)
	}
	le.PutUint32(a[20:], 256)
	if _, err := ParseAccessAlignment(a); err == nil {
		t.Error("physical sector smaller than logical accepted")
	}
}

func TestParseDiskExtents(t *testing.T) {
	b := make([]byte, 8+24*2)
	le.PutUint32(b, 2)
	le.PutUint32(b[8:], 0)
	le.PutUint64(b[16:], 1<<20)
	le.PutUint64(b[24:], 100<<30)
	le.PutUint32(b[32:], 3)
	le.PutUint64(b[40:], 1<<20)
	le.PutUint64(b[48:], 200<<30)
	ex, err := ParseDiskExtents(b)
	if err != nil || len(ex) != 2 || ex[1].Disk != 3 || ex[1].Length != 200<<30 {
		t.Fatalf("%+v %v", ex, err)
	}
	le.PutUint32(b, 3) // claims more than the buffer holds
	if _, err := ParseDiskExtents(b); !errors.Is(err, ErrShort) {
		t.Errorf("overlong count: %v", err)
	}
	le.PutUint32(b, 0)
	if _, err := ParseDiskExtents(b); err == nil {
		t.Error("zero extents accepted")
	}
}

func layout(style uint32, parts ...[2]int64) []byte {
	b := make([]byte, layoutHeader+partEntry*len(parts))
	le.PutUint32(b, style)
	le.PutUint32(b[4:], uint32(len(parts)))
	for i, p := range parts {
		e := b[layoutHeader+partEntry*i:]
		le.PutUint32(e, style)
		le.PutUint64(e[8:], uint64(p[0]))
		le.PutUint64(e[16:], uint64(p[1]))
		le.PutUint32(e[24:], uint32(i+1))
	}
	return b
}

func TestParseDriveLayout(t *testing.T) {
	// MBR: four slots, two used.
	l, err := ParseDriveLayout(layout(StyleMBR, [2]int64{1 << 20, 500 << 20}, [2]int64{501 << 20, 10 << 30}, [2]int64{}, [2]int64{}))
	if err != nil || l.Style != StyleMBR || len(l.Partitions) != 2 || l.Partitions[1].Disk != 2 {
		t.Fatalf("%+v %v", l, err)
	}
	raw, err := ParseDriveLayout(layout(StyleRAW))
	if err != nil || len(raw.Partitions) != 0 {
		t.Fatalf("raw: %+v %v", raw, err)
	}
	bad := layout(StyleGPT, [2]int64{1 << 20, 1 << 30})
	le.PutUint32(bad[4:], 2)
	if _, err := ParseDriveLayout(bad); !errors.Is(err, ErrShort) {
		t.Errorf("count past the end: %v", err)
	}
	if _, err := ParseDriveLayout(layout(7)); err == nil {
		t.Error("unknown partition style accepted")
	}
}

func TestNVMeIdentifyQuery(t *testing.T) {
	q, err := NVMeIdentifyQuery(0x01, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 8+40+4096 || le.Uint32(q) != PropAdapterProtocolSpecific || le.Uint32(q[4:]) != 0 {
		t.Fatalf("header % x", q[:8])
	}
	p := q[8:]
	for i, want := range []uint32{3, 1, 1, 0, 40, 4096, 0, 0, 0, 0} {
		if got := le.Uint32(p[4*i:]); got != want {
			t.Errorf("STORAGE_PROTOCOL_SPECIFIC_DATA field %d = %d, want %d", i, got, want)
		}
	}
	ns, err := NVMeIdentifyQuery(0x00, 1)
	if err != nil || le.Uint32(ns) != PropDeviceProtocolSpecific || le.Uint32(ns[8+12:]) != 1 {
		t.Fatalf("namespace query: %v", err)
	}
	for _, c := range []struct {
		cns  uint8
		nsid uint32
	}{{0x01, 1}, {0x00, 0}, {0x00, 0xffffffff}, {0x02, 0}, {0x10, 0}} {
		if _, err := NVMeIdentifyQuery(c.cns, c.nsid); err == nil {
			t.Errorf("CNS %#x nsid %#x accepted", c.cns, c.nsid)
		}
	}

	// The answer: the driver rewrites the buffer as STORAGE_PROTOCOL_DATA_DESCRIPTOR.
	ans := bytes.Clone(q)
	le.PutUint32(ans[0:], 48)
	le.PutUint32(ans[4:], 48)
	for i := range 4096 {
		ans[48+i] = byte(i)
	}
	id, err := ParseNVMeIdentify(ans)
	if err != nil || len(id) != 4096 || id[255] != 255 || id[4095] != 0xff {
		t.Fatalf("identify: %v", err)
	}
	for name, mut := range map[string]func([]byte){
		"version":  func(b []byte) { le.PutUint32(b, 12) },
		"protocol": func(b []byte) { le.PutUint32(b[8:], 2) },
		"offset":   func(b []byte) { le.PutUint32(b[8+16:], 41) },
		"low off":  func(b []byte) { le.PutUint32(b[8+16:], 8) },
		"length":   func(b []byte) { le.PutUint32(b[8+20:], 512) },
	} {
		b := bytes.Clone(ans)
		mut(b)
		if _, err := ParseNVMeIdentify(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzParsers(f *testing.F) {
	f.Add(descriptor(false, BusNVMe, "", "X", "1", "S"))
	f.Add(layout(StyleMBR, [2]int64{1, 2}))
	q, _ := NVMeIdentifyQuery(1, 0)
	f.Add(q)
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, err := ParseDeviceDescriptor(b); err == nil {
			for _, s := range []string{d.Vendor, d.Product, d.Revision, d.Serial} {
				for _, c := range []byte(s) {
					if c < 0x20 || c > 0x7e {
						t.Fatalf("non-printable byte in %q", s)
					}
				}
			}
		}
		if g, err := ParseGeometryEx(b); err == nil && (g.DiskSize < 0 || !validSector(g.BytesPerSector)) {
			t.Fatalf("%+v", g)
		}
		_, _ = ParseAccessAlignment(b)
		if ex, err := ParseDiskExtents(b); err == nil {
			for _, e := range ex {
				if e.Length <= 0 || e.Offset < 0 {
					t.Fatalf("%+v", e)
				}
			}
		}
		_, _ = ParseDriveLayout(b)
		if id, err := ParseNVMeIdentify(b); err == nil && len(id) != NVMeIdentifyBytes {
			t.Fatalf("identify %d bytes", len(id))
		}
	})
}
