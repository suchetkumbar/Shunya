package winata_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"shunya/internal/ata"
	. "shunya/internal/winstorage/winata"
)

func TestATAIdentifyRoundTrip(t *testing.T) {
	c := ata.IdentifyCmd()
	r, err := FromCDB(c.CDB())
	if err != nil {
		t.Fatal(err)
	}
	if r.Flags != 0x01|0x02 || r.DataLen != 512 || r.Curr[6] != 0xec || r.Ext {
		t.Fatalf("%+v", r)
	}
	data := make([]byte, 512)
	in, err := Encode(r, data, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(in) != 48 || binary.LittleEndian.Uint32(in[8:]) != 512 || binary.LittleEndian.Uint32(in[12:]) != 10 || binary.LittleEndian.Uint64(in[24:]) != 48 || in[46] != 0xec {
		t.Fatalf("header % x", in[:48])
	}
	// The driver's answer: IDENTIFY data, status DRDY, registers in CurrentTaskFile.
	out := bytes.Clone(in)
	copy(out[48:], bytes.Repeat([]byte{0x5a}, 512))
	copy(out[40:48], []byte{0x00, 0x01, 0, 0, 0, 0xa0, 0x50, 0})
	sense, err := Decode(r, out, data)
	if err != nil {
		t.Fatal(err)
	}
	if data[511] != 0x5a {
		t.Fatal("read data not copied")
	}
	s, err := ata.ParseSense(sense)
	if err != nil || !s.Regs.HaveRegs || s.Regs.Status != 0x50 || s.Regs.Failed() || s.Key != ata.SenseRecovered {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestATA48BitRegistersAndErrors(t *testing.T) {
	c := ata.ReadNativeMaxExt()
	r, err := FromCDB(c.CDB())
	if err != nil {
		t.Fatal(err)
	}
	if r.Flags&0x08 == 0 || r.DataLen != 0 || r.DataIn {
		t.Fatalf("%+v", r)
	}
	in, _ := Encode(r, nil, time.Second)
	if binary.LittleEndian.Uint64(in[24:]) != 0 {
		t.Fatal("DataBufferOffset set without data")
	}
	out := bytes.Clone(in)
	// LBA 0x0000_7470_C06F (a 1 TB drive's max), high bytes in PreviousTaskFile.
	copy(out[32:40], []byte{0, 0, 0x70, 0x74, 0x00, 0, 0, 0})
	copy(out[40:48], []byte{0, 0, 0x6f, 0xc0, 0x70, 0x40, 0x50, 0})
	sense, _ := Decode(r, out, nil)
	s, _ := ata.ParseSense(sense)
	if want := uint64(0x70)<<16 | 0xc0<<8 | 0x6f | uint64(0x70)<<24 | uint64(0x74)<<32; s.Regs.LBA != want {
		t.Fatalf("LBA %#x, want %#x", s.Regs.LBA, want)
	}
	// ERR + ABRT: an aborted command, as ata.Device reports it.
	copy(out[40:48], []byte{ata.ErrorABRT, 0, 0, 0, 0, 0x40, 0x51, 0})
	sense, _ = Decode(r, out, nil)
	s, _ = ata.ParseSense(sense)
	if !s.Regs.Aborted() || s.Key != ata.SenseAborted {
		t.Fatalf("%+v", s)
	}
}

func TestATARejects(t *testing.T) {
	var bad [16]byte
	bad[0] = 0x28 // READ(10), not ATA PASS-THROUGH
	if _, err := FromCDB(bad); err == nil {
		t.Error("non-ATA CDB accepted")
	}
	r, _ := FromCDB(ata.IdentifyCmd().CDB())
	if _, err := Encode(r, make([]byte, 100), time.Second); err == nil {
		t.Error("wrong buffer size accepted")
	}
	in, _ := Encode(r, make([]byte, 512), time.Second)
	if _, err := Decode(r, in[:100], make([]byte, 512)); !errors.Is(err, ErrShort) {
		t.Errorf("short output: %v", err)
	}
	short := bytes.Clone(in)
	binary.LittleEndian.PutUint32(short[8:], 256) // the driver transferred less than asked
	if _, err := Decode(r, short, make([]byte, 512)); err == nil {
		t.Error("short transfer accepted")
	}
}

func FuzzATA(f *testing.F) {
	idc := ata.IdentifyCmd().CDB()
	f.Add(idc[:], make([]byte, 600))
	f.Fuzz(func(t *testing.T, c []byte, out []byte) {
		var cdb [16]byte
		copy(cdb[:], c)
		r, err := FromCDB(cdb)
		if err != nil {
			return
		}
		data := make([]byte, r.DataLen)
		if _, err := Encode(r, data, time.Minute); err != nil {
			t.Fatal(err)
		}
		if sense, err := Decode(r, out, data); err == nil {
			if _, err := ata.ParseSense(sense); err != nil {
				t.Fatalf("own sense does not parse: %v", err)
			}
		}
	})
}

// winata reads the CDB itself (it cannot import ata); it must agree with ata.DecodeCDB
// on every command Shunya sends.
func TestFromCDBAgreesWithATA(t *testing.T) {
	cmds := []ata.Command{ata.IdentifyCmd(), ata.ReadNativeMaxExt(), ata.DCOIdentify(), ata.FlushCacheExt(),
		ata.SecurityErasePrepare(), ata.SanitizeStatus(), ata.SanitizeCryptoScramble(), ata.SanitizeBlockErase()}
	if c, err := ata.SetMaxAddressExtVolatile(0x7470c06f); err == nil {
		cmds = append(cmds, c)
	}
	for _, n := range []int{1, 8, 256} {
		if c, err := ata.ReadDMAExt(0x123456789a, n); err == nil {
			cmds = append(cmds, c)
		}
		if c, err := ata.WriteDMAExt(77, n); err == nil {
			cmds = append(cmds, c)
		}
	}
	if c, _, err := ata.SecurityEraseUnit("p", true, time.Hour); err == nil {
		cmds = append(cmds, c)
	}
	if c, err := ata.SanitizeOverwrite(3, 0xdeadbeef); err == nil {
		cmds = append(cmds, c)
	}
	if len(cmds) < 14 {
		t.Fatalf("only %d commands built", len(cmds))
	}
	for _, c := range cmds {
		cdb := c.CDB()
		d, err := ata.DecodeCDB(cdb)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		r, err := FromCDB(cdb)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		tf := d.TF
		curr := [8]byte{byte(tf.Feature), byte(tf.Count), byte(tf.LBA), byte(tf.LBA >> 8), byte(tf.LBA >> 16), tf.Device, tf.Command, 0}
		if r.Curr != curr || r.Ext != d.Ext || r.DataLen != d.Sectors*ata.SectorBytes || r.DataIn != (d.Dir == ata.DirIn) {
			t.Errorf("%s: %+v vs %+v", c.Name, r, d)
		}
		if d.Ext {
			prev := [8]byte{byte(tf.Feature >> 8), byte(tf.Count >> 8), byte(tf.LBA >> 24), byte(tf.LBA >> 32), byte(tf.LBA >> 40)}
			if r.Prev != prev {
				t.Errorf("%s: previous task file % x, want % x", c.Name, r.Prev, prev)
			}
		}
		if (r.Flags&0x10 != 0) != (d.Proto == ata.ProtoDMA) {
			t.Errorf("%s: DMA flag %#x for protocol %d", c.Name, r.Flags, d.Proto)
		}
	}
}

// Any CDB winata accepts, ata accepts too (and the reverse), with the same transfer.
func FuzzFromCDBAgrees(f *testing.F) {
	idc := ata.IdentifyCmd().CDB()
	f.Add(idc[:])
	f.Fuzz(func(t *testing.T, c []byte) {
		var cdb [16]byte
		copy(cdb[:], c)
		d, derr := ata.DecodeCDB(cdb)
		r, rerr := FromCDB(cdb)
		if (derr == nil) != (rerr == nil) {
			t.Fatalf("ata: %v, winata: %v", derr, rerr)
		}
		if derr == nil && r.DataLen != d.Sectors*ata.SectorBytes {
			t.Fatalf("transfer %d vs %d", r.DataLen, d.Sectors*ata.SectorBytes)
		}
	})
}
