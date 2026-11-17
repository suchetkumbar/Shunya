package engine

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"math/rand/v2"
	"testing"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// NIST SP 800-38A, F.5.5 CTR-AES256.Encrypt. Encrypting the plaintext with our
// keystream must give the published ciphertext, including when generation starts at a
// later block (the seek used by resume and verification).
func TestKeystreamNISTVector(t *testing.T) {
	key := unhex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	var base [16]byte
	copy(base[:], unhex(t, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
	plain := unhex(t, "6bc1bee22e409f96e93d7e117393172a"+"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+"f69f2445df4f9b17ad2b417be66c3710")
	cipherText := unhex(t, "601ec313775789a5b7a7f504bbf3d228"+"f443e3ca4d62b59aca84e990cacaf5c5"+
		"2b0930daa23de94ce87017ba2d84988d"+"dfc9c58db67aada613c2dd08457941a6")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, start := range []int{0, 16, 32, 48, 5, 21} {
		ks := make([]byte, len(plain)-start)
		keystream(block, base, ks, int64(start))
		for i := range ks {
			ks[i] ^= plain[start+i]
		}
		if !bytes.Equal(ks, cipherText[start:]) {
			t.Fatalf("start %d: got %x\nwant %x", start, ks, cipherText[start:])
		}
	}
}

func TestAddCounterCarries(t *testing.T) {
	iv := [16]byte{7: 0x01, 8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff}
	addCounter(&iv, 1)
	want := [16]byte{7: 0x02}
	if iv != want {
		t.Fatalf("got %x want %x", iv, want)
	}
	all := [16]byte{0: 0xff, 1: 0xff, 2: 0xff, 3: 0xff, 4: 0xff, 5: 0xff, 6: 0xff, 7: 0xff, 8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff}
	addCounter(&all, 1)
	if all != ([16]byte{}) {
		t.Fatalf("128-bit wrap: got %x", all)
	}
}

func TestConstantPatterns(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    byte
	}{{"zero", 0x00}, {"one", 0xff}} {
		p, err := NewPattern(tc.name, nil)
		if err != nil {
			t.Fatal(err)
		}
		buf := bytes.Repeat([]byte{0x5a}, 4097)
		p.Fill(buf, 12345)
		if !bytes.Equal(buf, bytes.Repeat([]byte{tc.b}, len(buf))) {
			t.Fatalf("%s: wrong fill", tc.name)
		}
		if p.Name() != tc.name {
			t.Fatalf("name %q", p.Name())
		}
	}
}

func TestNewPatternErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{"random", nil},
		{"random", make([]byte, 16)},
		{"zero", make([]byte, 32)},
		{"dod", nil},
		{"", nil},
	} {
		if _, err := NewPattern(tc.name, tc.key); err == nil {
			t.Errorf("NewPattern(%q, %d-byte key) accepted", tc.name, len(tc.key))
		}
	}
}

// Fill(buf, off) must equal the matching slice of one continuous stream, for any
// offset and length: that is what lets a resumed or verifying pass regenerate a range.
func TestRandomSeekable(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	p, err := NewPattern("random", key)
	if err != nil {
		t.Fatal(err)
	}
	const n = 1 << 16
	whole := make([]byte, n)
	p.Fill(whole, 0)
	r := rand.New(rand.NewPCG(1, 2))
	for range 500 {
		off := r.IntN(n)
		l := r.IntN(n - off + 1)
		part := make([]byte, l)
		p.Fill(part, int64(off))
		if !bytes.Equal(part, whole[off:off+l]) {
			t.Fatalf("Fill(%d bytes at %d) differs from the continuous stream", l, off)
		}
	}
	other, _ := NewPattern("random", bytes.Repeat([]byte{0x43}, 32))
	diff := make([]byte, 64)
	other.Fill(diff, 0)
	if bytes.Equal(diff, whole[:64]) {
		t.Fatal("different keys gave the same stream")
	}
	if bytes.Equal(whole[:4096], make([]byte, 4096)) {
		t.Fatal("random stream is all zeros")
	}
}

func FuzzRandomSeekable(f *testing.F) {
	f.Add(uint32(0), uint16(100))
	f.Add(uint32(17), uint16(4096))
	key := bytes.Repeat([]byte{7}, 32)
	p, _ := NewPattern("random", key)
	f.Fuzz(func(t *testing.T, off uint32, l uint16) {
		o := int64(off % (1 << 20))
		whole := make([]byte, int(l)+32)
		p.Fill(whole, o-o%16)
		part := make([]byte, l)
		p.Fill(part, o)
		skip := int(o % 16)
		if !bytes.Equal(part, whole[skip:skip+int(l)]) {
			t.Fatalf("off %d len %d", o, l)
		}
	})
}

func BenchmarkPattern(b *testing.B) {
	buf := make([]byte, 4<<20)
	for _, name := range []string{"zero", "one", "random"} {
		var key []byte
		if name == "random" {
			key = bytes.Repeat([]byte{1}, 32)
		}
		p, err := NewPattern(name, key)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(buf)))
			var off int64
			for b.Loop() {
				p.Fill(buf, off)
				off += int64(len(buf))
			}
		})
	}
}
