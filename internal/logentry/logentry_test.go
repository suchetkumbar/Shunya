package logentry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"shunya/internal/keys"
	"shunya/internal/tlog"
)

func request(t *testing.T) (SeedRequest, ed25519.PrivateKey) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	q, err := NewSeedRequest(priv, nil, strings.Repeat("ab", 16), "fp2:"+strings.Repeat("0", 64), sha256.Sum256([]byte("j")), keys.FormatTime(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	return q, priv
}

func TestSeedRequest(t *testing.T) {
	q, _ := request(t)
	if err := q.Verify(); err != nil {
		t.Fatal(err)
	}
	e, err := q.Entry()
	if err != nil || e[0] != TypeSeedRequest {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*SeedRequest){
		"fingerprint": func(r *SeedRequest) { r.Fingerprint += "x" },
		"wipe":        func(r *SeedRequest) { r.WipeID = strings.Repeat("cd", 16) },
		"journal":     func(r *SeedRequest) { r.JournalSHA256 = strings.Repeat("00", 32) },
		"time":        func(r *SeedRequest) { r.Requested = "2020-01-01T00:00:00Z" },
		"key id":      func(r *SeedRequest) { r.StationKeyID = "ed25519:0000000000000000" },
		"format":      func(r *SeedRequest) { r.Format = "x" },
		"signature":   func(r *SeedRequest) { r.Signature = "" },
		"bad time":    func(r *SeedRequest) { r.Requested = "yesterday" },
	} {
		r := q
		edit(&r)
		if r.Verify() == nil {
			t.Errorf("%s edited: verified", name)
		}
	}
	// Another key's signature.
	other, _ := request(t)
	r := q
	r.Signature = other.Signature
	if !errors.Is(r.Verify(), keys.ErrSignature) {
		t.Error("foreign signature")
	}
}

func TestEntriesAndSeed(t *testing.T) {
	if _, err := Entry(TypeCertificate, make([]byte, MaxEntry)); err == nil {
		t.Error("oversized entry")
	}
	if _, err := Entry(9, nil); err == nil {
		t.Error("unknown type")
	}
	b, _ := Beacon()
	if typ, p, err := Split(b); err != nil || typ != TypeBeacon || len(p) != 32 {
		t.Fatal("beacon")
	}
	for _, e := range [][]byte{nil, {0}, {5, 1}, {TypeBeacon, 1, 2}} {
		if _, _, err := Split(e); err == nil {
			t.Errorf("split %v", e)
		}
	}
	text := []byte("o\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	s1, s2 := Seed(text, "fp-a"), Seed(text, "fp-b")
	if bytes.Equal(s1, s2) || !bytes.Equal(s1, Seed(text, "fp-a")) || len(s1) != 32 {
		t.Fatal("seed")
	}
	if bytes.Equal(Seed(text, "fp-a"), Seed([]byte("o\n2\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), "fp-a")) {
		t.Fatal("seed ignores the checkpoint")
	}
	in := NewInclusion(0, nil, []tlog.Hash{{1}})
	if h, err := in.Hashes(); err != nil || h[0] != (tlog.Hash{1}) {
		t.Fatal(err)
	}
	in.Proof[0] = "AAAA"
	if _, err := in.Hashes(); err == nil {
		t.Fatal("short hash")
	}
	if NewInclusion(0, nil, nil).Proof == nil {
		t.Fatal("nil proof encodes as null")
	}
}
