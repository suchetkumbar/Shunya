package journal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

type payload struct {
	Pass   int   `json:"pass"`
	Offset int64 `json:"offset"`
}

// writeJournal creates a journal with n records and returns its path and bytes.
func writeJournal(t *testing.T, n int) (string, []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wipe.journal")
	w, err := Create(p, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	w.now = func() time.Time { clock = clock.Add(time.Second); return clock }
	for i := range n {
		typ := "checkpoint"
		if i == 0 {
			typ = "start"
		}
		if _, err := w.Append(typ, payload{0, int64(i) << 20}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, b
}

func TestRoundTrip(t *testing.T) {
	_, b := writeJournal(t, 5)
	log, err := Read(bytes.NewReader(b), testKey(1).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(log.Records) != 5 || log.TornBytes != 0 {
		t.Fatalf("records %d torn %d", len(log.Records), log.TornBytes)
	}
	for i, r := range log.Records {
		if r.Seq != uint64(i+1) {
			t.Fatalf("seq %d at %d", r.Seq, i)
		}
		var p payload
		if err := r.Decode(&p); err != nil || p.Offset != int64(i)<<20 {
			t.Fatalf("payload %+v %v", p, err)
		}
	}
	if log.Records[0].Prev != "" || log.Records[1].Prev == "" {
		t.Fatal("hash chain not set")
	}
	if log.KeyID != KeyID(testKey(1).Public().(ed25519.PublicKey)) {
		t.Fatal("key id")
	}
}

// Changing any single byte of a complete journal must be detected (or, for the final
// line, at worst turn it into a detected torn tail — never a silently different record).
func TestEveryByteFlipDetected(t *testing.T) {
	_, b := writeJournal(t, 3)
	pub := testKey(1).Public().(ed25519.PublicKey)
	for i := range b {
		for _, x := range []byte{0x01, 0x20, 0x80} {
			mut := bytes.Clone(b)
			mut[i] ^= x
			log, err := Read(bytes.NewReader(mut), pub)
			if err == nil {
				if mut[len(mut)-1] != '\n' && log.TornBytes > 0 && len(log.Records) == 2 {
					continue // the final newline was hit: reported as a torn tail
				}
				t.Fatalf("flip byte %d (^%#x) not detected: %d records", i, x, len(log.Records))
			}
			if !errors.Is(err, ErrTampered) {
				t.Fatalf("flip byte %d: error %v is not ErrTampered", i, err)
			}
		}
	}
}

func TestStructuralTampering(t *testing.T) {
	_, b := writeJournal(t, 4)
	pub := testKey(1).Public().(ed25519.PublicKey)
	lines := bytes.SplitAfter(b, []byte("\n"))
	lines = lines[:len(lines)-1] // trailing empty element
	join := func(ls ...[]byte) []byte { return bytes.Join(ls, nil) }
	cases := map[string][]byte{
		"drop first":   join(lines[1:]...),
		"drop middle":  join(lines[0], lines[1], lines[3]),
		"swap":         join(lines[0], lines[2], lines[1], lines[3]),
		"duplicate":    join(lines[0], lines[1], lines[1], lines[2]),
		"blank line":   join(lines[0], []byte("\n"), lines[1]),
		"garbage line": join(lines[0], []byte("{}\n"), lines[1]),
		"extra space":  join(lines[0], bytes.Replace(lines[1], []byte(`,"time"`), []byte(`, "time"`), 1)),
	}
	for name, mut := range cases {
		if _, err := Read(bytes.NewReader(mut), pub); !errors.Is(err, ErrTampered) {
			t.Errorf("%s: err = %v, want ErrTampered", name, err)
		}
	}
	if _, err := Read(bytes.NewReader(b), testKey(2).Public().(ed25519.PublicKey)); !errors.Is(err, ErrWrongKey) {
		t.Errorf("wrong key: err = %v", err)
	}
}

// Two journals by the same station key: a record from one, spliced into the other at
// the same position, has a valid signature and the right seq. Only the hash chain
// (prev) shows it doesn't belong there.
func TestSpliceFromOtherJournalDetected(t *testing.T) {
	_, a := writeJournal(t, 3)
	p := filepath.Join(t.TempDir(), "other.journal")
	w, err := Create(p, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	w.Append("start", payload{0, 0})
	w.Append("checkpoint", payload{0, 999 << 20}) // the forged progress claim
	w.Append("checkpoint", payload{0, 1000 << 20})
	w.Close()
	b, _ := os.ReadFile(p)
	la := bytes.SplitAfter(a, []byte("\n"))
	lb := bytes.SplitAfter(b, []byte("\n"))
	spliced := bytes.Join([][]byte{la[0], lb[1], la[2]}, nil)
	if _, err := Read(bytes.NewReader(spliced), testKey(1).Public().(ed25519.PublicKey)); !errors.Is(err, ErrTampered) ||
		!strings.Contains(err.Error(), "does not chain") {
		t.Fatalf("spliced journal: %v", err)
	}
}

func TestTornTail(t *testing.T) {
	_, b := writeJournal(t, 3)
	pub := testKey(1).Public().(ed25519.PublicKey)
	last := bytes.LastIndexByte(b[:len(b)-1], '\n') + 1
	for cut := last + 1; cut < len(b); cut += 7 {
		log, err := Read(bytes.NewReader(b[:cut]), pub)
		if err != nil {
			t.Fatalf("cut at %d: %v", cut, err)
		}
		if len(log.Records) != 2 || log.TornBytes != cut-last {
			t.Fatalf("cut at %d: %d records, torn %d", cut, len(log.Records), log.TornBytes)
		}
	}
}

func TestOpenAppendTruncatesTornTailAndContinues(t *testing.T) {
	p, b := writeJournal(t, 3)
	if err := os.WriteFile(p, append(bytes.Clone(b), []byte(`{"seq":4,"ti`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	w, log, err := OpenAppend(p, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if log.TornBytes != 12 || len(log.Records) != 3 {
		t.Fatalf("torn %d records %d", log.TornBytes, len(log.Records))
	}
	if _, err := w.Append("resumed", payload{0, 3 << 20}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	got, _ := os.ReadFile(p)
	log2, err := Read(bytes.NewReader(got), testKey(1).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(log2.Records) != 4 || log2.Records[3].Type != "resumed" || log2.Records[3].Seq != 4 {
		t.Fatalf("after append: %+v", log2.Records)
	}
}

func TestOpenAppendRefusesTamperedAndWrongKey(t *testing.T) {
	p, b := writeJournal(t, 3)
	if _, _, err := OpenAppend(p, testKey(2)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong key: %v", err)
	}
	b[10] ^= 1
	os.WriteFile(p, b, 0o600)
	if _, _, err := OpenAppend(p, testKey(1)); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered: %v", err)
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	p, _ := writeJournal(t, 1)
	if _, err := Create(p, testKey(1)); err == nil {
		t.Fatal("Create overwrote an existing journal")
	}
}

func TestEmptyAndOversized(t *testing.T) {
	pub := testKey(1).Public().(ed25519.PublicKey)
	log, err := Read(strings.NewReader(""), pub)
	if err != nil || len(log.Records) != 0 {
		t.Fatalf("empty: %v %v", log, err)
	}
	big := strings.Repeat("x", MaxLine+10) + "\n"
	if _, err := Read(strings.NewReader(big), pub); !errors.Is(err, ErrTampered) {
		t.Fatalf("oversized line: %v", err)
	}
}

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "station.key")
	pub, err := GenerateKeyFile(p)
	if err != nil {
		t.Fatal(err)
	}
	k, err := LoadKeyFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Public().(ed25519.PublicKey), pub) {
		t.Fatal("loaded key differs")
	}
	if _, err := GenerateKeyFile(p); err == nil {
		t.Fatal("GenerateKeyFile overwrote a key")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.key"), []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(filepath.Join(dir, "bad.key")); err == nil {
		t.Fatal("malformed key accepted")
	}
	// New keys carry the station header; keys written by Milestones 3–6 (dev header)
	// still load, so their journals can still be resumed and certified.
	raw, _ := os.ReadFile(p)
	if !bytes.HasPrefix(raw, []byte("shunya-station-key-v1 ")) {
		t.Errorf("header %q", raw[:24])
	}
	legacy := filepath.Join(dir, "legacy.key")
	os.WriteFile(legacy, bytes.Replace(raw, []byte("shunya-station-key-v1"), []byte("shunya-dev-station-key-v1"), 1), 0o600)
	if k2, err := LoadKeyFile(legacy); err != nil || !bytes.Equal(k2.Public().(ed25519.PublicKey), pub) {
		t.Errorf("legacy key: %v", err)
	}
}

func FuzzRead(f *testing.F) {
	dir := f.TempDir()
	p := filepath.Join(dir, "j")
	w, _ := Create(p, testKey(1))
	w.Append("start", payload{0, 0})
	w.Append("checkpoint", payload{0, 1 << 20})
	w.Close()
	b, _ := os.ReadFile(p)
	f.Add(b)
	f.Add([]byte("{}\n"))
	f.Add([]byte(""))
	pub := testKey(1).Public().(ed25519.PublicKey)
	f.Fuzz(func(t *testing.T, in []byte) {
		log, err := Read(bytes.NewReader(in), pub)
		if err != nil {
			return
		}
		// Anything accepted must re-encode to exactly the accepted prefix.
		var out []byte
		for _, r := range log.Records {
			out = append(out, r.raw...)
			out = append(out, '\n')
		}
		if !bytes.Equal(out, in[:len(in)-log.TornBytes]) {
			t.Fatalf("accepted input does not round-trip")
		}
	})
}

// A journal path must never open a device (or follow a symlink to one): refused from
// Lstat alone, before any open.
func TestOpenAppendRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link.journal")
	if err := os.Symlink(os.DevNull, link); err != nil {
		t.Skip("SKIPPED: cannot create symlink:", err)
	}
	for _, p := range []string{link, dir, os.DevNull} {
		if _, _, err := OpenAppend(p, testKey(1)); !errors.Is(err, ErrNotRegular) {
			t.Errorf("%s: err = %v, want ErrNotRegular", p, err)
		}
	}
}
