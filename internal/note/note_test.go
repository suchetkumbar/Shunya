package note

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	xnote "golang.org/x/mod/sumdb/note"
)

// The example in c2sp.org/signed-note ("Verifier keys" section).
const (
	specVkey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
	specNote = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
)

// golang.org/x/mod/sumdb/note's test keys and its expected signature (note_test.go).
const (
	peterSkey = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz"
	peterVkey = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
	peterText = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n"
	peterSig  = "— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n"
	enochVkey = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop"
	enochSig  = "— EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n"
)

func mustV(t *testing.T, k string) *Verifier {
	t.Helper()
	v, err := ParseVerifierKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSpecExample(t *testing.T) {
	if strings.Count(specNote, "—") != 1 || !strings.Contains(specNote, "\u2014") {
		t.Fatal("em dash lost in the source")
	}
	v := mustV(t, specVkey)
	if v.ID != 0x530d903a || v.VerifierKey() != specVkey {
		t.Fatalf("vkey round trip: %s", v.VerifierKey())
	}
	n, err := Open([]byte(specNote), v)
	if err != nil || string(n.Text) != "This is an example message.\n" {
		t.Fatalf("%v %+v", err, n)
	}
}

func TestXModVectors(t *testing.T) {
	s, err := ParseSignerKey(peterSkey)
	if err != nil {
		t.Fatal(err)
	}
	if s.SignerKey() != peterSkey || s.VerifierKey() != peterVkey {
		t.Fatal("key round trip")
	}
	got, err := Sign([]byte(peterText), s)
	if err != nil || string(got) != peterText+"\n"+peterSig {
		t.Fatalf("Sign:\n%s", got)
	}
	// Two signatures: the known one verifies, the unknown one is kept but untrusted.
	n, err := Open([]byte(peterText+"\n"+peterSig+enochSig), mustV(t, peterVkey))
	if err != nil || len(n.Sigs) != 2 || len(n.Verified) != 1 || n.Verified[0].Name != "PeterNeumann" {
		t.Fatalf("%v %+v", err, n)
	}
	if _, err := Open([]byte(peterText+"\n"+enochSig), mustV(t, peterVkey)); !errors.Is(err, ErrUnverified) {
		t.Fatalf("only unknown signer: %v", err)
	}
	if _, err := Open([]byte(peterText+"\n"+peterSig+enochSig), mustV(t, peterVkey), mustV(t, enochVkey)); err != nil {
		t.Fatal(err)
	}
}

// Interoperability with an independent implementation, both directions.
func TestAgainstXMod(t *testing.T) {
	skey, vkey, err := GenerateKey("shunya.test/log")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := ParseSignerKey(skey)
	text := []byte("shunya.test/log\n42\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	ours, _ := Sign(text, s)
	xv, err := xnote.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xnote.Open(ours, xnote.VerifierList(xv)); err != nil {
		t.Fatalf("x/mod rejects our note: %v", err)
	}
	xs, err := xnote.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	theirs, _ := xnote.Sign(&xnote.Note{Text: string(text)}, xs)
	if !bytes.Equal(theirs, ours) {
		t.Fatalf("x/mod signs differently:\n%s\n%s", theirs, ours)
	}
	xsk, xvk, _ := xnote.GenerateKey(nil, "other.example/key")
	if _, err := ParseSignerKey(xsk); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseVerifierKey(xvk); err != nil {
		t.Fatal(err)
	}
}

func TestRefusals(t *testing.T) {
	v := mustV(t, peterVkey)
	good := peterText + "\n" + peterSig
	flip := []byte(good)
	flip[3] ^= 1
	sigflip := strings.Replace(good, "pAcElZ", "pAcElY", 1)
	nonCanon := strings.Replace(good, "JnAM=", "JnAN=", 1) // non-zero padding bits
	cases := map[string]struct {
		msg  string
		want error
	}{
		"text changed":      {string(flip), ErrBadSig},
		"signature changed": {sigflip, ErrBadSig},
		"non-canonical b64": {nonCanon, ErrMalformed},
		"no blank line":     {peterText + peterSig, ErrMalformed},
		"no final newline":  {strings.TrimSuffix(good, "\n"), ErrMalformed},
		"hyphen not dash":   {strings.Replace(good, "—", "-", 1), ErrMalformed},
		"control char":      {"a\tb\n\n" + peterSig, ErrMalformed},
		"CR":                {strings.Replace(good, "\n", "\r\n", 1), ErrMalformed},
		"invalid utf-8":     {"\xff\n\n" + peterSig, ErrMalformed},
		"duplicate sig":     {good + peterSig, ErrMalformed},
		"empty text":        {"\n" + peterSig, ErrMalformed},
		"short sig":         {peterText + "\n— PeterNeumann AAAA\n", ErrMalformed},
		"too big":           {strings.Repeat("a", MaxSize) + "\n\n" + peterSig, ErrMalformed},
		"space in name":     {peterText + "\n— Peter Neumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n", ErrMalformed},
	}
	for name, c := range cases {
		if _, err := Open([]byte(c.msg), v); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	many := peterText + "\n" + peterSig
	for i := 0; i < MaxSigs; i++ {
		many += "— k" + strings.Repeat("x", i+1) + " AAAAAAAA\n"
	}
	if _, err := Open([]byte(many), v); !errors.Is(err, ErrMalformed) {
		t.Errorf("too many signatures: %v", err)
	}
	// Same name, different ID: a different key, ignored (not a failure of the known key).
	other := strings.Replace(peterVkey, "c74f20a3", "c74f20a4", 1)
	if _, err := ParseVerifierKey(other); err == nil {
		t.Error("vkey whose ID does not match its key accepted")
	}
	for _, k := range []string{"", "a+b", "a+c74f20a3+", "a b+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
		"PeterNeumann+C74F20A3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
		"PeterNeumann+c74f20a3+AhpczQcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"} {
		if _, err := ParseVerifierKey(k); err == nil {
			t.Errorf("vkey %q accepted", k)
		}
	}
	if _, err := ParseSignerKey(peterVkey); err == nil {
		t.Error("vkey accepted as signer key")
	}
	s, _ := ParseSignerKey(peterSkey)
	for _, txt := range []string{"", "no newline", "a\n\n", "tab\t\n"} {
		if _, err := Sign([]byte(txt), s); err == nil {
			t.Errorf("signed %q", txt)
		}
	}
	if _, err := NewSigner("a+b", ed25519.NewKeyFromSeed(make([]byte, 32))); err == nil {
		t.Error("bad name")
	}
}

func FuzzOpen(f *testing.F) {
	f.Add([]byte(peterText + "\n" + peterSig + enochSig))
	f.Add([]byte(specNote))
	v, _ := ParseVerifierKey(peterVkey)
	xv, _ := xnote.NewVerifier(peterVkey)
	f.Fuzz(func(t *testing.T, msg []byte) {
		n, err := Open(msg, v)
		if err != nil {
			return
		}
		// Whatever we accept, the independent implementation accepts with the same text.
		xn, xerr := xnote.Open(msg, xnote.VerifierList(xv))
		if xerr != nil || xn.Text != string(n.Text) {
			t.Fatalf("x/mod disagrees: %v", xerr)
		}
	})
}
