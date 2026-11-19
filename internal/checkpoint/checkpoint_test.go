package checkpoint

import (
	"errors"
	"strings"
	"testing"

	xtlog "golang.org/x/mod/sumdb/tlog"

	"shunya/internal/note"
	"shunya/internal/tlog"
)

func signer(t *testing.T, name string) *note.Signer {
	skey, _, err := note.GenerateKey(name)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := note.ParseSignerKey(skey)
	return s
}

// The spec's example text parses; our text for it is byte-identical; x/mod's tree
// format (the same three lines) agrees.
func TestFormat(t *testing.T) {
	spec := "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
	c, err := ParseText([]byte(spec))
	if err != nil || c.Size != 20852163 || c.Origin != "example.com/behind-the-sofa" {
		t.Fatalf("%v %+v", err, c)
	}
	if string(c.Text()) != spec {
		t.Fatalf("text %q", c.Text())
	}
	xt, err := xtlog.ParseTree([]byte("go.sum database tree\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"))
	if err != nil || tlog.Hash(xt.Hash) != c.Root || uint64(xt.N) != c.Size {
		t.Fatalf("x/mod: %v", err)
	}
}

func TestSignOpen(t *testing.T) {
	s := signer(t, "shunya.test/log")
	c := Checkpoint{Origin: "shunya.test/log", Size: 7, Root: tlog.LeafHash([]byte("x"))}
	signed, err := Sign(c, s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(signed, &s.Verifier)
	if err != nil || got != c {
		t.Fatalf("%v %+v", err, got)
	}
	other := signer(t, "shunya.test/log")
	if _, err := Open(signed, &other.Verifier); !errors.Is(err, note.ErrUnverified) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := Sign(c, signer(t, "elsewhere/log")); err == nil {
		t.Fatal("signed with a key not named after the origin")
	}
	// A key named after another origin cannot vouch for this one even if it signed it.
	wrong := signer(t, "elsewhere/log")
	txt, _ := note.Sign(c.Text(), wrong)
	if _, err := Open(txt, &wrong.Verifier); !errors.Is(err, ErrMalformed) {
		t.Fatalf("origin/key mismatch: %v", err)
	}
}

func TestParseRefusals(t *testing.T) {
	root := "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="
	for _, txt := range []string{
		"o\n1\n" + root,                                        // no final newline
		"o\n01\n" + root + "\n",                                // leading zero
		"o\n-1\n" + root + "\n",                                // negative
		"o\n+1\n" + root + "\n",                                // sign
		"o\n\n" + root + "\n",                                  // empty size
		"\n1\n" + root + "\n",                                  // empty origin
		"o o\n1\n" + root + "\n",                               // space in origin
		"o\n1\n" + root[:40] + "=\n",                           // short hash
		"o\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2J=\n", // non-canonical base64
		"o\n1\n" + root + "\next\n",                            // extension line
		"o\n1\n" + root + "\n\n",                               // blank line
		"o\n18446744073709551616\n" + root + "\n",
	} {
		if _, err := ParseText([]byte(txt)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", strings.ReplaceAll(txt, "\n", `\n`), err)
		}
	}
}

func FuzzParseText(f *testing.F) {
	f.Add([]byte("example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseText(b)
		if err != nil {
			return
		}
		if string(c.Text()) != string(b) {
			t.Fatalf("accepted a non-canonical checkpoint %q", b)
		}
	})
}
