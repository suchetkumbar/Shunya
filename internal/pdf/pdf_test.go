package pdf

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strconv"
	"testing"
)

func sampleDoc() []byte {
	d := &Doc{Title: "Test (1)", Producer: "shunya test", Created: "D:20261101000000Z"}
	p := d.NewPage()
	p.Text(50, 800, HelveticaBold, 18, "Certificate (draft) \\ é € 😀")
	p.Rect(50, 700, 10, 10)
	p.Gray(0.5)
	p.Line(50, 690, 300, 690, 0.5)
	d.NewPage().Text(50, 800, Courier, 9, "page two")
	return d.Bytes()
}

// TestStructure checks what a PDF reader relies on: the header, every xref offset
// pointing at its object, stream lengths, and the startxref pointer.
func TestStructure(t *testing.T) {
	b := sampleDoc()
	if !bytes.HasPrefix(b, []byte("%PDF-1.7\n")) || !bytes.HasSuffix(b, []byte("%%EOF\n")) {
		t.Fatal("header/trailer")
	}
	m := regexp.MustCompile(`startxref\n(\d+)\n%%EOF\n$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("no startxref")
	}
	xref, _ := strconv.Atoi(string(m[1]))
	if !bytes.HasPrefix(b[xref:], []byte("xref\n0 ")) {
		t.Fatalf("startxref %d does not point at the xref table", xref)
	}
	entries := regexp.MustCompile(`(\d{10}) 00000 n \n`).FindAllSubmatch(b[xref:], -1)
	if len(entries) != 10 { // catalog, pages, 3 fonts, info, 2×(page, content)
		t.Fatalf("%d objects", len(entries))
	}
	for i, e := range entries {
		off, _ := strconv.Atoi(string(e[1]))
		if want := fmt.Sprintf("%d 0 obj\n", i+1); !bytes.HasPrefix(b[off:], []byte(want)) {
			t.Errorf("object %d offset %d: %q", i+1, off, b[off:off+12])
		}
	}
	for _, s := range regexp.MustCompile(`(?s)/Length (\d+) >>\nstream\n(.*?)endstream`).FindAllSubmatch(b, -1) {
		if n, _ := strconv.Atoi(string(s[1])); n != len(s[2]) {
			t.Errorf("stream length %d, actual %d", n, len(s[2]))
		}
	}
	// Text escaping: parentheses and backslash escaped, é as WinAnsi \351, € as \200,
	// the emoji (not in WinAnsi) spelt out.
	if !bytes.Contains(b, []byte(`(Certificate \(draft\) \\ \351 \200 <U+1F600>) Tj`)) {
		t.Errorf("text: %s", b)
	}
	if !bytes.Contains(b, []byte("/Title (Test \\(1\\))")) || !bytes.Contains(b, []byte("/CreationDate (D:20261101000000Z)")) {
		t.Error("info")
	}
}

func TestDeterministic(t *testing.T) {
	a, b := sampleDoc(), sampleDoc()
	if !bytes.Equal(a, b) {
		t.Fatal("two renders differ")
	}
	// Golden hash: a change to the writer's output must be deliberate (and is a new
	// layout: old PDFs then no longer re-render identically).
	if h := fmt.Sprintf("%x", sha256.Sum256(a)); h != goldenHash {
		t.Errorf("output changed: sha256 %s", h)
	}
}

const goldenHash = "36b7f9b29e4b12738461a23e4ef707982c30ea832a7a98e103a05bf019ce4760"

func TestEncode(t *testing.T) {
	if got := string(Encode("a\x01b ÿĀ")); got != "a<U+0001>b\xa0\xff<U+0100>" {
		t.Errorf("%q", got)
	}
	if CourierWidth(10, 10) != 60 || EncodedLen("é😀") != 1+9 {
		t.Error("widths")
	}
}
