package certpdf

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"shunya/internal/cert"
	"shunya/internal/keys"
	"shunya/internal/pdf"
	"shunya/internal/qr"
)

const id = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func sample(dev bool) cert.Certificate {
	c := cert.Certificate{
		Format: cert.Format, Version: 1, WipeID: "0123456789abcdef0123456789abcdef", Issued: "2026-11-01T10:06:00Z",
		Result: cert.ResultErasedVerified,
		Tool:   cert.Tool{Wipe: "shunya 0.7.0-dev", Issuer: "shunya 0.7.0-dev", IssuerBuildHash: strings.Repeat("cd", 32), Build: "dev"},
		Device: cert.Device{Path: "/dev/sdb", Model: "QEMU HARDDISK", Serial: "lab-é-(1)", SizeBytes: 1 << 30,
			Fingerprint: "fp2:" + strings.Repeat("0", 64), Media: "hdd", Virtual: true},
		Erasure: cert.Erasure{Method: "overwrite", NISTLevel: "clear", Passes: []string{"random"}, SizeBytes: 1 << 30, SectorSize: 512,
			Started: "2026-11-01T10:00:00Z", Finished: "2026-11-01T10:05:00Z",
			Notes: []string{"Clear only: overwriting cannot reach remapped sectors or spare blocks, which a firmware erase would."}},
		Hidden:       cert.Hidden{Checked: true, HPA: true, HPASectors: 2048, Wiped: true, DCO: "not-supported", Policy: "restore", Final: "hpa-restored"},
		Verification: []cert.Verification{{Mode: "full", Pattern: "random", OK: true, BytesRead: 1 << 30}},
		Journal:      cert.Journal{SHA256: strings.Repeat("11", 32), Records: 12, KeyID: "ed25519:1111111111111111"},
		Station:      cert.Station{KeyID: "ed25519:1111111111111111", Name: "bay-3", Certificate: &keys.StationCert{Issuer: "ed25519:2222222222222222", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"}},
		VerifyURL:    cert.DefaultVerifyURL,
	}
	if dev {
		c.Station = cert.Station{KeyID: "ed25519:1111111111111111"}
	}
	return c
}

// text returns the literal strings drawn on the pages, decoded from PDF escapes.
func text(b []byte) string {
	var s strings.Builder
	for _, m := range regexp.MustCompile(`\(((?:[^()\\]|\\.)*)\) Tj`).FindAllSubmatch(b, -1) {
		u := regexp.MustCompile(`\\([0-7]{3}|.)`).ReplaceAllFunc(m[1], func(e []byte) []byte {
			if len(e) == 4 {
				n, _ := strconv.ParseUint(string(e[1:]), 8, 8)
				return []byte(string(rune(n))) // WinAnsi = Latin-1 for these
			}
			return e[1:]
		})
		s.Write(u)
		s.WriteByte('\n')
	}
	return s.String()
}

func TestRender(t *testing.T) {
	c := sample(false)
	a, err := Render(c, id)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Render(c, id)
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	txt := text(a)
	for _, want := range []string{id, "lab-é-(1)", "QEMU HARDDISK", "CLEAR", "overwrite", "bay-3", "hpa-restored",
		"2048 sectors, removed for the wipe and erased", "full read-back of 1.0 GiB", "1073741824 bytes", cert.DefaultVerifyURL,
		"2026-11-01T10:06:00Z", "not recorded (journal predates Milestone 7)"} {
		if !strings.Contains(txt, want) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.Contains(txt, "page 1 of 1") {
		t.Errorf("a typical certificate should fit one page: %d", strings.Count(string(a), "/Type /Page /Parent"))
	}
	if strings.Contains(txt, "UNCERTIFIED") {
		t.Error("dev banner on a certified certificate")
	}
	if !bytes.Contains(a, []byte("/CreationDate (D:20261101100600Z)")) {
		t.Error("creation date not taken from the certificate")
	}
	// A changed field changes the PDF.
	c.Device.Serial = "lab-2"
	if d, _ := Render(c, id); bytes.Equal(d, a) {
		t.Error("PDF ignores the serial")
	}
	dev, _ := Render(sample(true), id)
	if !strings.Contains(text(dev), "UNCERTIFIED DEVELOPMENT KEY") {
		t.Error("no dev banner")
	}
}

// TestQRMatchesPayload rebuilds the module grid from the drawn rectangles and
// compares it with the QR encoding of URL + ID (the encoder itself is checked by
// internal/qr and, rendered, by zbarimg in the lab).
func TestQRMatchesPayload(t *testing.T) {
	c := sample(false)
	b, _ := Render(c, id)
	code, _ := qr.Encode([]byte(c.VerifyURL + id))
	const mod = 2.5
	re := regexp.MustCompile(`(?m)^([\d.]+) ([\d.]+) ([\d.]+) 2\.5 re f$`)
	rects := re.FindAllSubmatch(b, -1)
	if len(rects) == 0 {
		t.Fatal("no QR modules drawn")
	}
	var minX, maxY float64 = 1e9, 0
	type r struct{ x, y, w float64 }
	var rs []r
	for _, m := range rects {
		x, _ := strconv.ParseFloat(string(m[1]), 64)
		y, _ := strconv.ParseFloat(string(m[2]), 64)
		w, _ := strconv.ParseFloat(string(m[3]), 64)
		rs = append(rs, r{x, y, w})
		minX, maxY = min(minX, x), max(maxY, y)
	}
	grid := make([]bool, code.Size*code.Size)
	for _, q := range rs {
		col := int((q.x-minX)/mod + 0.5)
		row := int((maxY-q.y)/mod + 0.5)
		for k := 0; k < int(q.w/mod+0.5); k++ {
			grid[row*code.Size+col+k] = true
		}
	}
	// The top-left finder sits at the minimum x and maximum y, so offsets align.
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if grid[y*code.Size+x] != code.Black(x, y) {
				t.Fatalf("module %d,%d differs", x, y)
			}
		}
	}
}

func TestWrapAndPages(t *testing.T) {
	for _, s := range []string{strings.Repeat("x", 200), strings.Repeat("ab ", 70), strings.Repeat("é😀", 40), "short"} {
		lines := wrap(s, valueChars)
		var joined strings.Builder
		for _, l := range lines {
			if pdf.EncodedLen(l) > valueChars {
				t.Errorf("line too long: %q", l)
			}
			joined.WriteString(l)
		}
		if strings.ReplaceAll(joined.String(), " ", "") != strings.ReplaceAll(s, " ", "") {
			t.Errorf("wrap lost text: %q", s)
		}
	}
	c := sample(false)
	for range 80 {
		c.Verification = append(c.Verification, cert.Verification{Mode: "sampled", OK: true, Samples: 100, Seed: "ab", SeedSource: "operator"})
	}
	b, _ := Render(c, id)
	if n := strings.Count(string(b), "/Type /Page /Parent"); n < 2 || !strings.Contains(text(b), "page 2 of "+strconv.Itoa(n)) {
		t.Errorf("%d pages", n)
	}
}
