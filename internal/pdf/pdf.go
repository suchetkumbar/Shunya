// Package pdf writes small, deterministic PDF 1.7 documents: text in the standard
// Helvetica and Courier fonts (WinAnsiEncoding, not embedded) and filled rectangles.
// The same calls always produce the same bytes — no timestamps or random IDs unless
// the caller supplies them — so a PDF rendered from a certificate can be re-rendered
// and compared byte for byte.
//
// Coordinates are PDF points (1/72 inch), origin at the bottom-left of the page.
package pdf

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// A4 page size in points.
const (
	A4Width  = 595.28
	A4Height = 841.89
)

// Font is one of the standard fonts.
type Font int

const (
	Helvetica Font = iota
	HelveticaBold
	Courier
)

var fontNames = [...]string{"Helvetica", "Helvetica-Bold", "Courier"}

// Doc is a document under construction.
type Doc struct {
	pages []*Page
	Title string
	// Producer and Created (a PDF date "D:20261101000000Z") go into the Info dictionary.
	Producer, Created string
}

// Page is one page's content stream.
type Page struct{ buf bytes.Buffer }

// Pages returns the pages so far.
func (d *Doc) Pages() []*Page { return d.pages }

// NewPage appends an A4 page.
func (d *Doc) NewPage() *Page {
	p := &Page{}
	d.pages = append(d.pages, p)
	return p
}

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// Text draws s with its baseline starting at (x, y).
func (p *Page) Text(x, y float64, f Font, size float64, s string) {
	fmt.Fprintf(&p.buf, "BT /F%d %s Tf %s %s Td (%s) Tj ET\n", int(f)+1, num(size), num(x), num(y), escape(Encode(s)))
}

// Rect fills a black rectangle with its lower-left corner at (x, y).
func (p *Page) Rect(x, y, w, h float64) {
	fmt.Fprintf(&p.buf, "%s %s %s %s re f\n", num(x), num(y), num(w), num(h))
}

// Line strokes a line of the given width.
func (p *Page) Line(x1, y1, x2, y2, width float64) {
	fmt.Fprintf(&p.buf, "%s w %s %s m %s %s l S\n", num(width), num(x1), num(y1), num(x2), num(y2))
}

// Gray sets the fill and stroke grey level (0 black … 1 white) for what follows.
func (p *Page) Gray(g float64) {
	fmt.Fprintf(&p.buf, "%s g %s G\n", num(g), num(g))
}

// CourierWidth is the advance of n Courier characters at size (every glyph is 600/1000 em).
func CourierWidth(n int, size float64) float64 { return float64(n) * 0.6 * size }

// winAnsi maps the non-Latin-1 characters of WinAnsiEncoding (0x80–0x9F).
var winAnsi = map[rune]byte{
	'€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87, 'ˆ': 0x88, '‰': 0x89,
	'Š': 0x8a, '‹': 0x8b, 'Œ': 0x8c, 'Ž': 0x8e, '‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95,
	'–': 0x96, '—': 0x97, '˜': 0x98, '™': 0x99, 'š': 0x9a, '›': 0x9b, 'œ': 0x9c, 'ž': 0x9e, 'Ÿ': 0x9f,
}

// Encode converts s to WinAnsiEncoding bytes. Characters the encoding lacks (and
// control characters) are written as "<U+XXXX>", so nothing is silently dropped; the
// certificate's JSON keeps the exact text.
func Encode(s string) []byte {
	var b []byte
	for _, r := range s {
		switch {
		case r >= 0x20 && r < 0x7f, r >= 0xa0 && r <= 0xff:
			b = append(b, byte(r))
		case winAnsi[r] != 0:
			b = append(b, winAnsi[r])
		default:
			b = append(b, fmt.Sprintf("<U+%04X>", r)...)
		}
	}
	return b
}

// EncodedLen is the number of glyphs s takes once encoded.
func EncodedLen(s string) int { return len(Encode(s)) }

// escape makes bytes safe inside a PDF literal string.
func escape(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		switch {
		case c == '(' || c == ')' || c == '\\':
			s.WriteByte('\\')
			s.WriteByte(c)
		case c >= 0x20 && c < 0x7f:
			s.WriteByte(c)
		default:
			fmt.Fprintf(&s, "\\%03o", c)
		}
	}
	return s.String()
}

// textString encodes an Info dictionary string (ASCII; anything else escaped).
func textString(s string) string { return "(" + escape(Encode(s)) + ")" }

// Bytes serializes the document.
func (d *Doc) Bytes() []byte {
	var out bytes.Buffer
	var offsets []int
	obj := func(body string) int {
		offsets = append(offsets, out.Len())
		n := len(offsets)
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", n, body)
		return n
	}
	out.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	// Fixed numbering: 1 catalog, 2 pages, 3–5 fonts, 6 info, then page/content pairs.
	first := 7
	kids := make([]string, len(d.pages))
	for i := range d.pages {
		kids[i] = fmt.Sprintf("%d 0 R", first+2*i)
	}
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(d.pages)))
	for _, name := range fontNames {
		obj("<< /Type /Font /Subtype /Type1 /BaseFont /" + name + " /Encoding /WinAnsiEncoding >>")
	}
	info := "<< /Title " + textString(d.Title) + " /Producer " + textString(d.Producer)
	if d.Created != "" {
		info += " /CreationDate " + textString(d.Created)
	}
	obj(info + " >>")
	for i, p := range d.pages {
		obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>",
			num(A4Width), num(A4Height), first+2*i+1))
		obj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", p.buf.Len(), p.buf.Bytes()))
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, o := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)
	return out.Bytes()
}
