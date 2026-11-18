// Package certpdf renders an erasure certificate as a printable PDF with a QR code.
//
// The PDF is a pure function of the certificate body and its ID: it carries no data of
// its own, so it can never disagree with the JSON. A verifier re-renders the PDF from a
// verified certificate and compares bytes (shunya-verify --pdf). The layout is
// versioned (Layout); a PDF made by a different layout version does not compare equal
// and is checked against its JSON instead.
package certpdf

import (
	"fmt"
	"strings"

	"shunya/internal/cert"
	"shunya/internal/pdf"
	"shunya/internal/qr"
)

// Layout is the rendering version (part of the PDF's Producer string).
const Layout = 1

const (
	left    = 50.0
	valueX  = 185.0
	right   = 545.0
	top     = 800.0
	bottom  = 70.0
	size    = 9.0
	leading = 10.5
)

var valueChars = int((right - valueX) / pdf.CourierWidth(1, size))

type layout struct {
	d *pdf.Doc
	p *pdf.Page
	y float64
}

func (l *layout) need(h float64) {
	if l.y-h < bottom {
		l.p = l.d.NewPage()
		l.y = top
	}
}

func (l *layout) heading(s string) {
	l.need(3 * leading)
	l.y -= leading * 0.5
	l.p.Text(left, l.y, pdf.HelveticaBold, 11, s)
	l.p.Gray(0.6)
	l.p.Line(left, l.y-3, right, l.y-3, 0.5)
	l.p.Gray(0)
	l.y -= leading * 1.25
}

// row writes a label and a value, wrapping the value in the Courier column.
func (l *layout) row(label, value string) {
	lines := wrap(value, valueChars)
	l.need(float64(len(lines)) * leading)
	l.p.Text(left, l.y, pdf.HelveticaBold, size, label)
	for _, s := range lines {
		l.p.Text(valueX, l.y, pdf.Courier, size, s)
		l.y -= leading
	}
}

// wrap splits s into lines of at most n encoded glyphs, on rune boundaries, preferring
// to break after a space.
func wrap(s string, n int) []string {
	if s == "" {
		return []string{"-"}
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		for pdf.EncodedLen(para) > n {
			cut, w, lastSpace, spaceW := 0, 0, -1, 0
			for i, r := range para {
				rw := pdf.EncodedLen(string(r))
				if w+rw > n {
					break
				}
				w += rw
				cut = i + len(string(r))
				if r == ' ' {
					lastSpace, spaceW = cut, w
				}
			}
			if lastSpace > 0 && spaceW > n/2 { // break at a space unless it wastes half the line
				cut = lastSpace
			}
			if cut == 0 { // one glyph wider than the line: cannot happen with n ≥ 9
				cut = len(string([]rune(para)[0]))
			}
			out = append(out, strings.TrimRight(para[:cut], " "))
			para = para[cut:]
		}
		out = append(out, para)
	}
	return out
}

// Render draws the certificate. id is cert.ID of the body.
func Render(c cert.Certificate, id string) ([]byte, error) {
	code, err := qr.Encode([]byte(c.VerifyURL + id))
	if err != nil {
		return nil, err
	}
	d := &pdf.Doc{
		Title:    "Erasure certificate " + id[:16],
		Producer: fmt.Sprintf("%s (certificate layout %d)", c.Tool.Issuer, Layout),
		Created:  pdfDate(c.Issued),
	}
	l := &layout{d: d, p: d.NewPage(), y: top}

	// Header, with the QR code on the right.
	l.p.Text(left, top, pdf.HelveticaBold, 20, "Certificate of Data Erasure")
	l.p.Text(left, top-22, pdf.Helvetica, 12, "NIST SP 800-88 Rev. 1 sanitization level: "+strings.ToUpper(c.Erasure.NISTLevel))
	l.p.Text(left, top-38, pdf.Helvetica, 12, "Result: "+strings.ReplaceAll(c.Result, "-", " "))
	if c.Station.Certificate == nil {
		l.p.Text(left, top-56, pdf.HelveticaBold, 10, "UNCERTIFIED DEVELOPMENT KEY - not a trusted certificate")
	}
	const mod = 2.5
	qrSide := float64(code.Size+8) * mod
	qx, qy := right-qrSide, top+14-qrSide // top edge (with quiet zone) level with the title
	drawQR(l.p, code, qx+4*mod, qy+4*mod, mod)
	l.p.Text(qx+4*mod, qy-2, pdf.Helvetica, 7, "Scan to verify this certificate")
	l.y = min(qy-20, top-80)

	l.heading("Certificate")
	l.row("Certificate ID", id)
	l.row("Issued", c.Issued)
	l.row("Wipe ID", c.WipeID)
	l.row("Verify at", c.VerifyURL+id)

	dv := c.Device
	l.heading("Device")
	l.row("Model", dv.Model)
	l.row("Serial number", dv.Serial)
	if dv.WWID != "" {
		l.row("WWID", dv.WWID)
	}
	l.row("Capacity", fmt.Sprintf("%s (%d bytes)", human(dv.SizeBytes), dv.SizeBytes))
	media := dv.Media
	if dv.Virtual {
		media += " (virtual disk)"
	}
	l.row("Media", media)
	l.row("Device path", dv.Path)
	l.row("Fingerprint", dv.Fingerprint)
	if dv.NativeFingerprint != "" {
		l.row("Native fingerprint", dv.NativeFingerprint)
	}

	e := c.Erasure
	l.heading("Erasure")
	l.row("Method", e.Method)
	l.row("NIST level", strings.ToUpper(e.NISTLevel))
	if len(e.Passes) > 0 {
		l.row("Passes", fmt.Sprintf("%d: %s", len(e.Passes), strings.Join(e.Passes, ", ")))
	}
	l.row("Erased", fmt.Sprintf("%s (%d bytes, %d-byte sectors)", human(e.SizeBytes), e.SizeBytes, e.SectorSize))
	l.row("Started", e.Started)
	l.row("Finished", e.Finished)
	for i, s := range e.Steps {
		l.row(label(i, "Steps"), strings.TrimSuffix(s.Step+": "+s.Detail, ": "))
	}
	for i, n := range e.Notes {
		l.row(label(i, "Notes"), n)
	}

	h := c.Hidden
	l.heading("Hidden areas (HPA / DCO)")
	switch {
	case !h.Checked:
		l.row("Checked", "no: "+h.Reason)
	default:
		hpa := "none"
		if h.HPA {
			hpa = fmt.Sprintf("%d sectors", h.HPASectors)
			if h.Wiped {
				hpa += ", removed for the wipe and erased"
			} else {
				hpa += ", NOT erased: " + h.KeepReason
			}
		}
		l.row("HPA", hpa)
		dco := h.DCO
		if h.DCOSectors > 0 {
			dco += fmt.Sprintf(" (%d sectors)", h.DCOSectors)
		}
		l.row("DCO", dco)
		if h.Policy != "" {
			l.row("HPA policy", h.Policy)
		}
		if h.Final != "" {
			l.row("Final state", h.Final)
		}
	}

	l.heading("Verification")
	for i, v := range c.Verification {
		l.row(label(i, "Checks"), verification(v))
	}

	l.heading("Interruptions")
	if len(c.Interruptions) == 0 {
		l.row("Interruptions", "none")
	}
	for i, in := range c.Interruptions {
		s := fmt.Sprintf("%s at pass %d, byte %d; stopped %s, resumed %s", in.Kind, in.Pass+1, in.Offset, orDash(in.StoppedAt), orDash(in.ResumedAt))
		if in.Reason != "" {
			s += " (" + in.Reason + ")"
		}
		l.row(label(i, "Interruptions"), s)
	}

	st := c.Station
	l.heading("Signed by")
	if sc := st.Certificate; sc != nil {
		l.row("Station", st.Name)
		l.row("Station key", st.KeyID)
		l.row("Certified by root", sc.Issuer)
		l.row("Station valid", sc.NotBefore+" to "+sc.NotAfter)
	} else {
		l.row("Station", "uncertified development key")
		l.row("Station key", st.KeyID)
	}
	l.row("Journal SHA-256", c.Journal.SHA256)
	l.row("Journal records", fmt.Sprint(c.Journal.Records))
	l.row("Wiped with", c.Tool.Wipe)
	l.row("Wipe build", orNot(c.Tool.WipeBuildHash))
	l.row("Issued with", c.Tool.Issuer+" ("+c.Tool.Build+" build)")
	l.row("Issuer build", orNot(c.Tool.IssuerBuildHash))

	// Footer on every page.
	n := len(d.Pages())
	for i, p := range d.Pages() {
		p.Gray(0.35)
		p.Text(left, 52, pdf.Helvetica, 7, "This page is rendered from the signed JSON certificate, which is authoritative. Verify offline:")
		p.Text(left, 43, pdf.Courier, 7, "shunya-verify --root ROOT.pub --revocations REVOCATIONS.json CERT.json --pdf THIS.pdf")
		p.Text(left, 34, pdf.Helvetica, 7, fmt.Sprintf("Certificate %s  -  page %d of %d", id, i+1, n))
		p.Gray(0)
	}
	return d.Bytes(), nil
}

// drawQR fills the dark modules, one rectangle per horizontal run.
func drawQR(p *pdf.Page, c *qr.Code, x0, y0, mod float64) {
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; {
			if !c.Black(x, y) {
				x++
				continue
			}
			run := 1
			for x+run < c.Size && c.Black(x+run, y) {
				run++
			}
			// PDF y grows upwards: module row y is drawn from the top of the symbol.
			p.Rect(x0+float64(x)*mod, y0+float64(c.Size-1-y)*mod, float64(run)*mod, mod)
			x += run
		}
	}
}

func verification(v cert.Verification) string {
	var s string
	switch v.Mode {
	case "full":
		s = fmt.Sprintf("full read-back of %s: pattern %s, %d bad sectors", human(v.BytesRead), v.Pattern, v.BadSectors)
	case "sampled":
		s = fmt.Sprintf("%d random samples (%s read): pattern %s, %d bad; seed %s (%s); 95%% bound on unwritten fraction %.3g",
			v.Samples, human(v.BytesRead), v.Pattern, v.BadSectors, v.Seed, v.SeedSource, v.Bound95)
	case "markers":
		s = fmt.Sprintf("marker check: none of the planted marker sectors (%s) read back", human(v.BytesRead))
	default:
		s = v.Mode
	}
	if v.Scope != "" {
		s += "; scope: " + v.Scope
	}
	return "passed - " + s
}

func label(i int, s string) string {
	if i == 0 {
		return s
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orNot(s string) string {
	if s == "" {
		return "not recorded (journal predates Milestone 7)"
	}
	return s
}

// pdfDate turns "2026-11-01T10:00:00Z" into "D:20261101100000Z".
func pdfDate(rfc string) string {
	s := strings.NewReplacer("-", "", ":", "", "T", "").Replace(rfc)
	if len(s) != 15 || !strings.HasSuffix(s, "Z") {
		return ""
	}
	return "D:" + s
}

func human(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
