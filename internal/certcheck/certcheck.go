// Package certcheck is the offline verification shared by shunya-verify and
// "shunya cert show": load the root public key and revocation list, verify the
// certificate, optionally check that a PDF is exactly its rendering, and report.
package certcheck

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"shunya/internal/cert"
	"shunya/internal/certpdf"
	"shunya/internal/keys"
)

// Options says what the verifier trusts and checks.
type Options struct {
	Root           string // root public key file, or its 64 hex digits
	Revocations    string // revocation list file
	SkipRevocation bool
	AllowDevKey    bool
	PDF            string // a PDF claimed to render this certificate
}

// Outcome is a successful verification.
type Outcome struct {
	*cert.Result
	RevocationList uint64 // number of the list checked (0: not checked)
	PDFChecked     bool
}

// ErrPDFMismatch: the PDF is not the rendering of the certificate.
var ErrPDFMismatch = errors.New("the PDF is not this certificate's rendering (edited, or made from another certificate)")

// Verify runs the full offline check of the certificate file at path.
func Verify(path string, o Options) (*Outcome, error) {
	file, err := readLimited(path, cert.MaxBytes)
	if err != nil {
		return nil, err
	}
	p := cert.Policy{SkipRevocation: o.SkipRevocation, AllowDevKey: o.AllowDevKey}
	if o.Root == "" {
		if !o.AllowDevKey {
			return nil, errors.New("--root is required (the organisation's root public key)")
		}
	} else {
		rootText := o.Root
		if b, err := os.ReadFile(o.Root); err == nil {
			rootText = string(b)
		} else if len(strings.TrimSpace(o.Root)) != 64 {
			return nil, fmt.Errorf("root key: %w", err)
		}
		if p.Root, err = keys.ParsePublic(rootText); err != nil {
			return nil, fmt.Errorf("root key: %w", err)
		}
	}
	out := &Outcome{}
	if o.Revocations != "" {
		raw, err := readLimited(o.Revocations, 4<<20)
		if err != nil {
			return nil, err
		}
		l, err := keys.ParseRevocationList(raw, p.Root)
		if err != nil {
			return nil, err
		}
		p.Revocations, out.RevocationList = &l, l.Number
	}
	r, err := cert.Verify(file, p)
	if err != nil {
		return nil, err
	}
	out.Result = r
	if o.PDF != "" {
		got, err := readLimited(o.PDF, 16<<20)
		if err != nil {
			return nil, err
		}
		want, err := certpdf.Render(r.Certificate, r.ID)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, want) {
			if !bytes.Contains(got, []byte(fmt.Sprintf("certificate layout %d)", certpdf.Layout))) {
				return nil, fmt.Errorf("%w; it was not made by certificate layout %d, so it cannot be compared: rely on the JSON", ErrPDFMismatch, certpdf.Layout)
			}
			return nil, ErrPDFMismatch
		}
		out.PDFChecked = true
	}
	return out, nil
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, max)
	}
	return b, nil
}

// Print writes a human-readable verdict.
func Print(w io.Writer, o *Outcome) {
	c := o.Certificate
	trust := "UNCERTIFIED development key " + c.Station.KeyID
	if sc := c.Station.Certificate; sc != nil {
		trust = "station " + c.Station.Name + " (" + c.Station.KeyID + "), certified by root " + sc.Issuer
	}
	fmt.Fprintf(w, "VALID certificate %s\n", o.ID)
	fmt.Fprintf(w, "  device       %s, serial %s, %d bytes (%s%s)\n", orDash(c.Device.Model), orDash(c.Device.Serial), c.Device.SizeBytes, c.Device.Media, virt(c.Device.Virtual))
	fmt.Fprintf(w, "  erasure      %s, NIST SP 800-88 %s, finished %s\n", c.Erasure.Method, strings.ToUpper(c.Erasure.NISTLevel), c.Erasure.Finished)
	modes := []string{}
	for _, v := range c.Verification {
		modes = append(modes, v.Mode)
	}
	fmt.Fprintf(w, "  verified     %s (all passed); %d interruption(s)\n", strings.Join(modes, ", "), len(c.Interruptions))
	fmt.Fprintf(w, "  signed by    %s, issued %s\n", trust, c.Issued)
	if o.RevocationList > 0 {
		fmt.Fprintf(w, "  revocation   not revoked in list %d\n", o.RevocationList)
	}
	if o.PDFChecked {
		fmt.Fprintln(w, "  pdf          is exactly this certificate's rendering")
	}
	for _, warn := range o.Warnings {
		fmt.Fprintln(w, "  WARNING     ", warn)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func virt(v bool) string {
	if v {
		return ", virtual"
	}
	return ""
}
