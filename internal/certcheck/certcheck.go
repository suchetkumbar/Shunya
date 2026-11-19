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
	"path/filepath"
	"strings"

	"shunya/internal/cert"
	"shunya/internal/certpdf"
	"shunya/internal/keys"
	"shunya/internal/manifest"
	"shunya/internal/note"
)

// Options says what the verifier trusts and checks.
type Options struct {
	Root           string // root public key file, or its 64 hex digits
	Revocations    string // revocation list file
	SkipRevocation bool
	AllowDevKey    bool
	PDF            string // a PDF claimed to render this certificate
	LogKey         string // the transparency log's verifier key file, or the key itself
	RequireLog     bool   // refuse certificates without a verified log inclusion proof
}

// ReadLogKey reads a log verifier key from a file, or takes s as the key itself.
func ReadLogKey(s string) (*note.Verifier, error) {
	text := s
	if b, err := os.ReadFile(s); err == nil {
		text = string(b)
	} else if !strings.Contains(s, "+") {
		return nil, fmt.Errorf("log key: %w", err)
	}
	v, err := note.ParseVerifierKey(text)
	if err != nil {
		return nil, fmt.Errorf("log key: %w", err)
	}
	return v, nil
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
	p, n, err := o.Policy()
	if err != nil {
		return nil, err
	}
	out := &Outcome{RevocationList: n}
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

// Policy loads the root key, revocation list and log key the options name, and returns
// the revocation list's number (0: none given).
func (o Options) Policy() (cert.Policy, uint64, error) {
	var err error
	p := cert.Policy{SkipRevocation: o.SkipRevocation, AllowDevKey: o.AllowDevKey, RequireLog: o.RequireLog}
	if o.LogKey != "" {
		if p.LogKey, err = ReadLogKey(o.LogKey); err != nil {
			return p, 0, err
		}
	}
	if o.Root == "" {
		if !o.AllowDevKey {
			return p, 0, errors.New("--root is required (the organisation's root public key)")
		}
	} else {
		rootText := o.Root
		if b, err := os.ReadFile(o.Root); err == nil {
			rootText = string(b)
		} else if len(strings.TrimSpace(o.Root)) != 64 {
			return p, 0, fmt.Errorf("root key: %w", err)
		}
		if p.Root, err = keys.ParsePublic(rootText); err != nil {
			return p, 0, fmt.Errorf("root key: %w", err)
		}
	}
	if o.Revocations == "" {
		return p, 0, nil
	}
	raw, err := readLimited(o.Revocations, 4<<20)
	if err != nil {
		return p, 0, err
	}
	l, err := keys.ParseRevocationList(raw, p.Root)
	if err != nil {
		return p, 0, err
	}
	p.Revocations = &l
	return p, l.Number, nil
}

// ManifestOutcome is a verified batch manifest and the certificates checked with it.
type ManifestOutcome struct {
	*manifest.Result
	RevocationList uint64
	Certificates   []*cert.Result
	// Problems lists certified devices whose certificate is missing or does not match;
	// Invalid lists certificate files that did not verify. Both empty: complete.
	Problems []string
	Invalid  []string
}

// Complete: every certified device has a matching, valid certificate.
func (m *ManifestOutcome) Complete() bool { return len(m.Problems) == 0 && len(m.Invalid) == 0 }

// VerifyManifest checks a batch manifest, then each certificate file given (files, or
// every *.cert.json in a directory) and matches them against the manifest.
func VerifyManifest(path string, certs []string, o Options) (*ManifestOutcome, error) {
	file, err := readLimited(path, manifest.MaxBytes)
	if err != nil {
		return nil, err
	}
	p, n, err := o.Policy()
	if err != nil {
		return nil, err
	}
	r, err := manifest.Verify(file, p)
	if err != nil {
		return nil, err
	}
	out := &ManifestOutcome{Result: r, RevocationList: n}
	var files []string
	for _, c := range certs {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			m, _ := filepath.Glob(filepath.Join(c, "*.cert.json"))
			files = append(files, m...)
			continue
		}
		files = append(files, c)
	}
	for _, f := range files {
		b, err := readLimited(f, cert.MaxBytes)
		if err == nil {
			var cr *cert.Result
			if cr, err = cert.Verify(b, p); err == nil {
				out.Certificates = append(out.Certificates, cr)
				continue
			}
		}
		out.Invalid = append(out.Invalid, fmt.Sprintf("%s: %v", f, err))
	}
	out.Problems = r.CheckCertificates(out.Certificates)
	return out, nil
}

// PrintManifest summarises a manifest check.
func PrintManifest(w io.Writer, m *ManifestOutcome) {
	verdict := "BATCH COMPLETE"
	if !m.Complete() {
		verdict = "BATCH INCOMPLETE"
	}
	mf := m.Manifest
	fmt.Fprintf(w, "%s  manifest %s\n  batch %s, %s, station %s (%s), %d device(s): %d certified, %d not\n", verdict, m.ID,
		mf.BatchID, mf.Created, orDash(mf.Station.Name), m.Trust, len(mf.Items), m.Certified(), m.Failed())
	if l := m.Logged; l != nil {
		state := "proof not checked (no --log-key)"
		if l.Checked {
			state = fmt.Sprintf("proof verified against checkpoint %s size %d", l.Checkpoint.Origin, l.Checkpoint.Size)
		}
		fmt.Fprintf(w, "  log: entry %d, %s\n", l.Index, state)
	}
	for _, it := range mf.Items {
		id := it.CertificateID
		if id == "" {
			id = it.Error
		}
		fmt.Fprintf(w, "  %-14s %-24s serial %-20s %-34s %s\n", it.Outcome, it.Path, orDash(it.Serial), it.Method, id)
	}
	for _, p := range m.Problems {
		fmt.Fprintln(w, "  PROBLEM:", p)
	}
	for _, p := range m.Invalid {
		fmt.Fprintln(w, "  INVALID certificate:", p)
	}
	for _, x := range m.Warnings {
		fmt.Fprintln(w, "  warning:", x)
	}
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
	if l := o.Logged; l != nil {
		if l.Checked {
			fmt.Fprintf(w, "  logged       entry %d in log %s (checkpoint size %d, proof verified)\n", l.Index, l.Checkpoint.Origin, l.Checkpoint.Size)
		} else {
			fmt.Fprintf(w, "  logged       entry %d (proof NOT checked: no --log-key)\n", l.Index)
		}
	}
	for _, v := range c.Verification {
		if v.SeedSource == cert.SeedTlog {
			fmt.Fprintf(w, "  sampling     %d sectors, seed from the transparency log (request entry %d)\n", v.Samples, v.SeedLog.Index)
		}
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
