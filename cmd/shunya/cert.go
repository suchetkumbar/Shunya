package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"shunya/internal/backend"
	"shunya/internal/buildinfo"
	"shunya/internal/cert"
	"shunya/internal/certcheck"
	"shunya/internal/certpdf"
	"shunya/internal/engine"
	"shunya/internal/journal"
	"shunya/internal/keys"
)

const certUsage = `usage: shunya cert <command>

  issue --journal J --key K [--station-cert S] [--verify-url URL] [--out F.json] [--pdf F.pdf]
                          certificate for a finished, verified wipe (default: J.cert.json, J.cert.pdf)
  show  [verify flags] CERT.json         verify and summarise (as shunya-verify)
  pdf   [verify flags] --out F.pdf CERT.json   verify, then render the printable PDF again

verify flags: --root ROOT.pub --revocations FILE | --no-revocation-check, --allow-dev-key, --pdf FILE
`

func cmdCert(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, certUsage)
		return 2
	}
	switch args[0] {
	case "issue":
		return certIssue(args[1:], stdout, stderr)
	case "show":
		return certShow(args[1:], "", stdout, stderr)
	case "pdf":
		return certShow(args[1:], "pdf", stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, certUsage)
		return 0
	}
	fmt.Fprintf(stderr, "shunya cert: unknown command %q\n\n%s", args[0], certUsage)
	return 2
}

// issueRequest is one certificate to issue from a journal.
type issueRequest struct {
	journal, key, stationCert, verifyURL, outJSON, outPDF string
}

// issueCertificate builds, signs and writes the certificate and its PDF.
func issueCertificate(r issueRequest, stdout io.Writer) error {
	priv, err := journal.LoadKeyFile(r.key)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	raw, err := os.ReadFile(r.journal)
	if err != nil {
		return err
	}
	log, err := journal.Read(bytes.NewReader(raw), pub)
	if err != nil {
		return fmt.Errorf("journal %s: %w", r.journal, err)
	}
	st, err := engine.Replay(log)
	if err != nil {
		return err
	}
	var sc *keys.StationCert
	if r.stationCert != "" {
		b, err := os.ReadFile(r.stationCert)
		if err != nil {
			return err
		}
		c, err := keys.DecodeStationCert(b)
		if err != nil {
			return err
		}
		sc = &c
	}
	h, err := buildinfo.ExecutableHash()
	if err != nil {
		return fmt.Errorf("build hash: %w", err)
	}
	body, err := engine.BuildCertificate(log, raw, st, engine.CertInput{Issuer: "shunya " + version, IssuerBuildHash: h,
		Build: backend.BuildKind, StationPub: pub, StationCert: sc, Now: now(), VerifyURL: r.verifyURL})
	if err != nil {
		return err
	}
	signed, err := cert.Sign(body, priv)
	if err != nil {
		return err
	}
	id, err := cert.BodyID(body)
	if err != nil {
		return err
	}
	pdfBytes, err := certpdf.Render(body, id)
	if err != nil {
		return err
	}
	if r.outJSON == "" {
		r.outJSON = r.journal + ".cert.json"
	}
	if r.outPDF == "" {
		r.outPDF = r.journal + ".cert.pdf"
	}
	if err := writeFile(r.outJSON, signed, false); err != nil {
		return err
	}
	if err := writeFile(r.outPDF, pdfBytes, false); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "CERTIFICATE %s\n  %s\n  %s\n  QR: %s%s\n", id, r.outJSON, r.outPDF, body.VerifyURL, id)
	if sc == nil {
		fmt.Fprintln(stdout, "  signed with an uncertified station key: verifiers refuse it unless --allow-dev-key (certify the key with shunya keys issue-station)")
	}
	return nil
}

func certIssue(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("cert issue", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var r issueRequest
	fl.StringVar(&r.journal, "journal", "", "the wipe's journal")
	fl.StringVar(&r.key, "key", "", "the station key that signed the journal")
	fl.StringVar(&r.stationCert, "station-cert", "", "the station's certificate from the root (without: dev-key certificate)")
	fl.StringVar(&r.verifyURL, "verify-url", "", "verification URL prefix for the QR code (default "+cert.DefaultVerifyURL+")")
	fl.StringVar(&r.outJSON, "out", "", "certificate file (default JOURNAL.cert.json)")
	fl.StringVar(&r.outPDF, "pdf", "", "PDF file (default JOURNAL.cert.pdf)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if r.journal == "" || r.key == "" || fl.NArg() != 0 {
		fmt.Fprint(stderr, "usage: shunya cert issue --journal J --key K [--station-cert S] [--verify-url URL] [--out F] [--pdf F]\n")
		return 2
	}
	if err := issueCertificate(r, stdout); err != nil {
		fmt.Fprintln(stderr, "shunya: cert issue:", err)
		if errors.Is(err, engine.ErrNotCertifiable) {
			return 4
		}
		return 1
	}
	return 0
}

// verifyFlags registers the verification options shared with shunya-verify.
func verifyFlags(fl *flag.FlagSet, o *certcheck.Options) {
	fl.StringVar(&o.Root, "root", "", "the organisation's root public key (root.pub, or 64 hex digits)")
	fl.StringVar(&o.Revocations, "revocations", "", "the root's current revocation list")
	fl.BoolVar(&o.SkipRevocation, "no-revocation-check", false, "verify without a revocation list (reported)")
	fl.BoolVar(&o.AllowDevKey, "allow-dev-key", false, "accept certificates signed by uncertified dev keys (reported)")
	fl.StringVar(&o.PDF, "pdf", "", "also check that this PDF is exactly the certificate's rendering")
}

func certShow(args []string, mode string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("cert "+mode, flag.ContinueOnError)
	fl.SetOutput(stderr)
	var o certcheck.Options
	verifyFlags(fl, &o)
	out := ""
	if mode == "pdf" {
		fl.StringVar(&out, "out", "", "write the PDF here")
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || (mode == "pdf" && out == "") {
		fmt.Fprint(stderr, certUsage)
		return 2
	}
	res, err := certcheck.Verify(fl.Arg(0), o)
	if err != nil {
		fmt.Fprintln(stdout, "INVALID:", err)
		return 1
	}
	certcheck.Print(stdout, res)
	if mode == "pdf" {
		b, err := certpdf.Render(res.Certificate, res.ID)
		if err == nil {
			err = writeFile(out, b, false)
		}
		if err != nil {
			fmt.Fprintln(stderr, "shunya: cert pdf:", err)
			return 1
		}
		fmt.Fprintln(stdout, "wrote", out)
	}
	return 0
}
