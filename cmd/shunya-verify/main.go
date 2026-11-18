// Command shunya-verify checks an erasure certificate fully offline: its canonical
// form and signature, the station certificate's chain to the organisation's root,
// revocation, and optionally that a PDF is exactly the certificate's rendering.
//
//	shunya-verify --root ROOT.pub --revocations REVOCATIONS.json [--pdf CERT.pdf] CERT.json
//
// It never opens a device and needs no network. Exit status: 0 valid, 1 invalid,
// 2 usage.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"shunya/internal/certcheck"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("shunya-verify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.Usage = func() {
		fmt.Fprint(stderr, "usage: shunya-verify --root ROOT.pub (--revocations FILE | --no-revocation-check) [--allow-dev-key] [--pdf FILE] [--json] CERT.json\n\n")
		fl.PrintDefaults()
	}
	var o certcheck.Options
	fl.StringVar(&o.Root, "root", "", "the organisation's root public key (root.pub, or 64 hex digits)")
	fl.StringVar(&o.Revocations, "revocations", "", "the root's current revocation list")
	fl.BoolVar(&o.SkipRevocation, "no-revocation-check", false, "verify without a revocation list (reported)")
	fl.BoolVar(&o.AllowDevKey, "allow-dev-key", false, "accept certificates signed by uncertified dev keys (reported)")
	fl.StringVar(&o.PDF, "pdf", "", "also check that this PDF is exactly the certificate's rendering")
	asJSON := fl.Bool("json", false, "print the result as JSON")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fl.Usage()
		return 2
	}
	res, err := certcheck.Verify(fl.Arg(0), o)
	if *asJSON {
		out := map[string]any{"valid": err == nil}
		if err != nil {
			out["error"] = err.Error()
		} else {
			out["id"], out["trust"], out["warnings"], out["certificate"] = res.ID, res.Trust, res.Warnings, res.Certificate
			out["revocation_list"], out["pdf_checked"] = res.RevocationList, res.PDFChecked
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
	} else if err != nil {
		fmt.Fprintln(stdout, "INVALID:", err)
	} else {
		certcheck.Print(stdout, res)
	}
	if err != nil {
		return 1
	}
	return 0
}
