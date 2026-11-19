// Command shunya-verify checks an erasure certificate fully offline, and runs the
// transparency log and public verifier.
//
//	shunya-verify --root ROOT.pub --revocations REVOCATIONS.json [--log-key LOG.vkey] [--pdf CERT.pdf] CERT.json
//	shunya-verify log-key --origin NAME --out DIR
//	shunya-verify serve --dir DIR --log-key DIR/log.key --root ROOT.pub --revocations FILE [--listen ADDR]
//	shunya-verify audit --log URL|DIR --log-key LOG.vkey --state FILE
//	shunya-verify manifest --root ROOT.pub --revocations FILE [--certs DIR] MANIFEST.json
//
// Verifying a certificate never opens a device and needs no network. Exit status:
// 0 valid / passed, 1 invalid / failed, 2 usage.
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
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return cmdServe(args[1:], stdout, stderr)
		case "audit":
			return cmdAudit(args[1:], stdout, stderr)
		case "log-key":
			return cmdLogKey(args[1:], stdout, stderr)
		case "manifest":
			return cmdManifest(args[1:], stdout, stderr)
		}
	}
	fl := flag.NewFlagSet("shunya-verify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.Usage = func() {
		fmt.Fprint(stderr, "usage: shunya-verify --root ROOT.pub (--revocations FILE | --no-revocation-check) [--log-key LOG.vkey [--require-log]] [--allow-dev-key] [--pdf FILE] [--json] CERT.json\n"+
			"       shunya-verify log-key | serve | audit | manifest ...   (each with -h)\n\n")
		fl.PrintDefaults()
	}
	var o certcheck.Options
	trustFlags(fl, &o)
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
			if l := res.Logged; l != nil {
				out["log"] = map[string]any{"index": l.Index, "checked": l.Checked, "origin": l.Checkpoint.Origin, "tree_size": l.Checkpoint.Size}
			}
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

// trustFlags registers what a verifier trusts (shared by certificates and manifests).
func trustFlags(fl *flag.FlagSet, o *certcheck.Options) {
	fl.StringVar(&o.Root, "root", "", "the organisation's root public key (root.pub, or 64 hex digits)")
	fl.StringVar(&o.Revocations, "revocations", "", "the root's current revocation list")
	fl.BoolVar(&o.SkipRevocation, "no-revocation-check", false, "verify without a revocation list (reported)")
	fl.BoolVar(&o.AllowDevKey, "allow-dev-key", false, "accept files signed by uncertified dev keys (reported)")
	fl.StringVar(&o.LogKey, "log-key", "", "the transparency log's verifier key (file or key): check log proofs and log seeds")
	fl.BoolVar(&o.RequireLog, "require-log", false, "refuse files without a verified log inclusion proof")
}
