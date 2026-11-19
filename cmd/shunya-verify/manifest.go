package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"shunya/internal/certcheck"
)

// cmdManifest: shunya-verify manifest [trust flags] [--certs DIR|FILE]... MANIFEST.json
// verifies a fleet batch manifest and the certificates it lists.
func cmdManifest(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("shunya-verify manifest", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var o certcheck.Options
	trustFlags(fl, &o)
	var certs multi
	fl.Var(&certs, "certs", "a certificate file, or a directory of *.cert.json files, to match against the manifest (repeatable)")
	asJSON := fl.Bool("json", false, "print the result as JSON")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fmt.Fprint(stderr, "usage: shunya-verify manifest --root ROOT.pub (--revocations FILE | --no-revocation-check) [--log-key LOG.vkey [--require-log]] [--certs DIR]... MANIFEST.json\n")
		return 2
	}
	res, err := certcheck.VerifyManifest(fl.Arg(0), certs, o)
	ok := err == nil && (len(certs) == 0 || res.Complete())
	if *asJSON {
		out := map[string]any{"valid": err == nil, "complete": ok && len(certs) > 0}
		if err != nil {
			out["error"] = err.Error()
		} else {
			out["id"], out["trust"], out["warnings"], out["manifest"] = res.ID, res.Trust, res.Warnings, res.Manifest
			out["problems"], out["invalid_certificates"], out["certificates_checked"] = res.Problems, res.Invalid, len(res.Certificates)
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
		certcheck.PrintManifest(stdout, res)
		if len(certs) == 0 {
			fmt.Fprintln(stdout, "  (certificates not checked: give --certs DIR to match them against the manifest)")
		}
	}
	if !ok {
		return 1
	}
	return 0
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return fmt.Sprint(*m) }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }
