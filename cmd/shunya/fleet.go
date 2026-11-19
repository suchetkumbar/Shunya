package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"

	"shunya/internal/backend"
	"shunya/internal/engine"
	"shunya/internal/manifest"
)

const fleetUsage = `usage: shunya fleet [flags] [--image FILE]... [DEVICE...]

Wipes several disks in parallel, each exactly as "shunya wipe" would (same guards, own
journal, own certificate), then signs a batch manifest listing every disk and outcome.
Without --execute it prints each disk's plan and writes nothing.

With --execute it needs --journal-dir DIR, --key FILE, and --approved FILE --yes-really:
every disk's fingerprint must be in the approved list (shunya list --json shows them).
`

// fleetOptions are the batch-level settings around the per-disk wipe flags.
type fleetOptions struct {
	dir      string
	parallel int
	images   multiFlag
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// batchFlags registers the flags fleet mode and the TUI share with shunya wipe.
func batchFlags(fl *flag.FlagSet, f *wipeFlags, o *fleetOptions) {
	fl.StringVar(&f.method, "method", methodAuto, "erase method for every disk: auto (each disk's recommendation) or one of "+strings.Join(engine.Methods, ", "))
	fl.BoolVar(&f.verify, "verify", true, "read each disk back in full afterwards (the default; --sample N instead samples)")
	fl.IntVar(&f.sample, "sample", 0, "verify N sectors per disk at unpredictable positions (with --log) instead of the full read-back")
	logFlags(fl, f)
	fl.StringVar(&o.dir, "journal-dir", "", "directory for the journals, logs, certificates and the manifest (the tool's own medium)")
	fl.StringVar(&f.key, "key", "", "station signing key")
	fl.StringVar(&f.stationCert, "station-cert", "", "the station's certificate: issue a certificate for each verified disk")
	fl.StringVar(&f.verifyURL, "verify-url", "", "verification URL prefix for the QR codes")
	fl.StringVar(&f.hpa, "hpa", engine.HPARestore, "Host Protected Area policy: restore, leave-removed or skip")
	fl.IntVar(&o.parallel, "parallel", 3, "wipe at most N disks at the same time")
	fl.Var(&o.images, "image", "also wipe this image file (repeatable)")
	fl.IntVar(&f.sector, "sector", 512, "image files: logical sector size")
}

func cmdFleet(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("fleet", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.Usage = func() { fmt.Fprint(stderr, fleetUsage); fl.PrintDefaults() }
	var f wipeFlags
	var o fleetOptions
	batchFlags(fl, &f, &o)
	fl.BoolVar(&f.execute, "execute", false, "actually wipe (without it: print every plan, write nothing)")
	fl.StringVar(&f.approved, "approved", "", "file of approved device fingerprints, one fp1:… per line")
	fl.BoolVar(&f.yesReally, "yes-really", false, "wipe the approved disks without typing each serial")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	f.patterns, f.chunkMiB, f.syncMiB, f.offlineSeed = engine.PatternRandom, engine.DefaultChunk>>20, engine.DefaultSyncEvery>>20, orDefault(f.offlineSeed, offlineFull)
	if f.sample > 0 {
		f.verify = false
	}
	f.autoVerify = true
	if err := checkBatch(f, o, fl.NArg(), true); err != nil {
		fmt.Fprintln(stderr, "shunya: fleet:", err)
		return 2
	}
	targets := inspectTargets(fl.Args(), o.images, f.sector)
	if !f.execute {
		code := 0
		for _, t := range targets {
			fmt.Fprintf(stdout, "\n=== %s\n", t.path)
			if t.spec == nil {
				fmt.Fprintln(stdout, "REFUSED:", t.refusal)
				printExplanations(stdout, t.refusal)
				code = 1
				continue
			}
			g, dev := f, t.path
			if t.isImage {
				g.image, dev = t.path, ""
			}
			code = max(code, explained(func(_ []string, so, se io.Writer) int { return freshWipe(g, dev, so, se) }, nil, stdout, stderr))
		}
		fmt.Fprintf(stdout, "\nDRY RUN of %d disk(s): nothing was written. Add --execute --journal-dir DIR --key FILE --approved FILE --yes-really.\n", len(targets))
		return code
	}
	approved, err := readApproved(f.approved)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: fleet:", err)
		return 2
	}
	approve(targets, approved)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var mu sync.Mutex
	lastTenth := map[int]int64{}
	say := func(i int, s string) {
		mu.Lock()
		fmt.Fprintf(stdout, "[%s] %s\n", targets[i].label(), s)
		mu.Unlock()
	}
	results := runBatch(ctx, f, targets, o.dir, o.parallel, func(e deviceEvent) {
		switch {
		case e.line != "":
			say(e.idx, e.line)
		case e.progress != nil:
			p := e.progress
			tenth := 10 * p.Done / max(p.Total, 1)
			mu.Lock()
			prev, seen := lastTenth[e.idx]
			lastTenth[e.idx] = tenth
			mu.Unlock()
			if !seen || tenth != prev {
				say(e.idx, progressLine(*p))
			}
		}
	})
	return fleetSummary(f, results, o.dir, stdout, stderr)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// checkBatch validates batch flags before any device is touched.
func checkBatch(f wipeFlags, o fleetOptions, nargs int, approval bool) error {
	switch {
	case nargs+len(o.images) == 0:
		return fmt.Errorf("no disks given")
	case nargs+len(o.images) > manifest.MaxItems:
		return fmt.Errorf("at most %d disks per batch", manifest.MaxItems)
	case f.method != methodAuto && !slices.Contains(engine.Methods, f.method):
		return fmt.Errorf("unknown --method %q", f.method)
	case o.parallel < 1:
		return fmt.Errorf("--parallel must be at least 1")
	}
	if f.execute {
		switch {
		case o.dir == "" || f.key == "":
			return fmt.Errorf("needs --journal-dir DIR (on the tool's own medium) and --key FILE")
		case approval && (f.approved == "" || !f.yesReally):
			return fmt.Errorf("--execute needs --approved FILE and --yes-really: a batch wipes only disks approved in advance")
		}
		if st, err := os.Stat(o.dir); err != nil || !st.IsDir() {
			return fmt.Errorf("--journal-dir %s: not an existing directory", o.dir)
		}
	}
	return checkVerifyFlags(f)
}

func readApproved(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return backend.ParseApprovedList(b)
}

// approve refuses every target whose fingerprint is not in the approved list (in
// every build; release builds check it again when the device is opened).
func approve(targets []batchTarget, approved []string) {
	for i, t := range targets {
		if t.spec != nil && !slices.Contains(approved, strings.ToLower(t.spec.id.Fingerprint)) {
			targets[i].refusal = "confirmation: --yes-really given but fingerprint " + t.spec.id.Fingerprint + " is not in the approved list"
			targets[i].spec = nil
		}
	}
}

// fleetSummary prints the outcome table, signs the manifest and returns the exit code
// (0: every disk wiped and verified; 1 otherwise).
func fleetSummary(f wipeFlags, results []itemResult, dir string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, "\nBATCH RESULT")
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  DISK\tSERIAL\tMETHOD\tOUTCOME\tCERTIFICATE / REASON")
	code := 0
	for _, r := range results {
		detail := r.res.CertID
		if detail == "" {
			detail = r.err
		}
		serial := r.target.identity().Serial
		if r.target.isImage {
			serial = "(image)"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", r.target.path, orDash(serial), orDash(r.res.Method), r.outcome, detail)
		if r.outcome != manifest.OutcomeCertified && r.outcome != manifest.OutcomeNotCertified {
			code = 1
		}
	}
	tw.Flush()
	for _, r := range results {
		for _, e := range r.explain {
			fmt.Fprintf(stdout, "\n%s: %s\n  why:        %s\n  what to do: %s\n", r.target.label(), e.What, e.Why, e.Do)
		}
	}
	if _, err := writeManifest(f, results, dir, stdout); err != nil {
		fmt.Fprintln(stderr, "shunya: fleet: manifest:", err)
		return 1
	}
	return code
}
