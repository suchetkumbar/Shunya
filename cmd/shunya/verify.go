package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"shunya/internal/backend"
	"shunya/internal/engine"
	"shunya/internal/journal"
)

// checkVerifyFlags validates --sample/--seed before anything is opened.
func checkVerifyFlags(f wipeFlags) error {
	if f.sample < 0 {
		return errors.New("--sample must be positive")
	}
	if f.seed != "" && f.sample == 0 {
		return errors.New("--seed HEX needs --sample N")
	}
	if f.seed != "" && f.logURL != "" {
		return errors.New("--seed and --log are alternatives: the log's seed is the one the operator cannot choose")
	}
	if f.sample > 0 && f.seed == "" && f.logURL == "" && f.offlineSeed != offlineLocal {
		return errors.New("--sample N needs a seed: --log URL --log-key KEY (unpredictable), --seed HEX (operator-chosen) or --offline-seed local")
	}
	if err := checkLogFlags(f); err != nil {
		return err
	}
	if f.seed != "" {
		if b, err := hex.DecodeString(f.seed); err != nil || len(b) < 16 {
			return errors.New("--seed: want at least 32 hex digits")
		}
	}
	return nil
}

// verifyAndRecord runs the requested verifications against the plan's expected pattern
// (the last overwrite pass, or zeros after a normal Security Erase) and appends each
// result to the journal. scope is recorded when tg covers less than the plan. Exit code
// 4 if any sector differs.
func verifyAndRecord(ctx context.Context, tg backend.Target, plan engine.Plan, rec engine.JournalRecorder, f wipeFlags, scope string, stdout, stderr io.Writer) int {
	if !f.verify && f.sample == 0 {
		return 0
	}
	name, key := plan.ExpectedPattern()
	if name == "" {
		fmt.Fprintf(stderr, "shunya: verify: %s leaves a vendor-defined pattern; there is nothing to compare against\n", plan.Method)
		return 2
	}
	last := engine.Pass{Pattern: name, Key: key}
	pat, err := engine.NewPattern(last.Pattern, mustHex(last.Key))
	if err != nil {
		fmt.Fprintln(stderr, "shunya: verify:", err)
		return 1
	}
	if scope != "" {
		fmt.Fprintln(stdout, "note: "+scope)
	}
	code := 0
	record := func(v engine.VerifiedData) bool {
		if err := rec.Verified(v); err != nil {
			fmt.Fprintln(stderr, "shunya: verify: journal:", err)
			code = 1
			return false
		}
		if !v.OK {
			code = max(code, exitVerifyFail)
		}
		return true
	}
	if f.verify {
		v, err := engine.Verify(ctx, tg, pat, plan.ChunkBytes)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: verify:", err)
			return 1
		}
		if !record(engine.VerifiedData{Mode: "full", Pattern: last.Pattern, OK: v.OK(), BytesRead: v.BytesRead,
			BadSectors: v.BadSectors, FirstBad: v.FirstBad, Scope: scope}) {
			return code
		}
		if v.OK() {
			fmt.Fprintf(stdout, "VERIFIED (full): all %s read back and match the %s pattern.\n", human(uint64(v.BytesRead)), last.Pattern)
		} else {
			fmt.Fprintf(stdout, "VERIFY FAILED (full): %d sector(s) differ, first at byte %d\n", v.BadSectors, v.FirstBad)
		}
	}
	if f.sample > 0 {
		seed, src, q, in, full, err := sampleSeed(ctx, f, tg, stdout)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: verify: sampling seed:", err)
			return max(code, 1)
		}
		if full { // offline fallback: the whole target instead
			if f.verify {
				return code // already read back in full above
			}
			g := f
			g.verify, g.sample = true, 0
			return max(code, verifyAndRecord(ctx, tg, plan, rec, g, scope, stdout, stderr))
		}
		v, err := engine.VerifySampled(ctx, tg, pat, seed, src, f.sample)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: verify:", err)
			return 1
		}
		if !record(engine.VerifiedData{Mode: "sampled", Pattern: last.Pattern, OK: v.OK(), BytesRead: v.BytesRead,
			BadSectors: v.BadSectors, FirstBad: v.FirstBad, Samples: v.Samples, SeedSource: v.SeedSource, Seed: v.Seed,
			Bound95: v.Bound95, Scope: scope, SeedRequest: q, SeedLog: in}) {
			return code
		}
		verdict := "VERIFIED (sampled)"
		if !v.OK() {
			verdict = fmt.Sprintf("VERIFY FAILED (sampled): %d of", v.BadSectors)
		}
		from := map[string]string{engine.SeedOperator: "an operator-chosen seed", engine.SeedLocal: "a random seed drawn by this tool",
			engine.SeedTlog: "a seed from the transparency log"}[src]
		fmt.Fprintf(stdout, "%s %d sectors from %s; an unwiped share of %.3f%% or more would be caught with 95%% probability.\n",
			verdict, v.Samples, from, 100*v.Bound95)
		switch src {
		case engine.SeedOperator:
			fmt.Fprintln(stdout, "  note: the operator chose this seed, so it proves less; use --log for an unpredictable one.")
		case engine.SeedTlog:
			fmt.Fprintf(stdout, "  seed: log entry %d, asked after the wipe finished; anyone can recompute it from the certificate.\n", in.Index)
		}
	}
	return code
}

// cmdVerify re-verifies a finished wipe from its journal and records the result.
func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("verify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var f wipeFlags
	fl.BoolVar(&f.verify, "full", false, "full read-back (default when --sample is not given)")
	fl.IntVar(&f.sample, "sample", 0, "verify N sectors chosen from --seed")
	fl.StringVar(&f.seed, "seed", "", "hex seed (at least 16 bytes) for --sample, chosen by the operator (labelled)")
	fl.StringVar(&f.stationCert, "station-cert", "", "the station's certificate: needed to ask the log for a seed")
	logFlags(fl, &f)
	fl.StringVar(&f.journal, "journal", "", "the wipe's journal")
	fl.StringVar(&f.key, "key", "", "station key")
	fl.BoolVar(&f.direct, "direct", false, "image files: use O_DIRECT")
	fl.StringVar(&f.confirm, "confirm", "", "release builds: last 4 characters of the serial")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 0 || f.journal == "" || f.key == "" {
		fmt.Fprint(stderr, "usage: shunya verify [--full] [--sample N (--log URL --log-key K --station-cert S | --seed HEX | --offline-seed local)] --journal FILE --key FILE\n")
		return 2
	}
	if err := checkVerifyFlags(f); err != nil {
		fmt.Fprintln(stderr, "shunya: verify:", err)
		return 2
	}
	explicit := f.verify || f.sample > 0
	if f.sample == 0 {
		f.verify = true
	}
	key, err := journal.LoadKeyFile(f.key)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: verify:", err)
		return 1
	}
	w, log, err := journal.OpenAppend(f.journal, key)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: verify:", err)
		return 1
	}
	defer w.Close()
	st, err := engine.Replay(log)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: verify:", err)
		return 1
	}
	if !st.Done {
		fmt.Fprintf(stderr, "shunya: verify: wipe %s is not complete (%s); resume it first\n", st.WipeID, st.Pending())
		return 1
	}
	plan := st.Plan
	spec, code := inspect(plan.Target.Path, plan.Media == engine.MediaImage, plan.SectorSize, stderr)
	if code != 0 {
		return code
	}
	if spec.id.Fingerprint != plan.Target.Fingerprint {
		fmt.Fprintf(stderr, "shunya: verify: %s is now %s, but the journal is for %s: refusing\n", spec.path, spec.id.Fingerprint, plan.Target.Fingerprint)
		return 1
	}
	noPattern := false
	if name, _ := plan.ExpectedPattern(); name == "" {
		if explicit || plan.Markers == nil {
			fmt.Fprintf(stderr, "shunya: verify: %s leaves an indeterminate pattern; there is nothing to compare against (without --full/--sample the marker check runs)\n", plan.Method)
			return 2
		}
		noPattern = true
	}
	tg, code := spec.open(f, false, stderr) // read-only
	if code != 0 {
		return code
	}
	defer tg.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	work, scope, err := verifyTarget(ctx, tg, plan)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: verify:", err)
		return 1
	}
	fmt.Fprintf(stdout, "verifying wipe %s of %s (read-only)\n", st.WipeID, spec.path)
	rec := engine.JournalRecorder{W: w}
	code = 0
	if plan.Markers != nil && plan.Markers.Seed != "" {
		if code = checkMarkers(ctx, work, plan, rec, stdout, stderr); code == 1 || noPattern {
			return code
		}
	}
	return max(code, verifyAndRecord(ctx, work, plan, rec, f, scope, stdout, stderr))
}

// verifyTarget is the target a later verification reads. With a wiped HPA: if the
// drive still has it removed (policy leave-removed, no power cycle), the whole native
// range through pass-through reads; if it is back, only the visible part, and the scope
// says so. Verification never changes the drive's maximum address.
func verifyTarget(ctx context.Context, tg backend.Target, plan engine.Plan) (backend.Target, string, error) {
	if plan.Hidden == nil || !plan.Hidden.RemoveHPA {
		return tg, "", nil
	}
	dev, ok := ataDevice(tg)
	if !ok {
		return nil, "", errors.New("the plan includes a hidden range but this target has no ATA pass-through")
	}
	id, _, err := dev.Identify(ctx)
	if err != nil {
		return nil, "", err
	}
	h := plan.Hidden.Before
	switch id.Sectors() {
	case h.NativeSectors:
		s, err := hiddenSpan(ctx, tg, dev, plan)
		return s, "", err
	case h.ReportedSectors:
		return tg, // the block device is exactly the visible range
			fmt.Sprintf("visible range only: the HPA is back in place, so its %d sectors (verified, if requested, during the wipe) are not re-read", h.HPASectors()), nil
	}
	return nil, "", fmt.Errorf("drive reports %d sectors; the plan expects %d or %d", id.Sectors(), h.ReportedSectors, h.NativeSectors)
}
