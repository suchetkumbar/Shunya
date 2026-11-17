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
	if (f.sample > 0) != (f.seed != "") {
		return errors.New("--sample N and --seed HEX go together")
	}
	if f.seed != "" {
		if b, err := hex.DecodeString(f.seed); err != nil || len(b) < 16 {
			return errors.New("--seed: want at least 32 hex digits")
		}
	}
	return nil
}

// verifyAndRecord runs the requested verifications of the last pass and appends each
// result to the journal. Exit code 4 if any sector differs.
func verifyAndRecord(ctx context.Context, tg backend.Target, plan engine.Plan, rec engine.JournalRecorder, f wipeFlags, stdout, stderr io.Writer) int {
	if !f.verify && f.sample == 0 {
		return 0
	}
	last := plan.Passes[len(plan.Passes)-1]
	pat, err := engine.NewPattern(last.Pattern, mustHex(last.Key))
	if err != nil {
		fmt.Fprintln(stderr, "shunya: verify:", err)
		return 1
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
			BadSectors: v.BadSectors, FirstBad: v.FirstBad}) {
			return code
		}
		if v.OK() {
			fmt.Fprintf(stdout, "VERIFIED (full): all %s read back and match the %s pattern.\n", human(uint64(v.BytesRead)), last.Pattern)
		} else {
			fmt.Fprintf(stdout, "VERIFY FAILED (full): %d sector(s) differ, first at byte %d\n", v.BadSectors, v.FirstBad)
		}
	}
	if f.sample > 0 {
		seed, _ := hex.DecodeString(f.seed)
		v, err := engine.VerifySampled(ctx, tg, pat, seed, engine.SeedOperator, f.sample)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: verify:", err)
			return 1
		}
		if !record(engine.VerifiedData{Mode: "sampled", Pattern: last.Pattern, OK: v.OK(), BytesRead: v.BytesRead,
			BadSectors: v.BadSectors, FirstBad: v.FirstBad, Samples: v.Samples, SeedSource: v.SeedSource, Seed: v.Seed,
			Bound95: v.Bound95}) {
			return code
		}
		verdict := "VERIFIED (sampled)"
		if !v.OK() {
			verdict = fmt.Sprintf("VERIFY FAILED (sampled): %d of", v.BadSectors)
		}
		fmt.Fprintf(stdout, "%s %d sectors from an operator-chosen seed; an unwiped share of %.3f%% or more would be caught with 95%% probability.\n",
			verdict, v.Samples, 100*v.Bound95)
		fmt.Fprintln(stdout, "  note: the operator chose this seed; from Milestone 8 it comes from the transparency log instead.")
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
	fl.StringVar(&f.seed, "seed", "", "hex seed (at least 16 bytes) for --sample")
	fl.StringVar(&f.journal, "journal", "", "the wipe's journal")
	fl.StringVar(&f.key, "key", "", "station key")
	fl.BoolVar(&f.direct, "direct", false, "image files: use O_DIRECT")
	fl.StringVar(&f.confirm, "confirm", "", "release builds: last 4 characters of the serial")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 0 || f.journal == "" || f.key == "" {
		fmt.Fprint(stderr, "usage: shunya verify [--full] [--sample N --seed HEX] --journal FILE --key FILE\n")
		return 2
	}
	if err := checkVerifyFlags(f); err != nil {
		fmt.Fprintln(stderr, "shunya: verify:", err)
		return 2
	}
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
	tg, code := spec.open(f, false, stderr) // read-only
	if code != 0 {
		return code
	}
	defer tg.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Fprintf(stdout, "verifying wipe %s of %s (read-only)\n", st.WipeID, spec.path)
	return verifyAndRecord(ctx, tg, plan, engine.JournalRecorder{W: w}, f, stdout, stderr)
}
