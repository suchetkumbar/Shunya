package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"shunya/internal/ata"
	"shunya/internal/backend"
	"shunya/internal/engine"
	"shunya/internal/nvme"
	"shunya/internal/sanitize"
)

// firmwareWipe runs a firmware method on work (the target, or the span including the
// hidden range): plant markers, run the drive's erase, record done, check the markers,
// then the pattern verification if asked.
func firmwareWipe(ctx context.Context, tg, work backend.Target, plan engine.Plan, rec engine.JournalRecorder, st *engine.State, f wipeFlags, stdout, stderr io.Writer) int {
	fp := plan.Target.Fingerprint
	if plan.Markers != nil && (st == nil || !st.MarkersPlanted) {
		if err := engine.PlantMarkers(ctx, work, plan.Markers, fp); err != nil {
			rec.Failed(0, 0, err)
			fmt.Fprintf(stdout, "FAILED: planting markers: %v\n", err)
			return 1
		}
		if err := rec.Firmware(sanitize.Event{Event: engine.EvMarkersPlanted, Note: fmt.Sprintf("%d sectors", plan.Markers.Count)}); err != nil {
			fmt.Fprintln(stderr, "shunya: journal:", err)
			return 1
		}
		fmt.Fprintf(stdout, "planted %d markers (HMAC-tagged sectors that must not survive the erase)\n", plan.Markers.Count)
	}
	resume := st != nil && st.FirmwareStarted
	var err error
	switch m := plan.Method; {
	case m == engine.MethodATAErase || m == engine.MethodATAEnhancedErase:
		dev, _ := ataDevice(tg)
		if code := secureErase(ctx, dev, plan, rec, st, f, stdout); code != 0 {
			return code
		}
		return afterFirmware(ctx, work, plan, rec, f, stdout, stderr)
	case engine.IsATA(m):
		dev, _ := ataDevice(tg)
		err = runSanitize(ctx, ata.SanitizeOp{D: dev, Method: engine.ATASanitizeMethod(m), Passes: 1}, resume, rec, stdout)
	case engine.IsSanitize(m):
		dev, _ := nvmeDevice(tg)
		err = runSanitize(ctx, nvme.SanitizeOp{D: dev, Action: engine.NVMeSanitizeAction(m), Passes: 1}, resume, rec, stdout)
	default:
		dev, _ := nvmeDevice(tg)
		err = runFormat(ctx, dev, plan, rec, stdout)
	}
	switch {
	case errors.Is(err, context.Canceled):
		rec.Interrupted(0, 0, "operator interrupt")
		fmt.Fprintf(stdout, "INTERRUPTED. A started sanitize continues inside the drive. Resume with:\n  shunya wipe --resume --execute --journal %s --key %s\n", f.journal, f.key)
		return exitInterrupted
	case err != nil:
		rec.Failed(0, 0, err)
		fmt.Fprintf(stdout, "FAILED: %v\nFix the cause and resume with: shunya wipe --resume --execute --journal %s --key %s\n", err, f.journal, f.key)
		return 1
	}
	if err := rec.Done(0); err != nil {
		fmt.Fprintln(stderr, "shunya: journal:", err)
		return 1
	}
	fmt.Fprintf(stdout, "DONE: %s completed. NIST SP 800-88 level: %s.\n", plan.Method, levelName(plan.Level))
	return afterFirmware(ctx, work, plan, rec, f, stdout, stderr)
}

// afterFirmware checks the markers, then runs the requested pattern verification.
func afterFirmware(ctx context.Context, work backend.Target, plan engine.Plan, rec engine.JournalRecorder, f wipeFlags, stdout, stderr io.Writer) int {
	code := 0
	if plan.Markers != nil {
		code = checkMarkers(ctx, work, plan, rec, stdout, stderr)
		if code == 1 {
			return code
		}
	}
	return max(code, verifyAndRecord(ctx, work, plan, rec, f, "", stdout, stderr))
}

func checkMarkers(ctx context.Context, t backend.Target, plan engine.Plan, rec engine.JournalRecorder, stdout, stderr io.Writer) int {
	r, err := engine.CheckMarkers(ctx, t, plan.Markers, plan.Target.Fingerprint)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: marker check:", err)
		return 1
	}
	v := engine.VerifiedData{Mode: "markers", OK: r.Surviving == 0, BytesRead: int64(r.Checked) * int64(t.SectorSize()),
		BadSectors: int64(r.Surviving), FirstBad: r.First, Samples: r.Checked}
	if err := rec.Verified(v); err != nil {
		fmt.Fprintln(stderr, "shunya: journal:", err)
		return 1
	}
	if !v.OK {
		fmt.Fprintf(stdout, "VERIFY FAILED (markers): %d of %d planted markers still read back (first at byte %d): the erase did not change those sectors.\n", r.Surviving, r.Checked, r.First)
		return exitVerifyFail
	}
	fmt.Fprintf(stdout, "VERIFIED (markers): none of the %d planted markers reads back.\n", r.Checked)
	return 0
}

func runSanitize(ctx context.Context, op sanitize.Operation, resume bool, rec engine.JournalRecorder, stdout io.Writer) error {
	fmt.Fprintf(stdout, "%s: the drive erases itself; Shunya polls its status (it continues across power loss)\n", op.Name())
	last := -1
	_, err := sanitize.Run(ctx, op, sanitize.Options{Resume: resume, Record: rec.Firmware, Poll: sanitizePoll, OnProgress: func(s sanitize.Status) {
		if p := int(s.Progress * 10); s.Phase == sanitize.InProgress && p != last {
			last = p
			fmt.Fprintf(stdout, "  sanitize in progress: %.0f%%\n", 100*s.Progress)
		}
	}})
	return err
}

func runFormat(ctx context.Context, dev nvme.Device, plan engine.Plan, rec engine.JournalRecorder, stdout io.Writer) error {
	nv := plan.NVMe
	c, err := nvme.FormatCmd(&nv.Namespace, engine.NVMeFormatSES(plan.Method))
	if err != nil {
		return err
	}
	if err := rec.Firmware(sanitize.Event{Event: engine.EvFormatStarted, Action: plan.Method}); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	fmt.Fprintf(stdout, "%s on namespace %d (LBA format %d kept)…\n", c.Name, nv.Namespace.NSID, nv.Namespace.LBAF)
	if _, err := dev.Exec(ctx, c, nil); err != nil {
		return err
	}
	// The namespace must come back with the same geometry.
	n, _, err := dev.Namespace(ctx, nv.Namespace.NSID)
	if err != nil {
		return err
	}
	if n.Size != nv.Namespace.Size || n.BlockBytes() != nv.Namespace.BlockBytes() {
		return fmt.Errorf("after the format the namespace is %d × %d bytes, was %d × %d", n.Size, n.BlockBytes(), nv.Namespace.Size, nv.Namespace.BlockBytes())
	}
	if err := rec.Firmware(sanitize.Event{Event: engine.EvFormatCompleted, Action: plan.Method}); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	return nil
}

// sanitizePoll is the sanitize status interval (tests shorten it).
var sanitizePoll = 5 * time.Second

// ataPreconditions checks the live state each ATA firmware method needs (read-only).
func ataPreconditions(spec *targetSpec, id *ata.Identify, f wipeFlags, stderr io.Writer) map[string]error {
	pre := map[string]error{
		engine.MethodATAErase:         ata.CheckErase(id, false, false),
		engine.MethodATAEnhancedErase: ata.CheckErase(id, true, false),
	}
	if !id.Sanitize.Supported {
		return pre
	}
	tg, code := spec.open(f, false, stderr)
	if code != 0 {
		return pre
	}
	defer tg.Close()
	dev, _ := ataDevice(tg)
	for _, m := range []string{engine.MethodATASanitizeCrypto, engine.MethodATASanitizeBlock, engine.MethodATASanitizeOverwrite} {
		pre[m] = ata.CheckSanitize(context.Background(), dev, id, engine.ATASanitizeMethod(m))
	}
	return pre
}

// recommend ranks the methods for a probed target: NVMe facts if it is NVMe, else
// the ATA facts and the live preconditions of each ATA method.
func recommend(spec *targetSpec, f wipeFlags, hp *engine.HiddenPlan, id *ata.Identify, nv *engine.NVMePlan, stderr io.Writer) engine.Recommendation {
	in := engine.RecommendInput{Media: spec.media, Virtual: spec.virtual, NVMe: nv}
	if nv == nil {
		in.Hidden = hp
		if id != nil && hp != nil && hp.Before.Checked {
			in.Preconditions = ataPreconditions(spec, id, f, stderr)
		}
	}
	return engine.Recommend(in)
}

// cmdPlan: shunya plan DEVICE — every method, its level and why, and the choice.
func cmdPlan(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("plan", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var f wipeFlags
	asJSON := fl.Bool("json", false, "print JSON")
	fl.StringVar(&f.confirm, "confirm", "", "release builds: last 4 characters of the serial")
	if err := fl.Parse(args); err != nil || fl.NArg() != 1 {
		fmt.Fprint(stderr, "usage: shunya plan [--json] DEVICE\n")
		return 2
	}
	f.hpa = engine.HPARestore
	spec, code := inspect(fl.Arg(0), false, 0, stderr)
	if code != 0 {
		return code
	}
	note := ""
	nv, why, code := probeNVMe(spec, f, stderr)
	if code != 0 {
		return code
	}
	if nv == nil && why != "" {
		note = why
	}
	var hp *engine.HiddenPlan
	var id *ata.Identify
	if nv == nil {
		if hp, id, code = probeHidden(spec, f, stderr); code != 0 {
			return code
		}
		if (id == nil || hp == nil || !hp.Before.Checked) && hp != nil && note == "" {
			note = hp.Before.Reason
		}
	}
	r := recommend(spec, f, hp, id, nv, stderr)
	if *asJSON {
		return writeJSON(stdout, stderr, r)
	}
	media := string(spec.media)
	if spec.virtual {
		media += " (virtual)"
	}
	fmt.Fprintf(stdout, "PLAN OPTIONS  %s  %s  serial %s  %s, %s\n", spec.path, orDash(spec.id.Model), orDash(spec.id.Serial), media, human(uint64(spec.size)))
	if note != "" {
		fmt.Fprintf(stdout, "  firmware methods: %s\n", note)
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  METHOD\tLEVEL\tAVAILABLE\tWHY")
	for _, o := range r.Options {
		mark := "no"
		if o.Available {
			mark = "yes"
		}
		why := o.Why
		if len(why) > 140 {
			why = why[:137] + "…"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", o.Method, levelName(o.Level), mark, why)
	}
	tw.Flush()
	fmt.Fprintf(stdout, "\nRECOMMENDED: %s (%s)\n  shunya wipe --method %s %s   # dry run first; add --execute --journal FILE --key FILE\n",
		r.Best, r.Reason, r.Best, spec.path)
	fmt.Fprintln(stdout, "Shunya does not choose for you: pass --method explicitly. (read-only: Identify/IDENTIFY and status queries only)")
	return 0
}
