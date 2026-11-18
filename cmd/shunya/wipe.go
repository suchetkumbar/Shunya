package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"shunya/internal/ata"
	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/engine"
	"shunya/internal/journal"
)

// version is reported in journals (and, from Milestone 7, certificates).
var version = "0.5.0-dev"

// wrapTarget lets tests slow down or observe the target; identity in production.
var wrapTarget = func(t backend.Target) backend.Target { return t }

// Exit codes beyond 0/1/2.
const (
	exitInterrupted = 5 // stopped cleanly; resumable with --resume
	exitVerifyFail  = 4
)

type wipeFlags struct {
	execute, resume, verify, direct, asJSON, yesReally bool
	image, journal, key, patterns, confirm, approved   string
	seed, method, hpa                                  string
	sector, chunkMiB, syncMiB, passes, sample          int
}

func cmdWipe(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("wipe", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var f wipeFlags
	fl.BoolVar(&f.execute, "execute", false, "actually write (without it: print the plan, write nothing)")
	fl.BoolVar(&f.resume, "resume", false, "continue the wipe recorded in --journal")
	fl.BoolVar(&f.verify, "verify", false, "read the whole target back afterwards and compare with the last pass")
	fl.IntVar(&f.sample, "sample", 0, "afterwards, verify N sectors chosen from --seed (sampled verification)")
	fl.StringVar(&f.seed, "seed", "", "hex seed (at least 16 bytes) for --sample; recorded as operator-chosen")
	fl.BoolVar(&f.direct, "direct", false, "image files: use O_DIRECT (block devices always do)")
	fl.BoolVar(&f.asJSON, "json", false, "dry run: print the plan as JSON")
	fl.StringVar(&f.image, "image", "", "wipe this regular image file instead of a device")
	fl.IntVar(&f.sector, "sector", 512, "image files: logical sector size")
	fl.StringVar(&f.patterns, "pattern", engine.PatternRandom, "comma-separated passes: random, zero, one")
	fl.IntVar(&f.passes, "passes", 0, "repeat a single --pattern N times (not required by NIST SP 800-88)")
	fl.IntVar(&f.chunkMiB, "chunk-mib", engine.DefaultChunk>>20, "write size in MiB")
	fl.IntVar(&f.syncMiB, "sync-mib", engine.DefaultSyncEvery>>20, "sync and checkpoint every N MiB")
	fl.StringVar(&f.journal, "journal", "", "progress journal file, on the tool's own medium (required with --execute)")
	fl.StringVar(&f.key, "key", "", "station signing key (shunya keys gen-dev; required with --execute)")
	fl.StringVar(&f.confirm, "confirm", "", "release builds: last 4 characters of the device serial")
	fl.BoolVar(&f.yesReally, "yes-really", false, "release builds, fleet mode: skip typing, device must be in --approved")
	fl.StringVar(&f.approved, "approved", "", "fleet mode: file of approved device fingerprints")
	fl.StringVar(&f.method, "method", engine.MethodOverwrite, "overwrite, ata-secure-erase or ata-enhanced-secure-erase")
	fl.StringVar(&f.hpa, "hpa", engine.HPARestore, "a Host Protected Area found on the drive: wipe it and restore it afterwards (restore), wipe it and leave it removed until power-off (leave-removed), or do not wipe it (skip; disclosed in the plan)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	switch f.method {
	case engine.MethodOverwrite, engine.MethodATAErase, engine.MethodATAEnhancedErase:
	default:
		fmt.Fprintf(stderr, "shunya: wipe: unknown --method %q\n", f.method)
		return 2
	}
	if f.hpa != engine.HPARestore && f.hpa != engine.HPALeaveRemoved && f.hpa != "skip" {
		fmt.Fprintf(stderr, "shunya: wipe: --hpa must be restore, leave-removed or skip\n")
		return 2
	}
	if err := checkVerifyFlags(f); err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return 2
	}
	if f.resume {
		if fl.NArg() != 0 || f.image != "" {
			fmt.Fprintln(stderr, "shunya: wipe --resume takes the target from the journal; give no device or --image")
			return 2
		}
		return resumeWipe(f, stdout, stderr)
	}
	if (fl.NArg() == 1) == (f.image != "") {
		fmt.Fprint(stderr, "usage: shunya wipe [flags] (/dev/NAME | --image FILE)\n       shunya wipe --resume --execute --journal FILE --key FILE\n")
		return 2
	}
	return freshWipe(f, fl.Arg(0), stdout, stderr)
}

// targetSpec is a wipe target before it is opened.
type targetSpec struct {
	path      string // device path or absolute image path
	isImage   bool
	id        backend.Identity
	media     device.MediaType
	virtual   bool
	size      int64
	sector    int
	devs      engine.TargetDevs
	verdict   *backend.Verdict
	transport device.Transport
	firmware  string
	// opener replaces backend.OpenBlock for devices served by testDevice.
	opener func(execute bool) (backend.Target, error)
}

// testDevice, set only by tests, serves device paths from simulated drives instead of
// the live system (nil in every build of the shunya binary).
var testDevice func(path string) (*targetSpec, bool)

// inspect resolves the target without opening a device: sysfs for devices; for images
// a read-only open of the regular file (FileBackend refuses anything else).
func inspect(path string, isImage bool, sector int, stderr io.Writer) (*targetSpec, int) {
	if testDevice != nil && !isImage {
		if s, ok := testDevice(path); ok {
			return s, 0
		}
	}
	if isImage {
		t, err := backend.OpenFile(path, backend.FileOptions{SectorSize: sector})
		if err != nil {
			fmt.Fprintln(stderr, "shunya: wipe:", err)
			return nil, 1
		}
		defer t.Close()
		id := t.Identity()
		return &targetSpec{path: id.Path, isImage: true, id: id, media: engine.MediaImage, size: t.Size(), sector: t.SectorSize()}, 0
	}
	env, code := liveEnv(stderr)
	if code != 0 {
		return nil, code
	}
	v, err := backend.Check(env, path)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return nil, 1
	}
	if !v.Allowed {
		printVerdict(stderr, v)
		return nil, 1
	}
	d := v.Device
	devs := engine.TargetDevs{d.DevNum}
	for _, p := range d.Partitions {
		devs = append(devs, p.DevNum)
	}
	return &targetSpec{path: v.Path, id: backend.IdentityOf(v.Path, d), media: d.Media.Type, virtual: d.Media.Virtual,
		size: int64(d.SizeBytes), sector: int(d.LogicalSectorSize), devs: devs, verdict: v,
		transport: d.Transport, firmware: d.Firmware}, 0
}

// open opens the target for writing with every guard (block devices re-run Check).
func (s *targetSpec) open(f wipeFlags, execute bool, stderr io.Writer) (backend.Target, int) {
	if s.isImage {
		t, err := backend.OpenFile(s.path, backend.FileOptions{Options: backend.Options{Execute: execute, Direct: f.direct}, SectorSize: s.sector})
		if err != nil {
			fmt.Fprintln(stderr, "shunya: wipe:", err)
			return nil, 1
		}
		return t, 0
	}
	if s.opener != nil {
		t, err := s.opener(execute)
		if err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return nil, 1
		}
		return t, 0
	}
	env, code := liveEnv(stderr)
	if code != 0 {
		return nil, code
	}
	conf, err := confirmation(f)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return nil, 2
	}
	t, err := backend.OpenBlock(env, s.path, backend.Options{Execute: execute, Direct: true, Confirm: conf})
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return nil, 1
	}
	return t, 0
}

func confirmation(f wipeFlags) (*backend.Confirmation, error) {
	if f.confirm == "" && !f.yesReally {
		return nil, nil
	}
	c := &backend.Confirmation{Typed: f.confirm, YesReally: f.yesReally}
	if f.yesReally {
		if f.approved == "" {
			return nil, errors.New("--yes-really needs --approved FILE")
		}
		b, err := os.ReadFile(f.approved)
		if err != nil {
			return nil, err
		}
		if c.Approved, err = backend.ParseApprovedList(b); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func parsePatterns(f wipeFlags) ([]string, error) {
	var ps []string
	for p := range strings.SplitSeq(f.patterns, ",") {
		if p = strings.TrimSpace(p); p != "" {
			ps = append(ps, p)
		}
	}
	if f.passes > 0 {
		if len(ps) != 1 {
			return nil, errors.New("--passes repeats a single --pattern")
		}
		for len(ps) < f.passes {
			ps = append(ps, ps[0])
		}
	}
	return ps, nil
}

func freshWipe(f wipeFlags, dev string, stdout, stderr io.Writer) int {
	path, isImage := dev, false
	if f.image != "" {
		path, isImage = f.image, true
	}
	spec, code := inspect(path, isImage, f.sector, stderr)
	if code != 0 {
		return code
	}
	patterns, err := parsePatterns(f)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return 2
	}
	hp, id, code := probeHidden(spec, f, stderr)
	if code != 0 {
		return code
	}
	size := spec.size
	if hp != nil && hp.RemoveHPA {
		size = int64(hp.Before.NativeSectors) * int64(spec.sector)
	}
	var plan engine.Plan
	erase := f.method != engine.MethodOverwrite
	if erase {
		if id == nil || hp == nil || !hp.Before.Checked {
			why := "it is an image file"
			if hp != nil {
				why = hp.Before.Reason
			}
			fmt.Fprintf(stderr, "shunya: wipe: --method %s needs an ATA drive that answers IDENTIFY; %s\n", f.method, why)
			return 2
		}
		plan, err = engine.NewErasePlan(engine.EraseInput{Target: spec.id, Media: spec.media, Virtual: spec.virtual,
			SizeBytes: size, SectorSize: spec.sector, Enhanced: f.method == engine.MethodATAEnhancedErase, Hidden: hp,
			ChunkBytes: f.chunkMiB << 20})
	} else {
		plan, err = engine.NewPlan(engine.PlanInput{Target: spec.id, Media: spec.media, Virtual: spec.virtual,
			SizeBytes: size, SectorSize: spec.sector, Patterns: patterns,
			ChunkBytes: f.chunkMiB << 20, SyncEvery: int64(f.syncMiB) << 20, Hidden: hp})
	}
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe: plan:", err)
		return 2
	}
	if plan.VerifyPattern == "" && (f.verify || f.sample > 0) {
		fmt.Fprintln(stderr, "shunya: wipe: an enhanced Security Erase leaves a vendor-defined pattern; there is nothing to verify against (drop --verify/--sample)")
		return 2
	}
	var refusal error
	if erase {
		refusal = ata.CheckErase(id, f.method == engine.MethodATAEnhancedErase, false)
	}
	if !f.execute {
		if f.asJSON {
			return writeJSON(stdout, stderr, plan)
		}
		printPlan(stdout, plan)
		if refusal != nil {
			fmt.Fprintf(stdout, "\nPRECONDITIONS NOT MET: %v\n", refusal)
			return 1
		}
		opened := "the device was not opened"
		if id != nil {
			opened = "the device was opened read-only for ATA IDENTIFY, READ NATIVE MAX and DCO IDENTIFY only"
		}
		fmt.Fprintf(stdout, "\nDRY RUN: nothing was written; %s. Add --execute --journal FILE --key FILE to wipe.\n", opened)
		return 0
	}
	if refusal != nil {
		printPlan(stdout, plan)
		fmt.Fprintf(stderr, "shunya: wipe: %v\n", refusal)
		return 1
	}
	if f.journal == "" || f.key == "" {
		fmt.Fprintln(stderr, "shunya: wipe --execute needs --journal FILE (on the tool's own medium) and --key FILE")
		return 2
	}
	key, err := journal.LoadKeyFile(f.key)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return 1
	}
	imagePath := ""
	if isImage {
		imagePath = spec.path
	}
	if err := engine.CheckJournalPlacement(f.journal, imagePath, spec.devs); err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return 1
	}
	if err := plan.GenerateKeys(nil); err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return 1
	}
	printPlan(stdout, plan)
	tg, code := spec.open(f, true, stderr)
	if code != 0 {
		return code
	}
	defer tg.Close()
	w, err := journal.Create(f.journal, key)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return 1
	}
	defer w.Close()
	rec := engine.JournalRecorder{W: w}
	wipeID := engine.NewWipeID()
	if err := rec.Start(wipeID, "shunya "+version, plan); err != nil {
		fmt.Fprintln(stderr, "shunya: wipe: journal:", err)
		return 1
	}
	fmt.Fprintf(stdout, "\nwipe %s started; journal %s\n", wipeID, f.journal)
	return runWipe(tg, plan, rec, nil, engine.RunOptions{}, f, stdout, stderr)
}

// runWipe executes a plan on an opened target: HPA removal first if planned, then the
// overwrite or the Security Erase, verification, and the HPA policy last (only after a
// completed wipe; an interrupted one leaves the HPA removed until power-off or resume).
func runWipe(tg backend.Target, plan engine.Plan, rec engine.JournalRecorder, st *engine.State, opts engine.RunOptions, f wipeFlags, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dev, isATA := ataDevice(tg)
	work := tg
	removeHPA := plan.Hidden != nil && plan.Hidden.RemoveHPA
	if (removeHPA || plan.Method != engine.MethodOverwrite) && !isATA {
		fmt.Fprintln(stderr, "shunya: wipe: the plan needs ATA commands but this target has no ATA pass-through")
		return 1
	}
	if st != nil && st.Password != "" && removeHPA {
		// A drive power-cycled with Shunya's password comes up locked, and a locked
		// drive aborts SET MAX: unlock it first (the erase then proceeds unlocked).
		if err := unlockForResume(ctx, dev, st.Password, rec); err != nil {
			rec.Failed(0, 0, err)
			fmt.Fprintf(stdout, "FAILED: %v\n", err)
			return 1
		}
	}
	if removeHPA {
		if err := ensureHPARemoved(ctx, dev, plan, rec, stdout); err != nil {
			rec.Failed(opts.StartPass, opts.StartOffset, err)
			fmt.Fprintf(stdout, "FAILED: %v\n", err)
			return 1
		}
		s, err := hiddenSpan(ctx, tg, dev, plan)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: wipe:", err)
			return 1
		}
		work = s
	}
	var code int
	if plan.Method == engine.MethodOverwrite {
		code = execute(ctx, work, plan, rec, opts, f, stdout, stderr)
	} else if code = secureErase(ctx, dev, plan, rec, st, f, stdout); code == 0 {
		code = verifyAndRecord(ctx, work, plan, rec, f, "", stdout, stderr)
	}
	if removeHPA {
		switch code {
		case 0, exitVerifyFail:
			code = max(code, finishHPA(ctx, dev, plan, rec, stdout))
		default:
			fmt.Fprintln(stdout, "The HPA stays removed until the drive is powered off or the wipe is resumed.")
		}
	}
	return code
}

func resumeWipe(f wipeFlags, stdout, stderr io.Writer) int {
	if !f.execute || f.journal == "" || f.key == "" {
		fmt.Fprintln(stderr, "shunya: wipe --resume needs --execute, --journal FILE and --key FILE")
		return 2
	}
	key, err := journal.LoadKeyFile(f.key)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return 1
	}
	w, log, err := journal.OpenAppend(f.journal, key)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe --resume:", err)
		return 1
	}
	defer w.Close()
	st, err := engine.Replay(log)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: wipe --resume:", err)
		return 1
	}
	plan := st.Plan
	if st.Done {
		fmt.Fprintf(stdout, "wipe %s is already complete (%s).\n", st.WipeID, st.Finished.Format(time.RFC3339))
		if !pendingHPARestore(st) {
			return 0
		}
		// Crash between the end of the wipe and the HPA restore.
		spec, code := inspect(plan.Target.Path, false, plan.SectorSize, stderr)
		if code != 0 {
			return code
		}
		if spec.id.Fingerprint != plan.Target.Fingerprint {
			fmt.Fprintf(stderr, "shunya: wipe --resume: %s is now %s, but the journal is for %s: refusing\n", spec.path, spec.id.Fingerprint, plan.Target.Fingerprint)
			return 1
		}
		tg, code := spec.open(f, true, stderr)
		if code != 0 {
			return code
		}
		defer tg.Close()
		dev, ok := ataDevice(tg)
		if !ok {
			fmt.Fprintln(stderr, "shunya: no ATA pass-through on this target")
			return 1
		}
		id, _, err := dev.Identify(context.Background())
		if err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
		if id.Sectors() == plan.Hidden.Before.ReportedSectors {
			fmt.Fprintln(stdout, "The HPA is already back (the drive was power-cycled).")
			rec := engine.JournalRecorder{W: w}
			if err := rec.Hidden(engine.HiddenEvent{Event: engine.HiddenRestored, State: plan.Hidden.Before, Note: "restored by a power cycle"}); err != nil {
				fmt.Fprintln(stderr, "shunya: journal:", err)
				return 1
			}
			return 0
		}
		return finishHPA(context.Background(), dev, plan, engine.JournalRecorder{W: w}, stdout)
	}
	isImage := plan.Media == engine.MediaImage
	spec, code := inspect(plan.Target.Path, isImage, plan.SectorSize, stderr)
	if code != 0 {
		return code
	}
	if spec.id.Fingerprint != plan.Target.Fingerprint {
		fmt.Fprintf(stderr, "shunya: wipe --resume: %s is now %s, but the journal is for %s: refusing\n",
			spec.path, spec.id.Fingerprint, plan.Target.Fingerprint)
		return 1
	}
	imagePath := ""
	if isImage {
		imagePath = spec.path
	}
	if err := engine.CheckJournalPlacement(f.journal, imagePath, spec.devs); err != nil {
		fmt.Fprintln(stderr, "shunya: wipe:", err)
		return 1
	}
	tg, code := spec.open(f, true, stderr)
	if code != 0 {
		return code
	}
	defer tg.Close()
	rec := engine.JournalRecorder{W: w}
	if err := rec.Resumed(st, log.TornBytes); err != nil {
		fmt.Fprintln(stderr, "shunya: wipe: journal:", err)
		return 1
	}
	how := st.Pending()
	if log.TornBytes > 0 {
		how += fmt.Sprintf(", %d-byte torn journal line discarded", log.TornBytes)
	}
	if plan.Method == engine.MethodOverwrite {
		fmt.Fprintf(stdout, "resuming wipe %s of %s at pass %d/%d, offset %d (previous run: %s)\n",
			st.WipeID, spec.path, st.Pass+1, len(plan.Passes), st.Offset, how)
	} else {
		last := st.SecurityStep
		if last == "" {
			last = "none"
		}
		fmt.Fprintf(stdout, "resuming wipe %s of %s (%s; last journaled step: %s; previous run: %s)\n",
			st.WipeID, spec.path, plan.Method, last, how)
	}
	return runWipe(tg, plan, rec, &st, engine.RunOptions{StartPass: st.Pass, StartOffset: st.Offset}, f, stdout, stderr)
}

// pendingHPARestore: the wipe is done, the plan restores the HPA, and the journal's last
// hidden-area event leaves it removed.
func pendingHPARestore(st engine.State) bool {
	h := st.Plan.Hidden
	if h == nil || !h.RemoveHPA || h.Policy != engine.HPARestore || len(st.HiddenEvents) == 0 {
		return false
	}
	switch st.HiddenEvents[len(st.HiddenEvents)-1].Event {
	case engine.HiddenRemoved, engine.HiddenAlreadyGone:
		return true
	}
	return false
}

// execute runs an overwrite with a progress line; ctx carries Ctrl-C/SIGTERM.
func execute(ctx context.Context, tg backend.Target, plan engine.Plan, rec engine.JournalRecorder, opts engine.RunOptions, f wipeFlags, stdout, stderr io.Writer) int {
	ch := make(chan engine.Progress, 16)
	opts.Progress = ch
	printed := make(chan struct{})
	go func() {
		defer close(printed)
		var last time.Time
		for p := range ch {
			if time.Since(last) >= 500*time.Millisecond || p.Done == p.Total {
				last = time.Now()
				fmt.Fprintf(stderr, "\r%s", progressLine(p))
			}
		}
		fmt.Fprintln(stderr)
	}()
	res, err := engine.Run(ctx, wrapTarget(tg), plan, rec, opts)
	<-printed
	switch {
	case errors.Is(err, engine.ErrInterrupted):
		fmt.Fprintf(stdout, "INTERRUPTED: %v\nThe journal records the synced position. Resume with:\n  shunya wipe --resume --execute --journal %s --key %s\n",
			err, f.journal, f.key)
		return exitInterrupted
	case err != nil:
		fmt.Fprintf(stdout, "FAILED: %v\nThe journal records the last synced position; fix the cause and --resume.\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "DONE: %d pass(es), %s written in this run (%s, %.0f MB/s). NIST SP 800-88 level: Clear.\n",
		len(plan.Passes), human(uint64(res.BytesWritten)), res.Elapsed.Round(time.Millisecond),
		float64(res.BytesWritten)/max(res.Elapsed.Seconds(), 1e-9)/1e6)
	return verifyAndRecord(ctx, tg, plan, rec, f, "", stdout, stderr)
}

func mustHex(s string) []byte {
	if s == "" {
		return nil
	}
	b, _ := hex.DecodeString(s)
	return b
}

func progressLine(p engine.Progress) string {
	pct := 100 * float64(p.Done) / float64(max(p.Total, 1))
	return fmt.Sprintf("pass %d/%d %-6s %5.1f%%  %s / %s  %.0f MB/s  ETA %s   ", p.Pass+1, p.Passes, p.Pattern, pct,
		human(uint64(p.Done)), human(uint64(p.Total)), p.BytesPerSec/1e6, p.ETA.Round(time.Second))
}

func printPlan(w io.Writer, p engine.Plan) {
	fmt.Fprintf(w, "PLAN  %s\n", p.Target.Path)
	fmt.Fprintf(w, "  device:      %s  serial %s  %s\n", orDash(p.Target.Model), orDash(p.Target.Serial), p.Target.Fingerprint)
	media := string(p.Media)
	if p.Virtual {
		media += " (virtual)"
	}
	fmt.Fprintf(w, "  media:       %s, %s, %d-byte sectors\n", media, human(uint64(p.SizeBytes)), p.SectorSize)
	if p.Method == engine.MethodOverwrite {
		var names []string
		for _, ps := range p.Passes {
			names = append(names, ps.Pattern)
		}
		fmt.Fprintf(w, "  method:      %s, %d pass(es): %s\n", p.Method, len(p.Passes), strings.Join(names, ", "))
	} else {
		fmt.Fprintf(w, "  method:      %s (firmware erase; no host writes)\n", p.Method)
	}
	fmt.Fprintf(w, "  NIST level:  %s (SP 800-88 Rev. 1)\n", levelName(p.Level))
	if p.Method == engine.MethodOverwrite {
		fmt.Fprintf(w, "  writes:      %d MiB chunks, sync + journal checkpoint every %d MiB\n", p.ChunkBytes>>20, p.SyncEveryBytes>>20)
	}
	fmt.Fprintf(w, "  estimate:    ~%s\n", estimate(p))
	switch h := p.Hidden; {
	case h == nil && p.Media == engine.MediaImage:
		fmt.Fprintln(w, "  hidden areas: n/a (image file)")
	case h == nil:
		fmt.Fprintln(w, "  hidden areas: not checked")
	default:
		fmt.Fprintf(w, "  hidden areas: %s\n", h.Before.Summary())
		if h.RemoveHPA {
			fmt.Fprintf(w, "  HPA:         removed for the wipe (volatile), then %s\n", map[string]string{engine.HPARestore: "restored", engine.HPALeaveRemoved: "left removed until power-off"}[h.Policy])
		}
		if h.NativeFingerprint != "" {
			fmt.Fprintf(w, "  native fp:   %s\n", h.NativeFingerprint)
		}
	}
	for _, n := range p.Notes {
		fmt.Fprintf(w, "  - %s\n", n)
	}
}

func cmdJournal(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "show" {
		fmt.Fprint(stderr, "usage: shunya journal show (--key FILE | --pub HEX) [--json] JOURNAL\n")
		return 2
	}
	fl := flag.NewFlagSet("journal show", flag.ContinueOnError)
	fl.SetOutput(stderr)
	keyFile := fl.String("key", "", "station key file")
	pubHex := fl.String("pub", "", "station public key (hex), instead of --key")
	asJSON := fl.Bool("json", false, "print JSON")
	if err := fl.Parse(args[1:]); err != nil || fl.NArg() != 1 || (*keyFile == "") == (*pubHex == "") {
		fmt.Fprint(stderr, "usage: shunya journal show (--key FILE | --pub HEX) [--json] JOURNAL\n")
		return 2
	}
	var pub ed25519.PublicKey
	if *keyFile != "" {
		k, err := journal.LoadKeyFile(*keyFile)
		if err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
		pub = k.Public().(ed25519.PublicKey)
	} else {
		b, err := hex.DecodeString(*pubHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			fmt.Fprintln(stderr, "shunya: --pub: want 64 hex digits")
			return 2
		}
		pub = b
	}
	fh, err := journal.OpenRegular(fl.Arg(0), os.O_RDONLY)
	if err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		return 1
	}
	defer fh.Close()
	log, err := journal.Read(fh, pub)
	if err != nil {
		fmt.Fprintln(stdout, "INVALID:", err)
		return 1
	}
	st, err := engine.Replay(log)
	if err != nil {
		fmt.Fprintln(stdout, "INVALID:", err)
		return 1
	}
	if *asJSON {
		return writeJSON(stdout, stderr, map[string]any{"key": log.KeyID, "torn_bytes": log.TornBytes, "state": st, "records": log.Records})
	}
	fmt.Fprintf(stdout, "journal %s: %d records, signatures and hash chain valid (key %s)\n", fl.Arg(0), len(log.Records), log.KeyID)
	if log.TornBytes > 0 {
		fmt.Fprintf(stdout, "  torn final line: %d bytes (crash during an append; ignored)\n", log.TornBytes)
	}
	for _, r := range log.Records {
		if r.Type == engine.RecStart {
			fmt.Fprintf(stdout, "  %4d  %s  %-11s %s\n", r.Seq, r.Time, r.Type, "(plan)")
			continue
		}
		fmt.Fprintf(stdout, "  %4d  %s  %-11s %s\n", r.Seq, r.Time, r.Type, r.Data)
	}
	fmt.Fprintf(stdout, "wipe %s of %s (%s)\n", st.WipeID, st.Plan.Target.Path, st.Plan.Target.Fingerprint)
	switch {
	case st.Done:
		fmt.Fprintf(stdout, "  status: COMPLETE at %s\n", st.Finished.Format(time.RFC3339))
	default:
		fmt.Fprintf(stdout, "  status: INCOMPLETE at pass %d/%d offset %d (%s); resumable\n", st.Pass+1, len(st.Plan.Passes), st.Offset, st.Pending())
	}
	if st.Plan.Method != engine.MethodOverwrite {
		fmt.Fprintf(stdout, "  method: %s; security steps journaled: %d (last: %s)\n", st.Plan.Method, len(st.SecuritySteps), orDash(st.SecurityStep))
	}
	if h := st.Plan.Hidden; h != nil {
		fmt.Fprintf(stdout, "  hidden areas before: %s\n", h.Before.Summary())
		for _, e := range st.HiddenEvents {
			fmt.Fprintf(stdout, "    - %s: %s", e.Event, e.State.Summary())
			if e.Note != "" {
				fmt.Fprintf(stdout, " (%s)", e.Note)
			}
			fmt.Fprintln(stdout)
		}
	}
	fmt.Fprintf(stdout, "  interruptions: %d\n", len(st.Interruptions))
	for _, in := range st.Interruptions {
		fmt.Fprintf(stdout, "    - %s at pass %d offset %d", in.Kind, in.Pass+1, in.Offset)
		if in.Reason != "" {
			fmt.Fprintf(stdout, " (%s)", in.Reason)
		}
		if in.TornBytes > 0 {
			fmt.Fprintf(stdout, ", torn journal line %d bytes", in.TornBytes)
		}
		fmt.Fprintf(stdout, "; resumed %s\n", in.ResumedAt.Format(time.RFC3339))
	}
	return 0
}

func cmdKeys(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "gen-dev" {
		fmt.Fprint(stderr, "usage: shunya keys gen-dev FILE   (temporary station key until Milestone 7)\n")
		return 2
	}
	pub, err := journal.GenerateKeyFile(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys:", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (mode 0600)\nkey id: %s\npublic: %x\n", args[1], journal.KeyID(pub), []byte(pub))
	return 0
}

func levelName(l engine.Level) string {
	switch l {
	case engine.LevelClear:
		return "Clear"
	case engine.LevelPurge:
		return "Purge"
	}
	return string(l)
}
