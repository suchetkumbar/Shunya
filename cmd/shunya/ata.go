package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"shunya/internal/ata"
	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/engine"
	"shunya/internal/journal"
)

// ataDevice returns the ATA command interface of an opened target, if it has one (a
// SATA block device; the simulated drive in tests).
func ataDevice(tg backend.Target) (ata.Device, bool) {
	tr, ok := tg.(ata.Transport)
	return ata.Device{T: tr}, ok
}

// notATAReason explains why hidden areas are not checked for a transport.
func notATAReason(t device.Transport) string {
	switch t {
	case device.TransportNVMe:
		return "NVMe drive: ATA HPA/DCO do not exist on NVMe (namespace capacity is checked in Milestone 6)"
	case device.TransportVirtio:
		return "virtio disk: the hypervisor presents no ATA interface, so HPA/DCO cannot exist or be queried"
	case device.TransportMMC:
		return "MMC/SD device: no ATA interface"
	}
	return string(t) + " device: not an ATA drive, so ATA HPA/DCO commands do not apply"
}

// identityMismatch compares what IDENTIFY says with what sysfs said at selection.
func identityMismatch(spec *targetSpec, id *ata.Identify) string {
	var why []string
	if s := strings.TrimSpace(spec.id.Serial); s != "" && s != id.Serial {
		why = append(why, fmt.Sprintf("IDENTIFY serial %q, the system reports %q", id.Serial, s))
	}
	// SCSI INQUIRY truncates the model to 16 characters; compare the common prefix.
	if m := strings.TrimSpace(spec.id.Model); m != "" && !strings.HasPrefix(id.Model, m) && !strings.HasSuffix(id.Model, m) {
		why = append(why, fmt.Sprintf("IDENTIFY model %q, the system reports %q", id.Model, m))
	}
	if w := strings.TrimPrefix(spec.id.WWID, "naa."); id.WWN != "" && strings.HasPrefix(spec.id.WWID, "naa.") && w != id.WWN {
		why = append(why, fmt.Sprintf("IDENTIFY WWN %s, the system reports %s", id.WWN, spec.id.WWID))
	}
	return strings.Join(why, "; ")
}

// probeHidden reads IDENTIFY and the hidden-area state of a device target. The device
// is opened read-only and only read-only ATA commands are sent. Returns nil for image
// files.
func probeHidden(spec *targetSpec, f wipeFlags, stderr io.Writer) (*engine.HiddenPlan, *ata.Identify, int) {
	if spec.isImage {
		return nil, nil, 0
	}
	hp := &engine.HiddenPlan{VisibleBytes: spec.size}
	if !backend.ATATransports[spec.transport] {
		hp.Before.Reason = notATAReason(spec.transport)
		return hp, nil, 0
	}
	if backend.RequiresConfirmation() && f.confirm == "" && !f.yesReally {
		hp.Before.Reason = "not probed: a release build opens a drive (even read-only) only after confirmation; add --confirm"
		return hp, nil, 0
	}
	tg, code := spec.open(f, false, stderr)
	if code != 0 {
		return nil, nil, code
	}
	defer tg.Close()
	dev, ok := ataDevice(tg)
	if !ok {
		hp.Before.Reason = "this target has no ATA pass-through"
		return hp, nil, 0
	}
	ctx := context.Background()
	id, _, err := dev.Identify(ctx)
	switch {
	case errors.Is(err, ata.ErrNoPassThrough), errors.Is(err, ata.ErrNotATA):
		hp.Before.Reason = "the drive or its USB bridge does not answer ATA commands (" + err.Error() + ")"
		return hp, nil, 0
	case err != nil:
		fmt.Fprintln(stderr, "shunya: ATA IDENTIFY:", err)
		return nil, nil, 1
	}
	if why := identityMismatch(spec, id); why != "" {
		if spec.transport == device.TransportUSB {
			hp.Before.Reason = "behind a USB bridge the ATA identity cannot be tied to the selected device (" + why + ")"
			return hp, id, 0
		}
		fmt.Fprintf(stderr, "shunya: refusing %s: %s\n", spec.path, why)
		return nil, nil, 1
	}
	if got := id.Sectors() * uint64(id.LogicalSectorBytes); got != uint64(spec.size) {
		fmt.Fprintf(stderr, "shunya: refusing %s: IDENTIFY reports %d bytes, the kernel sees %d. The drive's maximum address changed since the kernel read it (an HPA set or removed in this power cycle?). Power-cycle the drive and try again.\n",
			spec.path, got, spec.size)
		return nil, nil, 1
	}
	h, err := ata.ProbeHidden(ctx, dev, id)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: hidden areas:", err)
		return nil, nil, 1
	}
	hp.Before = h
	hp.SolidState = id.SolidState()
	sec := id.Security
	hp.Security = &sec
	if h.Checked {
		hp.NativeFingerprint = device.ComputeFingerprintV2(device.FingerprintInput{Model: spec.id.Model, Serial: spec.id.Serial,
			WWID: spec.id.WWID, Firmware: spec.firmware, CapacityBytes: uint64(spec.size)}, h.NativeSectors*uint64(h.SectorBytes)).Value
	}
	if h.HPA {
		switch {
		case f.hpa == "skip":
			hp.KeepReason = "the operator chose --hpa skip"
		case h.SectorBytes != ata.SectorBytes:
			hp.KeepReason = fmt.Sprintf("hidden-range writes support 512-byte sectors only, this drive has %d", h.SectorBytes)
		default:
			hp.RemoveHPA, hp.Policy = true, f.hpa
		}
	}
	return hp, id, 0
}

// hiddenState re-reads the hidden-area state (after a change, for the journal).
func hiddenState(ctx context.Context, dev ata.Device) (ata.HiddenArea, error) {
	id, _, err := dev.Identify(ctx)
	if err != nil {
		return ata.HiddenArea{}, err
	}
	return ata.ProbeHidden(ctx, dev, id)
}

// ensureHPARemoved makes the plan's hidden range addressable (volatile SET MAX) and
// journals it. On a resume the HPA may still be removed (no power cycle since).
func ensureHPARemoved(ctx context.Context, dev ata.Device, plan engine.Plan, rec engine.JournalRecorder, stdout io.Writer) error {
	h := plan.Hidden.Before
	id, _, err := dev.Identify(ctx)
	if err != nil {
		return err
	}
	ev := engine.HiddenRemoved
	switch id.Sectors() {
	case h.NativeSectors:
		ev = engine.HiddenAlreadyGone
	case h.ReportedSectors:
		if err := ata.SetMaxVolatile(ctx, dev, h.NativeSectors); err != nil {
			return fmt.Errorf("remove HPA: %w", err)
		}
	default:
		return fmt.Errorf("drive reports %d sectors; the plan expects %d (HPA in place) or %d (removed)", id.Sectors(), h.ReportedSectors, h.NativeSectors)
	}
	st, err := hiddenState(ctx, dev)
	if err != nil {
		return err
	}
	if st.ReportedSectors != h.NativeSectors {
		return fmt.Errorf("after SET MAX the drive reports %d sectors, want %d", st.ReportedSectors, h.NativeSectors)
	}
	if err := rec.Hidden(engine.HiddenEvent{Event: ev, State: st}); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	fmt.Fprintf(stdout, "HPA removed for this power cycle (volatile SET MAX): %d hidden sectors are now part of the wipe.\n", h.HPASectors())
	return nil
}

// unlockForResume unlocks a drive left locked by an interrupted Security Erase, with the
// journaled password (journaled as a step first).
func unlockForResume(ctx context.Context, dev ata.Device, pw string, rec engine.JournalRecorder) error {
	id, _, err := dev.Identify(ctx)
	if err != nil {
		return err
	}
	if !id.Security.Locked {
		return nil
	}
	if id.Security.Frozen {
		return ata.FrozenError()
	}
	if err := rec.Security(ata.Step{Step: ata.StepUnlock}); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	c, data, err := ata.SecurityUnlockUser(pw)
	if err != nil {
		return err
	}
	if _, err := dev.Exec(ctx, c, data); err != nil {
		return fmt.Errorf("unlock with the journaled password: %w", err)
	}
	return nil
}

// hiddenSpan joins the visible device and the hidden range into the plan's target.
func hiddenSpan(ctx context.Context, tg backend.Target, dev ata.Device, plan engine.Plan) (backend.Target, error) {
	h := plan.Hidden.Before
	r, err := ata.NewRangeTarget(ctx, dev, h.ReportedSectors, h.NativeSectors, tg.Identity())
	if err != nil {
		return nil, err
	}
	return ata.NewSpan(tg, r)
}

// finishHPA applies the HPA policy after a completed wipe. A failed restore is
// reported and journaled but does not fail the wipe: the removal was volatile.
func finishHPA(ctx context.Context, dev ata.Device, plan engine.Plan, rec engine.JournalRecorder, stdout io.Writer) int {
	hp := plan.Hidden
	ev, note := engine.HiddenLeftRemoved, ""
	if hp.Policy == engine.HPARestore {
		ev = engine.HiddenRestored
		if err := ata.SetMaxVolatile(ctx, dev, hp.Before.ReportedSectors); err != nil {
			ev, note = engine.HiddenRestoreFailed, err.Error()
		}
	}
	st, err := hiddenState(ctx, dev)
	if err != nil {
		fmt.Fprintln(stdout, "WARNING: hidden-area state after the wipe could not be read:", err)
		return 1
	}
	if err := rec.Hidden(engine.HiddenEvent{Event: ev, State: st, Note: note}); err != nil {
		fmt.Fprintln(stdout, "WARNING: journal:", err)
		return 1
	}
	switch ev {
	case engine.HiddenRestored:
		fmt.Fprintf(stdout, "HPA restored: the drive reports %d sectors again (as before the wipe).\n", st.ReportedSectors)
	case engine.HiddenRestoreFailed:
		fmt.Fprintf(stdout, "WARNING: the HPA could not be restored (%s). It was removed only until power-off: the original size returns at the next power cycle.\n", note)
	default:
		fmt.Fprintf(stdout, "HPA left removed (--hpa leave-removed): the drive reports %d sectors until its next power cycle.\n", st.ReportedSectors)
	}
	return 0
}

// secureErase runs (or resumes) the ATA Security Erase of plan and records done.
func secureErase(ctx context.Context, dev ata.Device, plan engine.Plan, rec engine.JournalRecorder, st *engine.State, f wipeFlags, stdout io.Writer) int {
	o := ata.EraseOptions{Enhanced: plan.Method == engine.MethodATAEnhancedErase, Record: rec.Security}
	if st != nil {
		o.Password, o.Resume = st.Password, st.SecurityStep
	}
	if o.Password == "" {
		pw, err := ata.NewPassword(nil)
		if err != nil {
			fmt.Fprintln(stdout, "FAILED:", err)
			return 1
		}
		o.Password = pw
	}
	fmt.Fprintf(stdout, "ATA Security Erase (%s) starting. Once ERASE UNIT is sent it cannot be cancelled; do not power the drive off (drive estimate: %s).\n",
		ata.ModeName(o.Enhanced), (estimate(plan)).String())
	after, err := ata.SecureErase(ctx, dev, o)
	if err != nil {
		rec.Failed(0, 0, err)
		fmt.Fprintf(stdout, "FAILED: %v\n", err)
		var ref *ata.EraseRefusal
		if !errors.As(err, &ref) {
			fmt.Fprintf(stdout, "The temporary password is in the journal. If the drive is now locked, recover it with:\n  shunya ata unlock --journal %s --key %s\nthen start the erase again with: shunya wipe --resume --execute --journal %s --key %s\n",
				f.journal, f.key, f.journal, f.key)
		}
		return 1
	}
	if err := rec.Done(0); err != nil {
		fmt.Fprintln(stdout, "FAILED: journal:", err)
		return 1
	}
	fmt.Fprintf(stdout, "DONE: ATA Security Erase (%s) completed; the drive's security state is back to disabled/unlocked (enabled=%v locked=%v). NIST SP 800-88 level: %s.\n",
		ata.ModeName(o.Enhanced), after.Enabled, after.Locked, levelName(plan.Level))
	return 0
}

// cmdATA: shunya ata identify|hidden|unlock.
func cmdATA(args []string, stdout, stderr io.Writer) int {
	const usage = "usage: shunya ata identify [--json] [--save FILE] DEVICE\n       shunya ata identify --dump FILE   (parse a saved dump or hdparm --Istdout output)\n       shunya ata hidden [--json] DEVICE\n       shunya ata unlock --execute --journal FILE --key FILE\n"
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "identify":
		return cmdATAIdentify(args[1:], stdout, stderr)
	case "hidden":
		return cmdATAHidden(args[1:], stdout, stderr)
	case "unlock":
		return cmdATAUnlock(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

func cmdATAIdentify(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("ata identify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "print JSON")
	save := fl.String("save", "", "also write the raw IDENTIFY data in hdparm --Istdout form to FILE")
	dump := fl.String("dump", "", "parse this saved dump instead of asking a device")
	confirm := fl.String("confirm", "", "release builds: last 4 characters of the serial")
	if err := fl.Parse(args); err != nil || (fl.NArg() == 1) == (*dump != "") {
		fmt.Fprint(stderr, "usage: shunya ata identify [--json] [--save FILE] DEVICE | --dump FILE\n")
		return 2
	}
	var raw []byte
	if *dump != "" {
		b, err := os.ReadFile(*dump)
		if err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
		raw = b
		if len(b) != 512 {
			if raw, err = ata.ParseHdparmDump(b); err != nil {
				fmt.Fprintln(stderr, "shunya:", err)
				return 1
			}
		}
	} else {
		tg, code := openForATA(fl.Arg(0), *confirm, stderr)
		if code != 0 {
			return code
		}
		defer tg.Close()
		dev, _ := ataDevice(tg)
		var err error
		if _, raw, err = dev.Identify(context.Background()); err != nil && raw == nil {
			fmt.Fprintln(stderr, "shunya: ata identify:", err)
			return 1
		}
	}
	id, err := ata.ParseIdentify(raw)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: ata identify:", err)
		return 1
	}
	if *save != "" {
		hdr := "# IDENTIFY DEVICE recorded by shunya " + version + "\n"
		if err := os.WriteFile(*save, []byte(hdr+ata.FormatHdparmDump(raw)), 0o644); err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
	}
	if *asJSON {
		return writeJSON(stdout, stderr, id)
	}
	printIdentify(stdout, id)
	return 0
}

func printIdentify(w io.Writer, id *ata.Identify) {
	fmt.Fprintf(w, "model:     %s\nserial:    %s\nfirmware:  %s\n", id.Model, id.Serial, id.Firmware)
	if id.WWN != "" {
		fmt.Fprintf(w, "wwn:       %s\n", id.WWN)
	}
	fmt.Fprintf(w, "capacity:  %d sectors (%s), %d-byte logical / %d-byte physical sectors, 48-bit: %v\n",
		id.Sectors(), human(id.Sectors()*uint64(id.LogicalSectorBytes)), id.LogicalSectorBytes, id.PhysicalSectorBytes, id.Supports48)
	media := "not reported"
	switch {
	case id.SolidState():
		media = "solid state (word 217 = 1)"
	case id.RotationRPM > 0:
		media = fmt.Sprintf("rotating, %d rpm", id.RotationRPM)
	}
	fmt.Fprintf(w, "media:     %s; TRIM: %v\n", media, id.TRIM)
	fmt.Fprintf(w, "features:  HPA %v, DCO %v, Sanitize %v (crypto %v, block %v, overwrite %v)\n", id.HPASupported, id.DCOSupported,
		id.Sanitize.Supported, id.Sanitize.CryptoScramble, id.Sanitize.BlockErase, id.Sanitize.Overwrite)
	s := id.Security
	if !s.Supported {
		fmt.Fprintln(w, "security:  not supported")
	} else {
		fmt.Fprintf(w, "security:  supported; enabled %v, locked %v, frozen %v, count expired %v, enhanced erase %v, level %s\n",
			s.Enabled, s.Locked, s.Frozen, s.CountExpired, s.EnhancedSupported, map[bool]string{true: "maximum", false: "high"}[s.LevelMaximum])
		fmt.Fprintf(w, "erase time: normal %s, enhanced %s\n", minutes(s.NormalEraseMinutes), minutes(s.EnhancedEraseMinutes))
		if s.Frozen {
			fmt.Fprintln(w, "note:      "+ata.FrozenHelp)
		}
	}
	fmt.Fprintf(w, "checksum:  %s\n", id.Checksum)
}

func minutes(m int) string {
	switch {
	case m == 0:
		return "not reported"
	case m < 0:
		return "longer than the field can express"
	}
	return fmt.Sprintf("%d min", m)
}

// openForATA selects and opens a device read-only for ATA queries.
func openForATA(path, confirm string, stderr io.Writer) (backend.Target, int) {
	spec, code := inspect(path, false, 0, stderr)
	if code != 0 {
		return nil, code
	}
	if !backend.ATATransports[spec.transport] {
		fmt.Fprintf(stderr, "shunya: %s: %s\n", spec.path, notATAReason(spec.transport))
		return nil, 1
	}
	tg, code := spec.open(wipeFlags{confirm: confirm}, false, stderr)
	if code != 0 {
		return nil, code
	}
	if _, ok := ataDevice(tg); !ok {
		tg.Close()
		fmt.Fprintln(stderr, "shunya: no ATA pass-through on this target")
		return nil, 1
	}
	return tg, 0
}

func cmdATAHidden(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("ata hidden", flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "print JSON")
	confirm := fl.String("confirm", "", "release builds: last 4 characters of the serial")
	if err := fl.Parse(args); err != nil || fl.NArg() != 1 {
		fmt.Fprint(stderr, "usage: shunya ata hidden [--json] DEVICE\n")
		return 2
	}
	spec, code := inspect(fl.Arg(0), false, 0, stderr)
	if code != 0 {
		return code
	}
	hp, _, code := probeHidden(spec, wipeFlags{confirm: *confirm, hpa: engine.HPARestore}, stderr)
	if code != 0 {
		return code
	}
	if *asJSON {
		return writeJSON(stdout, stderr, hp)
	}
	fmt.Fprintf(stdout, "%s: %s\n", spec.path, hp.Before.Summary())
	if hp.NativeFingerprint != "" {
		fmt.Fprintf(stdout, "native fingerprint (fp-v2): %s\n", hp.NativeFingerprint)
	}
	fmt.Fprintln(stdout, "(read-only: IDENTIFY, READ NATIVE MAX ADDRESS EXT and DEVICE CONFIGURATION IDENTIFY only)")
	return 0
}

// cmdATAUnlock removes Shunya's temporary password from a drive whose Security Erase was
// interrupted, using the password in the journal. It does not write the journal: the
// erase is not complete, and `wipe --resume` starts it again.
func cmdATAUnlock(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("ata unlock", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var f wipeFlags
	fl.BoolVar(&f.execute, "execute", false, "required: this sends SECURITY UNLOCK / DISABLE PASSWORD")
	fl.StringVar(&f.journal, "journal", "", "the erase's journal (holds the temporary password)")
	fl.StringVar(&f.key, "key", "", "station key")
	fl.StringVar(&f.confirm, "confirm", "", "release builds: last 4 characters of the serial")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || f.journal == "" || f.key == "" || !f.execute {
		fmt.Fprint(stderr, "usage: shunya ata unlock --execute --journal FILE --key FILE\n")
		return 2
	}
	key, err := journal.LoadKeyFile(f.key)
	if err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		return 1
	}
	fh, err := journal.OpenRegular(f.journal, os.O_RDONLY)
	if err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		return 1
	}
	log, err := journal.Read(fh, key.Public().(ed25519.PublicKey))
	fh.Close()
	if err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		return 1
	}
	st, err := engine.Replay(log)
	if err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		return 1
	}
	if st.Password == "" {
		fmt.Fprintf(stdout, "wipe %s never set a password (method %s): nothing to unlock.\n", st.WipeID, st.Plan.Method)
		return 0
	}
	spec, code := inspect(st.Plan.Target.Path, false, 0, stderr)
	if code != 0 {
		return code
	}
	if spec.id.Fingerprint != st.Plan.Target.Fingerprint {
		fmt.Fprintf(stderr, "shunya: %s is now %s, but the journal is for %s: refusing\n", spec.path, spec.id.Fingerprint, st.Plan.Target.Fingerprint)
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
	s, err := ata.Unlock(context.Background(), dev, st.Password)
	if err != nil {
		fmt.Fprintln(stdout, "FAILED:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: security disabled (enabled=%v locked=%v). The erase of wipe %s is NOT complete; run it again with:\n  shunya wipe --resume --execute --journal %s --key %s\n",
		spec.path, s.Enabled, s.Locked, st.WipeID, f.journal, f.key)
	return 0
}

func estimate(p engine.Plan) time.Duration {
	return (time.Duration(p.EstimateSeconds) * time.Second).Round(time.Second)
}
