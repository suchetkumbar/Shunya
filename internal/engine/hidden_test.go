package engine

import (
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/ata"
	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/journal"
	"shunya/internal/sanitize"
)

func hiddenHPA() *HiddenPlan {
	return &HiddenPlan{
		Before: ata.HiddenArea{Checked: true, ReportedSectors: 2048, NativeSectors: 2112, HPASupported: true, HPA: true,
			DCO: ata.DCOAbsent, DCOSectors: 2112, SectorBytes: 512},
		RemoveHPA: true, Policy: HPARestore, VisibleBytes: 2048 * 512,
		Security: &ata.Security{Supported: true, EnhancedSupported: true, NormalEraseMinutes: 10, EnhancedEraseMinutes: 10},
	}
}

var eid = backend.Identity{Path: "/dev/sda", Fingerprint: "fp1:ab"}

func TestErasePlanLevels(t *testing.T) {
	tests := []struct {
		name     string
		media    device.MediaType
		virtual  bool
		solid    bool
		enhanced bool
		want     Level
	}{
		{"hdd normal", device.MediaHDD, false, false, false, LevelPurge},
		{"hdd enhanced", device.MediaHDD, false, false, true, LevelPurge},
		{"ssd", device.MediaSSD, false, false, true, LevelClear},
		{"sysfs hdd but IDENTIFY solid state", device.MediaHDD, false, true, false, LevelClear},
		{"virtual hdd", device.MediaHDD, true, false, false, LevelClear},
		{"usb bridge", device.MediaUSBDisk, false, false, false, LevelClear},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := hiddenHPA()
			h.SolidState = tc.solid
			p, err := NewErasePlan(EraseInput{Target: eid, Media: tc.media, Virtual: tc.virtual, SizeBytes: 2112 * 512,
				SectorSize: 512, Enhanced: tc.enhanced, Hidden: h})
			if err != nil {
				t.Fatal(err)
			}
			if p.Level != tc.want {
				t.Fatalf("level %s, want %s", p.Level, tc.want)
			}
			p.GenerateKeys(nil)
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			notes := strings.Join(p.Notes, "\n")
			if (p.VerifyPattern == PatternZero) == tc.enhanced || !strings.Contains(notes, "Level: "+levelTitle(tc.want)) && !strings.Contains(notes, "level: "+levelTitle(tc.want)) {
				t.Errorf("verify %q, notes:\n%s", p.VerifyPattern, notes)
			}
			if p.EstimateSeconds != 600 {
				t.Errorf("estimate %v, want the drive's 10 minutes", p.EstimateSeconds)
			}
			// A plan claiming Purge where the media doesn't earn it is invalid.
			p.Level = LevelPurge
			if tc.want == LevelClear && p.Validate() == nil {
				t.Fatal("Purge claim accepted for " + tc.name)
			}
		})
	}
}

func levelTitle(l Level) string { return strings.ToUpper(string(l[:1])) + string(l[1:]) }

func TestPlanHiddenValidate(t *testing.T) {
	ok := func() PlanInput {
		return PlanInput{Target: eid, Media: device.MediaHDD, SizeBytes: 2112 * 512, SectorSize: 512, Hidden: hiddenHPA()}
	}
	if _, err := NewPlan(ok()); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*PlanInput){
		"size is the visible size":     func(in *PlanInput) { in.SizeBytes = 2048 * 512 },
		"no policy":                    func(in *PlanInput) { in.Hidden.Policy = "" },
		"bad policy":                   func(in *PlanInput) { in.Hidden.Policy = "dco-restore" },
		"removal without an HPA":       func(in *PlanInput) { in.Hidden.Before.HPA = false },
		"visible size wrong":           func(in *PlanInput) { in.Hidden.VisibleBytes = 100 * 512 },
		"sector size mismatch":         func(in *PlanInput) { in.Hidden.Before.SectorBytes = 4096 },
		"no removal, size not visible": func(in *PlanInput) { in.Hidden.RemoveHPA = false },
	} {
		in := ok()
		mod(&in)
		if _, err := NewPlan(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewErasePlan(EraseInput{Target: eid, Media: device.MediaHDD, SizeBytes: 1 << 20, SectorSize: 512}); err == nil {
		t.Error("erase plan without IDENTIFY state accepted")
	}
}

func TestHiddenNotes(t *testing.T) {
	h := hiddenHPA()
	h.Before.DCO, h.Before.DCOSectors = ata.DCOPresent, 4000
	p, err := NewPlan(PlanInput{Target: eid, Media: device.MediaHDD, SizeBytes: 2112 * 512, SectorSize: 512, Hidden: h})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(p.Notes, "\n")
	for _, want := range []string{"64 sectors hidden beyond the reported 2048", "volatile SET MAX", "restored to the original size",
		"hides 1888 sectors beyond the native maximum", "NOT wiped"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q:\n%s", want, all)
		}
	}
	for name, h := range map[string]*HiddenPlan{
		"not checked": {Before: ata.HiddenArea{Reason: "virtio disk: not an ATA device"}},
		"dco frozen":  {Before: ata.HiddenArea{Checked: true, HPASupported: true, ReportedSectors: 8, NativeSectors: 8, DCO: ata.DCOUnavailable}, VisibleBytes: 4096},
		"hpa kept":    {Before: ata.HiddenArea{Checked: true, HPASupported: true, HPA: true, ReportedSectors: 8, NativeSectors: 9, DCO: ata.DCONotSupported}, VisibleBytes: 4096},
	} {
		p, err := NewPlan(PlanInput{Target: eid, Media: device.MediaHDD, SizeBytes: 4096, SectorSize: 512, ChunkBytes: 4096, Hidden: h})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all := strings.Join(p.Notes, "\n")
		want := map[string]string{"not checked": "not checked: virtio disk", "dco frozen": "state unknown", "hpa kept": "1 sectors hidden and NOT wiped"}[name]
		if !strings.Contains(all, want) {
			t.Errorf("%s: notes lack %q:\n%s", name, want, all)
		}
	}
}

func erasePlan(t *testing.T) Plan {
	t.Helper()
	p, err := NewErasePlan(EraseInput{Target: eid, Media: device.MediaHDD, SizeBytes: 2112 * 512, SectorSize: 512, Hidden: hiddenHPA()})
	if err != nil {
		t.Fatal(err)
	}
	p.GenerateKeys(nil)
	return p
}

func TestReplayEraseJournal(t *testing.T) {
	jpath := filepath.Join(t.TempDir(), "j")
	w, _ := journal.Create(jpath, jkey)
	rec := JournalRecorder{w}
	if err := rec.Start("id", "t", erasePlan(t)); err != nil {
		t.Fatal(err)
	}
	removed := hiddenHPA().Before
	removed.ReportedSectors, removed.HPA = 2112, false
	rec.Hidden(HiddenEvent{Event: HiddenRemoved, State: removed})
	rec.Firmware(sanitize.Event{Event: EvMarkersPlanted})
	for _, s := range []ata.Step{{Step: ata.StepSetPassword, Password: "shunya-x"}, {Step: ata.StepErasePrepare},
		{Step: ata.StepEraseUnit, Mode: "normal"}, {Step: ata.StepEraseDone, Seconds: 3}, {Step: ata.StepChecked}} {
		rec.Security(s)
	}
	rec.Done(0)
	rec.Verified(VerifiedData{Mode: "sampled", Pattern: PatternZero, OK: true})
	rec.Hidden(HiddenEvent{Event: HiddenRestored, State: hiddenHPA().Before})
	w.Close()
	st, err := Replay(readLog(t, jpath))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Done || st.Password != "shunya-x" || st.SecurityStep != ata.StepChecked || len(st.SecuritySteps) != 5 ||
		len(st.HiddenEvents) != 2 || st.HiddenEvents[1].Event != HiddenRestored || len(st.Verifications) != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestReplayEraseRejects(t *testing.T) {
	cases := map[string]func(rec JournalRecorder){
		"done before checked": func(rec JournalRecorder) {
			rec.Security(ata.Step{Step: ata.StepSetPassword, Password: "p"})
			rec.Security(ata.Step{Step: ata.StepEraseDone})
			rec.Done(0)
		},
		"done without any step": func(rec JournalRecorder) { rec.Done(0) },
		"step before password":  func(rec JournalRecorder) { rec.Security(ata.Step{Step: ata.StepErasePrepare}) },
		"password missing":      func(rec JournalRecorder) { rec.Security(ata.Step{Step: ata.StepSetPassword}) },
		"unknown step":          func(rec JournalRecorder) { rec.Security(ata.Step{Step: "dco-restore", Password: "p"}) },
		"checkpoint":            func(rec JournalRecorder) { rec.Checkpoint(0, 512) },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			jpath := filepath.Join(t.TempDir(), "j")
			w, _ := journal.Create(jpath, jkey)
			rec := JournalRecorder{w}
			rec.Start("id", "t", erasePlan(t))
			rec.Firmware(sanitize.Event{Event: EvMarkersPlanted}) // isolate each case from the marker rule
			f(rec)
			w.Close()
			if _, err := Replay(readLog(t, jpath)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// Security steps and hidden events don't belong in a plain overwrite journal.
	for name, f := range map[string]func(rec JournalRecorder){
		"security in overwrite":  func(rec JournalRecorder) { rec.Security(ata.Step{Step: ata.StepSetPassword, Password: "p"}) },
		"hidden without removal": func(rec JournalRecorder) { rec.Hidden(HiddenEvent{Event: HiddenRemoved}) },
	} {
		jpath := filepath.Join(t.TempDir(), "j")
		w, _ := journal.Create(jpath, jkey)
		rec := JournalRecorder{w}
		p, _ := NewPlan(PlanInput{Target: eid, Media: device.MediaHDD, SizeBytes: 1 << 20, SectorSize: 512})
		p.GenerateKeys(nil)
		rec.Start("id", "t", p)
		f(rec)
		w.Close()
		if _, err := Replay(readLog(t, jpath)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
