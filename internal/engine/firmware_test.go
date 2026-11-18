package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/ata"
	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/journal"
	"shunya/internal/nvme"
	"shunya/internal/sanitize"
)

// qemuNVMe is the lab's QEMU controller and namespace (SANICAP 0, FNA 0, DLFEAT zeros),
// with capabilities patched per test.
func qemuNVMe(t *testing.T, sanicap uint32, fna uint8) *NVMePlan {
	t.Helper()
	cb, err := os.ReadFile(filepath.Join("..", "nvme", "testdata", "qemu-id-ctrl.bin"))
	if err != nil {
		t.Fatal(err)
	}
	nb, _ := os.ReadFile(filepath.Join("..", "nvme", "testdata", "qemu-id-ns.bin"))
	c, err := nvme.ParseController(cb)
	if err != nil {
		t.Fatal(err)
	}
	n, err := nvme.ParseNamespace(1, nb)
	if err != nil {
		t.Fatal(err)
	}
	c.Sanicap = nvme.Sanicap{Raw: sanicap, Crypto: sanicap&1 != 0, Block: sanicap&2 != 0, Overwrite: sanicap&4 != 0}
	c.FNA = nvme.FNA{Raw: fna, CryptoErase: fna&4 != 0}
	return &NVMePlan{Controller: *c, Namespace: *n, Active: []uint32{1}}
}

var nid = backend.Identity{Path: "/dev/nvme0n1", Fingerprint: "fp1:nv"}

func nvmePlan(t *testing.T, m string, nv *NVMePlan, virtual bool) (Plan, error) {
	return NewFirmwarePlan(FirmwareInput{Target: nid, Media: device.MediaNVMeSSD, Virtual: virtual, SizeBytes: int64(nv.Namespace.SizeBytes()),
		SectorSize: nv.Namespace.BlockBytes(), Method: m, NVMe: nv})
}

func TestNVMeFirmwarePlans(t *testing.T) {
	nv := qemuNVMe(t, 7, 4)
	tests := []struct {
		m       string
		pattern string
	}{
		{MethodNVMeSanitizeCrypto, ""}, {MethodNVMeSanitizeBlock, PatternZero}, {MethodNVMeSanitizeOverwrite, PatternZero},
		{MethodNVMeFormatCrypto, ""}, {MethodNVMeFormatUserData, PatternZero},
	}
	for _, tc := range tests {
		p, err := nvmePlan(t, tc.m, nv, false)
		if err != nil {
			t.Fatalf("%s: %v", tc.m, err)
		}
		if p.Level != LevelPurge || p.VerifyPattern != tc.pattern || p.Markers == nil || p.Markers.Count != DefaultMarkers {
			t.Errorf("%s: %+v", tc.m, p)
		}
		if err := p.GenerateKeys(nil); err != nil || p.Validate() != nil || len(p.Markers.Key) != 64 {
			t.Errorf("%s: keys %v %v", tc.m, err, p.Validate())
		}
		// Virtual: never Purge.
		pv, _ := nvmePlan(t, tc.m, nv, true)
		if pv.Level != LevelClear || !strings.Contains(strings.Join(pv.Notes, " "), "virtual") {
			t.Errorf("%s virtual: %s", tc.m, pv.Level)
		}
		// A plan claiming Purge for a virtual disk fails validation.
		pv.Level = LevelPurge
		pv.GenerateKeys(nil)
		if pv.Validate() == nil {
			t.Errorf("%s: Purge on virtual accepted", tc.m)
		}
	}
	// Dealloc reads not reported: no pattern to verify after a block erase.
	nv2 := qemuNVMe(t, 2, 0)
	nv2.Namespace.DeallocRead = 0
	if p, _ := nvmePlan(t, MethodNVMeSanitizeBlock, nv2, false); p.VerifyPattern != "" {
		t.Errorf("pattern %q", p.VerifyPattern)
	}
}

func TestNVMeFirmwarePlanRefusals(t *testing.T) {
	qemu := qemuNVMe(t, 0, 0) // as the lab drive reports itself
	for _, m := range []string{MethodNVMeSanitizeCrypto, MethodNVMeSanitizeBlock, MethodNVMeSanitizeOverwrite, MethodNVMeFormatCrypto} {
		if _, err := nvmePlan(t, m, qemu, true); err == nil {
			t.Errorf("%s accepted on the QEMU controller", m)
		}
	}
	if _, err := nvmePlan(t, MethodNVMeFormatUserData, qemu, true); err != nil {
		t.Errorf("user data format refused: %v", err)
	}
	multi := qemuNVMe(t, 7, 4)
	multi.Active = []uint32{1, 2}
	if _, err := nvmePlan(t, MethodNVMeSanitizeBlock, multi, false); err == nil || !strings.Contains(err.Error(), "other namespace") {
		t.Errorf("multi-namespace sanitize: %v", err)
	}
	if _, err := NewFirmwarePlan(FirmwareInput{Target: nid, Method: MethodOverwrite}); err == nil {
		t.Error("overwrite as firmware method accepted")
	}
	wrongSize := qemuNVMe(t, 7, 4)
	if _, err := NewFirmwarePlan(FirmwareInput{Target: nid, Media: device.MediaNVMeSSD, SizeBytes: 4096, SectorSize: 512, Method: MethodNVMeSanitizeBlock, NVMe: wrongSize}); err == nil {
		t.Error("size mismatch accepted")
	}
}

func ataHidden(san *ata.Sanitize) *HiddenPlan {
	h := hiddenHPA()
	h.Sanitize = san
	return h
}

func TestATASanitizePlans(t *testing.T) {
	all := &ata.Sanitize{Supported: true, CryptoScramble: true, BlockErase: true, Overwrite: true}
	for m, pat := range map[string]string{MethodATASanitizeCrypto: "", MethodATASanitizeBlock: "", MethodATASanitizeOverwrite: PatternZero} {
		p, err := NewFirmwarePlan(FirmwareInput{Target: eid, Media: device.MediaSSD, SizeBytes: 2112 * 512, SectorSize: 512, Method: m, Hidden: ataHidden(all)})
		if err != nil || p.Level != LevelPurge || p.VerifyPattern != pat {
			t.Errorf("%s: %+v %v", m, p.Level, err)
		}
		if _, err := NewFirmwarePlan(FirmwareInput{Target: eid, Media: device.MediaSSD, SizeBytes: 2112 * 512, SectorSize: 512, Method: m,
			Hidden: ataHidden(&ata.Sanitize{})}); err == nil {
			t.Errorf("%s accepted without support", m)
		}
	}
}

func TestMarkers(t *testing.T) {
	tg := image(t, "", 2<<20, 512)
	m, err := NewMarkerPlan(64, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := PlantMarkers(ctx, tg, m, "fp1:x"); err != nil {
		t.Fatal(err)
	}
	r, err := CheckMarkers(ctx, tg, m, "fp1:x")
	if err != nil || r.Checked != 64 || r.Surviving != 64 || r.First != 0 {
		t.Fatalf("before erase: %+v %v", r, err)
	}
	// An "erase" that misses one marker sector is caught.
	tg.WriteAt(make([]byte, 2<<20-512), 0)
	r, _ = CheckMarkers(ctx, tg, m, "fp1:x")
	if r.Surviving != 1 || r.First != 2<<20-512 {
		t.Fatalf("partial erase: %+v", r)
	}
	tg.WriteAt(make([]byte, 512), 2<<20-512)
	if r, _ = CheckMarkers(ctx, tg, m, "fp1:x"); r.Surviving != 0 || r.First != -1 {
		t.Fatalf("after erase: %+v", r)
	}
	// Another run's markers (different key) don't count.
	m2, _ := NewMarkerPlan(64, nil)
	PlantMarkers(ctx, tg, m, "fp1:x")
	if r, _ = CheckMarkers(ctx, tg, m2, "fp1:x"); r.Surviving != 0 {
		t.Fatalf("foreign markers counted: %+v", r)
	}
}

func journalFor(t *testing.T, p Plan, f func(JournalRecorder)) error {
	t.Helper()
	jpath := filepath.Join(t.TempDir(), "j")
	w, _ := journal.Create(jpath, jkey)
	rec := JournalRecorder{W: w}
	if err := rec.Start("id", "t", p); err != nil {
		t.Fatal(err)
	}
	f(rec)
	w.Close()
	_, err := Replay(readLog(t, jpath))
	return err
}

func TestReplayFirmware(t *testing.T) {
	p, _ := nvmePlan(t, MethodNVMeSanitizeBlock, qemuNVMe(t, 2, 0), false)
	p.GenerateKeys(nil)
	ev := func(rec JournalRecorder, names ...string) {
		for _, n := range names {
			rec.Firmware(sanitize.Event{Event: n})
		}
	}
	good := func(rec JournalRecorder) {
		ev(rec, EvMarkersPlanted, sanitize.EvStarted, sanitize.EvProgress, sanitize.EvCompleted)
		rec.Done(0)
		rec.Verified(VerifiedData{Mode: "markers", OK: true})
	}
	if err := journalFor(t, p, good); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(JournalRecorder){
		"done before complete":     func(r JournalRecorder) { ev(r, EvMarkersPlanted, sanitize.EvStarted); r.Done(0) },
		"done without markers":     func(r JournalRecorder) { ev(r, sanitize.EvAttested); r.Done(0) },
		"started before markers":   func(r JournalRecorder) { ev(r, sanitize.EvStarted) },
		"format event in sanitize": func(r JournalRecorder) { ev(r, EvMarkersPlanted, EvFormatStarted) },
		"unknown event":            func(r JournalRecorder) { ev(r, "dco-restore") },
		"completed after failed":   func(r JournalRecorder) { ev(r, EvMarkersPlanted, sanitize.EvStarted, sanitize.EvFailed); r.Done(0) },
		"checkpoint":               func(r JournalRecorder) { r.Checkpoint(0, 512) },
		"security step":            func(r JournalRecorder) { r.Security(ata.Step{Step: ata.StepSetPassword, Password: "p"}) },
	} {
		if err := journalFor(t, p, f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Resume path: failed, then resumed and completed.
	if err := journalFor(t, p, func(r JournalRecorder) {
		ev(r, EvMarkersPlanted, sanitize.EvStarted, sanitize.EvFailed)
		r.Failed(0, 0, sanitize.ErrFailed)
		r.W.Append(RecResumed, ResumeData{After: StopError})
		ev(r, sanitize.EvStarted, sanitize.EvCompleted)
		r.Done(0)
	}); err != nil {
		t.Fatal(err)
	}
	// Overwrite journals take no firmware events.
	po, _ := NewPlan(PlanInput{Target: eid, Media: device.MediaHDD, SizeBytes: 1 << 20, SectorSize: 512})
	po.GenerateKeys(nil)
	if err := journalFor(t, po, func(r JournalRecorder) { ev(r, EvMarkersPlanted) }); err == nil {
		t.Error("firmware event in overwrite journal accepted")
	}
}

func TestRecommend(t *testing.T) {
	names := func(r Recommendation) (avail []string) {
		for _, o := range r.Options {
			if o.Available {
				avail = append(avail, o.Method)
			}
		}
		return
	}
	// The lab's QEMU NVMe drive: only Format user data erase and overwrite; virtual → Clear.
	r := Recommend(RecommendInput{Media: device.MediaNVMeSSD, Virtual: true, NVMe: qemuNVMe(t, 0, 0)})
	if r.Best != MethodNVMeFormatUserData || !strings.Contains(r.Reason, "virtual") || strings.Join(names(r), ",") != MethodNVMeFormatUserData+","+MethodOverwrite {
		t.Errorf("qemu: %+v", r)
	}
	for _, o := range r.Options {
		if o.Level != LevelClear || (!o.Available && o.Why == "") {
			t.Errorf("qemu option %+v", o)
		}
	}
	// A real NVMe drive with everything: crypto sanitize first.
	r = Recommend(RecommendInput{Media: device.MediaNVMeSSD, NVMe: qemuNVMe(t, 7, 4)})
	if r.Best != MethodNVMeSanitizeCrypto || r.Options[0].Level != LevelPurge {
		t.Errorf("full nvme: %+v", r)
	}
	// Block erase only.
	if r = Recommend(RecommendInput{Media: device.MediaNVMeSSD, NVMe: qemuNVMe(t, 2, 0)}); r.Best != MethodNVMeSanitizeBlock {
		t.Errorf("block only: %s", r.Best)
	}
	// SATA SSD with Security only: SE is Clear there, so no Purge; SE is chosen as the
	// strongest Clear method ahead of overwrite.
	h := ataHidden(nil)
	h.SolidState = true
	r = Recommend(RecommendInput{Media: device.MediaSSD, Hidden: h})
	if r.Best != MethodATAEnhancedErase || !strings.Contains(r.Reason, "no Purge") {
		t.Errorf("ssd SE: %+v", r)
	}
	// HDD with Security: Purge via enhanced SE; frozen → refused, overwrite chosen.
	r = Recommend(RecommendInput{Media: device.MediaHDD, Hidden: ataHidden(nil)})
	if r.Best != MethodATAEnhancedErase {
		t.Errorf("hdd: %+v", r)
	}
	frozen := map[string]error{MethodATAErase: ata.FrozenError(), MethodATAEnhancedErase: ata.FrozenError()}
	r = Recommend(RecommendInput{Media: device.MediaHDD, Hidden: ataHidden(nil), Preconditions: frozen})
	if r.Best != MethodOverwrite || !strings.Contains(r.Options[3].Why, "FROZEN") {
		t.Errorf("frozen: %+v", r)
	}
	// SATA SSD with Sanitize crypto scramble: Purge.
	r = Recommend(RecommendInput{Media: device.MediaSSD, Hidden: ataHidden(&ata.Sanitize{Supported: true, CryptoScramble: true})})
	if r.Best != MethodATASanitizeCrypto {
		t.Errorf("sanitize: %+v", r)
	}
	// Not ATA, not NVMe (virtio, USB without SAT): overwrite only.
	r = Recommend(RecommendInput{Media: device.MediaVirtual, Virtual: true, Hidden: &HiddenPlan{Before: ata.HiddenArea{Reason: "virtio"}}})
	if len(r.Options) != 1 || r.Best != MethodOverwrite {
		t.Errorf("virtio: %+v", r)
	}
}
