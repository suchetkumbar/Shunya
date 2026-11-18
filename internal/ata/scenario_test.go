package ata_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"shunya/internal/ata"
	"shunya/internal/ata/atafake"
	"shunya/internal/backend"
)

// Scenario tests against the simulated drive (pending-real-hardware: QEMU emulates no
// HPA, DCO or Security feature set).

var ctx = context.Background()

func drive(t *testing.T, o atafake.Options) (*atafake.Drive, ata.Device) {
	t.Helper()
	dump, err := os.ReadFile(filepath.Join("testdata", "identify", "samsung-hd321kj.txt"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := atafake.New(dump, o)
	if err != nil {
		t.Fatal(err)
	}
	return d, ata.Device{T: d}
}

func identify(t *testing.T, dev ata.Device) *ata.Identify {
	t.Helper()
	id, _, err := dev.Identify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestProbeHidden(t *testing.T) {
	tests := []struct {
		name string
		o    atafake.Options
		want ata.HiddenArea
	}{
		{"no hpa", atafake.Options{Sectors: 1000, HPA: true},
			ata.HiddenArea{Checked: true, ReportedSectors: 1000, NativeSectors: 1000, HPASupported: true, DCO: ata.DCONotSupported, SectorBytes: 512}},
		{"hpa", atafake.Options{Sectors: 1000, NativeSectors: 1064},
			ata.HiddenArea{Checked: true, ReportedSectors: 1000, NativeSectors: 1064, HPASupported: true, HPA: true, DCO: ata.DCONotSupported, SectorBytes: 512}},
		{"hpa unsupported", atafake.Options{Sectors: 1000},
			ata.HiddenArea{Checked: true, ReportedSectors: 1000, NativeSectors: 1000, DCO: ata.DCONotSupported, SectorBytes: 512}},
		{"dco absent", atafake.Options{Sectors: 1000, HPA: true, DCO: true},
			ata.HiddenArea{Checked: true, ReportedSectors: 1000, NativeSectors: 1000, HPASupported: true, DCO: ata.DCOAbsent, DCOSectors: 1000, SectorBytes: 512}},
		{"dco present", atafake.Options{Sectors: 1000, NativeSectors: 1064, DCOSectors: 1200, DCO: true},
			ata.HiddenArea{Checked: true, ReportedSectors: 1000, NativeSectors: 1064, HPASupported: true, HPA: true, DCO: ata.DCOPresent, DCOSectors: 1200, SectorBytes: 512}},
		{"dco frozen", atafake.Options{Sectors: 1000, HPA: true, DCO: true, DCOFrozen: true},
			ata.HiddenArea{Checked: true, ReportedSectors: 1000, NativeSectors: 1000, HPASupported: true, DCO: ata.DCOUnavailable, SectorBytes: 512}},
		{"fixed sense", atafake.Options{Sectors: 1000, NativeSectors: 1064, FixedSense: true},
			ata.HiddenArea{Checked: true, ReportedSectors: 1000, NativeSectors: 1064, HPASupported: true, HPA: true, DCO: ata.DCONotSupported, SectorBytes: 512}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, dev := drive(t, tc.o)
			h, err := ata.ProbeHidden(ctx, dev, identify(t, dev))
			if err != nil {
				t.Fatal(err)
			}
			if h != tc.want {
				t.Errorf("\n got %+v\nwant %+v", h, tc.want)
			}
			if h.Summary() == "" {
				t.Error("empty summary")
			}
		})
	}
	h := ata.HiddenArea{Checked: true, ReportedSectors: 1000, NativeSectors: 1064, HPASupported: true, HPA: true, DCO: ata.DCOPresent, DCOSectors: 1200}
	if h.HPASectors() != 64 || h.DCOHiddenSectors() != 136 || !strings.Contains(h.Summary(), "HPA hides 64") {
		t.Errorf("%d %d %s", h.HPASectors(), h.DCOHiddenSectors(), h.Summary())
	}
}

// Fixed-format sense carries LBA 23:0 only: a native max beyond that is refused rather
// than misread.
func TestFixedSenseLargeLBARefused(t *testing.T) {
	_, dev := drive(t, atafake.Options{Sectors: 1 << 25, NativeSectors: 1<<25 + 8, FixedSense: true})
	if _, err := ata.ProbeHidden(ctx, dev, identify(t, dev)); err == nil || !strings.Contains(err.Error(), "descriptor sense") {
		t.Fatalf("%v", err)
	}
}

func TestNoPassThrough(t *testing.T) {
	_, dev := drive(t, atafake.Options{Sectors: 1000, NoSAT: true})
	if _, _, err := dev.Identify(ctx); !errors.Is(err, ata.ErrNoPassThrough) {
		t.Fatalf("%v", err)
	}
}

func TestSetMaxVolatile(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 1000, NativeSectors: 1064, OneSetMax: true})
	if err := ata.SetMaxVolatile(ctx, dev, 1064); err != nil {
		t.Fatal(err)
	}
	if cur, _, _, _ := d.State(); cur != 1064 {
		t.Fatalf("current %d", cur)
	}
	// One SET MAX per power cycle: restoring now is refused, and the error says why.
	err := ata.SetMaxVolatile(ctx, dev, 1000)
	if !ata.Aborted(err) || !strings.Contains(err.Error(), "one SET MAX per power cycle") {
		t.Fatalf("second SET MAX: %v", err)
	}
	// The removal was volatile: a power cycle brings the HPA back.
	d.PowerCycle()
	if cur, _, _, _ := d.State(); cur != 1000 {
		t.Fatalf("after power cycle: %d", cur)
	}
	if err := ata.SetMaxVolatile(ctx, dev, 2000); err == nil {
		t.Fatal("SET MAX beyond native accepted")
	}
	if d.NonVolatileAttempts != 0 {
		t.Fatal("a non-volatile SET MAX reached the drive")
	}
	// READ NATIVE MAX immediately precedes every SET MAX.
	for i, c := range d.Log {
		if c == "SET MAX EXT" && (i == 0 || d.Log[i-1] != "READ NATIVE MAX EXT") {
			t.Fatalf("SET MAX not preceded by READ NATIVE MAX: %v", d.Log)
		}
	}
}

func span(t *testing.T, d *atafake.Drive, dev ata.Device, reported, native uint64) *ata.Span {
	t.Helper()
	id := backend.Identity{Path: "/dev/fake", Fingerprint: "fp1:test"}
	vis := d.Visible(id, true)
	if vis.Size() != int64(reported)*512 {
		t.Fatalf("visible size %d", vis.Size())
	}
	r, err := ata.NewRangeTarget(ctx, dev, reported, native, id)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ata.NewSpan(vis, r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSpanReachesHiddenRange(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 1000, NativeSectors: 1600})
	s := span(t, d, dev, 1000, 1600)
	// Before the HPA is removed the drive refuses the hidden sectors (IDNF).
	buf := bytes.Repeat([]byte{0xab}, 1024)
	if _, err := s.WriteAt(buf, 1000*512); err == nil || !strings.Contains(err.Error(), "IDNF") {
		t.Fatalf("write behind HPA: %v", err)
	}
	if err := ata.SetMaxVolatile(ctx, dev, 1600); err != nil {
		t.Fatal(err)
	}
	// One write across the boundary, longer than one ATA command (256 sectors).
	big := bytes.Repeat([]byte{0x5a}, 400*512)
	if n, err := s.WriteAt(big, 900*512); err != nil || n != len(big) {
		t.Fatalf("write: %d %v", n, err)
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	for _, lba := range []uint64{899, 900, 999, 1000, 1299, 1300} {
		want := lba >= 900 && lba < 1300
		got := bytes.Equal(d.Sector(lba), bytes.Repeat([]byte{0x5a}, 512))
		if got != want {
			t.Errorf("sector %d written=%v", lba, got)
		}
	}
	back := make([]byte, len(big))
	if _, err := s.ReadAt(back, 900*512); err != nil || !bytes.Equal(back, big) {
		t.Fatalf("read back: %v", err)
	}
	if s.Size() != 1600*512 || s.HiddenFrom() != 1000*512 {
		t.Fatalf("size %d hidden from %d", s.Size(), s.HiddenFrom())
	}
	if _, err := s.WriteAt(buf, 1599*512); !errors.Is(err, backend.ErrOutOfRange) {
		t.Fatalf("past end: %v", err)
	}
	if !slices.Contains(d.Log, "FLUSH CACHE EXT") {
		t.Error("Sync did not flush the hidden range")
	}
}

func TestNewSpanChecks(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 1000, NativeSectors: 1600})
	vis := d.Visible(backend.Identity{}, true)
	r, _ := ata.NewRangeTarget(ctx, dev, 1001, 1600, backend.Identity{})
	if _, err := ata.NewSpan(vis, r); err == nil {
		t.Fatal("gap between visible and hidden accepted")
	}
	if _, err := ata.NewRangeTarget(ctx, dev, 5, 5, backend.Identity{}); err == nil {
		t.Fatal("empty range accepted")
	}
}

type steps struct{ got []ata.Step }

func (s *steps) record(st ata.Step) error { s.got = append(s.got, st); return nil }
func (s *steps) names() []string {
	var n []string
	for _, st := range s.got {
		n = append(n, st.Step)
	}
	return n
}

func plant(d *atafake.Drive, dev ata.Device, t *testing.T) {
	t.Helper()
	vis := d.Visible(backend.Identity{}, true)
	if _, err := vis.WriteAt(bytes.Repeat([]byte("secret!!"), 64*8), 0); err != nil {
		t.Fatal(err)
	}
}

func TestSecureEraseNormal(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 1000, Security: true, Enhanced: true, EraseMinutes: 60})
	plant(d, dev, t)
	var st steps
	after, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Password: "shunya-test", Record: st.record})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{ata.StepSetPassword, ata.StepErasePrepare, ata.StepEraseUnit, ata.StepEraseDone, ata.StepChecked}
	if !slices.Equal(st.names(), want) {
		t.Fatalf("steps %v", st.names())
	}
	if st.got[0].Password != "shunya-test" || st.got[2].Mode != "normal" || st.got[2].Timeout != (150*60) {
		t.Errorf("steps %+v", st.got)
	}
	if after.Enabled || after.Locked {
		t.Errorf("after %+v", after)
	}
	for _, lba := range []uint64{0, 7, 999} {
		if !bytes.Equal(d.Sector(lba), make([]byte, 512)) {
			t.Errorf("sector %d not zero after a normal erase", lba)
		}
	}
	// SECURITY ERASE PREPARE immediately precedes ERASE UNIT.
	i := slices.Index(d.Log, "SECURITY ERASE UNIT")
	if i < 1 || d.Log[i-1] != "SECURITY ERASE PREPARE" {
		t.Errorf("log %v", d.Log)
	}
}

func TestSecureEraseEnhancedAndHPA(t *testing.T) {
	// The simulator erases only up to the current max, as some real drives do: an
	// HPA left in place survives the erase. Removing it first gets everything.
	d, dev := drive(t, atafake.Options{Sectors: 1000, NativeSectors: 1100, Security: true, Enhanced: true, EnhancedFill: 0x6b})
	var st steps
	if _, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Enhanced: true, Password: "pw", Record: st.record}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.Sector(5), bytes.Repeat([]byte{0x6b}, 512)) || !bytes.Equal(d.Sector(1050), atafake.OldSector(1050)) {
		t.Fatal("expected: visible erased with the vendor pattern, hidden range untouched")
	}
	if err := ata.SetMaxVolatile(ctx, dev, 1100); err != nil {
		t.Fatal(err)
	}
	if _, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Enhanced: true, Password: "pw", Record: st.record}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.Sector(1050), bytes.Repeat([]byte{0x6b}, 512)) {
		t.Fatal("hidden range not erased after HPA removal")
	}
}

func TestSecureEraseRefusals(t *testing.T) {
	tests := []struct {
		name  string
		o     atafake.Options
		setup func(*atafake.Drive)
		enh   bool
		want  string
	}{
		{"unsupported", atafake.Options{Sectors: 100}, nil, false, "does not support the ATA Security"},
		{"frozen", atafake.Options{Sectors: 100, Security: true, FreezeOnBoot: true}, nil, false, "suspend the machine to RAM"},
		{"enhanced unsupported", atafake.Options{Sectors: 100, Security: true}, nil, true, "enhanced erase requested"},
		{"foreign password", atafake.Options{Sectors: 100, Security: true}, func(d *atafake.Drive) { d.SetPassword("theirs") }, false, "already set"},
		{"foreign lock", atafake.Options{Sectors: 100, Security: true}, func(d *atafake.Drive) { d.SetPassword("theirs"); d.PowerCycle() }, false, "locked with an unknown password"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, dev := drive(t, tc.o)
			if tc.setup != nil {
				tc.setup(d)
			}
			var st steps
			_, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Enhanced: tc.enh, Password: "pw", Record: st.record})
			var ref *ata.EraseRefusal
			if !errors.As(err, &ref) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v", err)
			}
			if len(st.got) != 0 || slices.Contains(d.Log, "SECURITY SET PASSWORD") {
				t.Fatalf("refused erase still acted: %v %v", st.names(), d.Log)
			}
		})
	}
}

func TestSecureEraseExpiredCounter(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 100, Security: true})
	d.SetPassword("theirs")
	d.PowerCycle()
	for range 5 {
		ata.Unlock(ctx, dev, "wrong")
	}
	id := identify(t, dev)
	if !id.Security.CountExpired {
		t.Fatal("counter did not expire")
	}
	if err := ata.CheckErase(id, false, true); err == nil || !strings.Contains(err.Error(), "attempt counter") {
		t.Fatalf("%v", err)
	}
}

var errPower = errors.New("power lost")

// Crash before SET PASSWORD reached the drive: the resume sets it again.
func TestSecureEraseResumeBeforePassword(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 100, Security: true})
	d.Before = func(c uint8) error {
		if c == ata.CmdSecuritySetPassword {
			return errPower
		}
		return nil
	}
	var st steps
	if _, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Password: "pw", Record: st.record}); !errors.Is(err, errPower) {
		t.Fatal(err)
	}
	d.Before = nil
	d.PowerCycle()
	if _, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Password: "pw", Resume: ata.StepSetPassword, Record: st.record}); err != nil {
		t.Fatal(err)
	}
}

// Power lost after SET PASSWORD, before the erase ran: the drive comes back locked with
// the journaled password; the resume unlocks it and erases.
func TestSecureEraseResumeLocked(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 100, Security: true})
	plant(d, dev, t)
	d.Before = func(c uint8) error {
		if c == ata.CmdSecurityEraseUnit {
			return errPower
		}
		return nil
	}
	var st steps
	if _, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Password: "pw", Record: st.record}); !errors.Is(err, errPower) {
		t.Fatal(err)
	}
	d.Before = nil
	d.PowerCycle()
	if _, en, locked, _ := d.State(); !en || !locked {
		t.Fatal("expected a locked drive after the power cycle")
	}
	st = steps{}
	if _, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Password: "pw", Resume: ata.StepEraseUnit, Record: st.record}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(st.names(), []string{ata.StepUnlock, ata.StepErasePrepare, ata.StepEraseUnit, ata.StepEraseDone, ata.StepChecked}) {
		t.Fatalf("%v", st.names())
	}
	if !bytes.Equal(d.Sector(0), make([]byte, 512)) {
		t.Fatal("not erased")
	}
}

// The erase completed, but the journal write of erase-done failed (crash). A missing
// password is not proof of a completed erase (an operator may have disabled it on an
// interrupted drive), so the resume erases again from SET PASSWORD.
func TestSecureEraseResumeNeverInfers(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 100, Security: true})
	fail := func(s ata.Step) error {
		if s.Step == ata.StepEraseDone {
			return errPower
		}
		return nil
	}
	if _, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Password: "pw", Record: fail}); !errors.Is(err, errPower) {
		t.Fatal(err)
	}
	var st steps
	if _, err := ata.SecureErase(ctx, dev, ata.EraseOptions{Password: "pw", Resume: ata.StepEraseUnit, Record: st.record}); err != nil {
		t.Fatal(err)
	}
	if st.names()[0] != ata.StepSetPassword || st.names()[len(st.got)-1] != ata.StepChecked {
		t.Fatalf("%v", st.names())
	}
	if n := strings.Count(strings.Join(d.Log, ","), "SECURITY ERASE UNIT"); n != 2 {
		t.Fatalf("ERASE UNIT sent %d times, want 2", n)
	}
	// The same after an operator disabled the password of an interrupted erase.
	d2, dev2 := drive(t, atafake.Options{Sectors: 100, Security: true})
	plant(d2, dev2, t)
	d2.Before = func(c uint8) error {
		if c == ata.CmdSecurityEraseUnit {
			return errPower
		}
		return nil
	}
	ata.SecureErase(ctx, dev2, ata.EraseOptions{Password: "pw", Record: st.record})
	d2.Before = nil
	if _, err := ata.Unlock(ctx, dev2, "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := ata.SecureErase(ctx, dev2, ata.EraseOptions{Password: "pw", Resume: ata.StepEraseUnit, Record: st.record}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d2.Sector(0), make([]byte, 512)) {
		t.Fatal("drive certified without being erased")
	}
}

func TestUnlockRecovery(t *testing.T) {
	d, dev := drive(t, atafake.Options{Sectors: 100, Security: true})
	d.SetPassword("shunya-x")
	d.PowerCycle()
	s, err := ata.Unlock(ctx, dev, "shunya-x")
	if err != nil || s.Enabled || s.Locked {
		t.Fatalf("%+v %v", s, err)
	}
	if _, en, _, _ := d.State(); en {
		t.Fatal("still enabled")
	}
	d.SetPassword("other")
	if _, err := ata.Unlock(ctx, dev, "shunya-x"); !ata.Aborted(err) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestNewPasswordAndTimeout(t *testing.T) {
	p, err := ata.NewPassword(nil)
	if err != nil || len(p) != 27 || !strings.HasPrefix(p, "shunya-") || len(p) > ata.PasswordBytes {
		t.Fatalf("%q %v", p, err)
	}
	q, _ := ata.NewPassword(nil)
	if p == q {
		t.Fatal("same password twice")
	}
	id := &ata.Identify{Security: ata.Security{NormalEraseMinutes: 112, EnhancedEraseMinutes: -1}}
	if got := ata.EraseTimeout(id, false).Minutes(); got != 254 {
		t.Errorf("normal timeout %v min", got)
	}
	if got := ata.EraseTimeout(id, true).Hours(); got != 24 {
		t.Errorf("unknown-length timeout %v h", got)
	}
}
