package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/journal"
	"shunya/internal/testutil/leakcheck"
)

var jkey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))

func readLog(t *testing.T, path string) *journal.Log {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	log, err := journal.Read(f, jkey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return log
}

// The full crash-safe cycle with a real journal: start, interrupt, resume, crash
// (no stop record, torn line), resume, finish; the replayed history shows both stops.
func TestJournalInterruptResumeCrashResume(t *testing.T) {
	leakcheck.Check(t)
	const chunk = 64 * kib
	file := image(t, "", 30*chunk+512, 512)
	p := planFor(t, file, chunk, 2*chunk)
	jpath := filepath.Join(t.TempDir(), "wipe.journal")
	w, err := journal.Create(jpath, jkey)
	if err != nil {
		t.Fatal(err)
	}
	rec := JournalRecorder{w}
	if err := rec.Start(NewWipeID(), "shunya-test", p); err != nil {
		t.Fatal(err)
	}

	// Run 1: cancelled after 7 writes.
	ctx, cancel := context.WithCancelCause(context.Background())
	tg := &hookTarget{Target: file, onWrite: func(n int, _ int64) error {
		if n == 7 {
			cancel(errors.New("SIGINT"))
		}
		return nil
	}}
	if _, err := Run(ctx, tg, p, rec, RunOptions{}); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	w.Close()
	st, err := Replay(readLog(t, jpath))
	if err != nil {
		t.Fatal(err)
	}
	if st.Pending() != StopInterrupted || st.Offset != 7*chunk || st.StopReason != "SIGINT" {
		t.Fatalf("after run 1: %+v", st)
	}

	// Run 2: resumed, then "killed": the journal simply stops (a write error in the
	// target fakes the kill; we then drop its error record and add a torn line).
	w, log, err := journal.OpenAppend(jpath, jkey)
	if err != nil {
		t.Fatal(err)
	}
	rec = JournalRecorder{w}
	if err := rec.Resumed(st, log.TornBytes); err != nil {
		t.Fatal(err)
	}
	tg = &hookTarget{Target: file, onWrite: func(n int, _ int64) error {
		if n == 9 {
			return errors.New("killed")
		}
		return nil
	}}
	if _, err := Run(context.Background(), tg, p, rec, RunOptions{StartPass: st.Pass, StartOffset: st.Offset}); err == nil {
		t.Fatal("expected failure")
	}
	w.Close()
	b, _ := os.ReadFile(jpath)
	lines := bytes.SplitAfter(b, []byte("\n"))
	lines = lines[:len(lines)-2] // drop the error record and the empty tail
	b = append(bytes.Join(lines, nil), []byte(`{"seq":99,"time":"2026-`)...)
	os.WriteFile(jpath, b, 0o600)

	w, log, err = journal.OpenAppend(jpath, jkey)
	if err != nil {
		t.Fatal(err)
	}
	if log.TornBytes == 0 {
		t.Fatal("torn tail not reported")
	}
	st, err = Replay(log)
	if err != nil {
		t.Fatal(err)
	}
	if st.Pending() != StopUnclean {
		t.Fatalf("pending %q, want unclean stop", st.Pending())
	}
	rec = JournalRecorder{w}
	if err := rec.Resumed(st, log.TornBytes); err != nil {
		t.Fatal(err)
	}
	if res, err := Run(context.Background(), file, p, rec, RunOptions{StartPass: st.Pass, StartOffset: st.Offset}); err != nil || !res.Completed {
		t.Fatal(err)
	}
	w.Close()
	checkRange(t, file, mustPattern(t, p.Passes[0]), 0, file.Size())

	st, err = Replay(readLog(t, jpath))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Done || len(st.Interruptions) != 2 {
		t.Fatalf("final state %+v", st)
	}
	i1, i2 := st.Interruptions[0], st.Interruptions[1]
	if i1.Kind != StopInterrupted || i1.Reason != "SIGINT" || i1.Offset != 7*chunk {
		t.Fatalf("interruption 1 %+v", i1)
	}
	if i2.Kind != StopUnclean || i2.TornBytes == 0 || i2.Offset < i1.Offset {
		t.Fatalf("interruption 2 %+v", i2)
	}
	if st.Pending() != "" {
		t.Fatal("done journal still pending")
	}
}

// Replay rejects histories the engine could never have written, even if signed.
func TestReplayRejectsInconsistentHistory(t *testing.T) {
	tg := image(t, "", 4*64*kib, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	size := tg.Size()
	type rec struct {
		typ  string
		data any
	}
	start := rec{RecStart, StartData{WipeID: "x", Tool: "t", Plan: p}}
	cases := map[string][]rec{
		"no start":            {{RecCheckpoint, posData{0, 512}}},
		"backwards":           {start, {RecCheckpoint, posData{0, 2048}}, {RecCheckpoint, posData{0, 1024}}},
		"beyond size":         {start, {RecCheckpoint, posData{0, size + 512}}},
		"early pass-done":     {start, {RecCheckpoint, posData{0, 512}}, {RecPassDone, posData{Pass: 0}}},
		"wrong pass":          {start, {RecCheckpoint, posData{1, 512}}},
		"early done":          {start, {RecDone, doneData{}}},
		"after done":          {start, {RecCheckpoint, posData{0, size}}, {RecPassDone, posData{}}, {RecDone, doneData{}}, {RecCheckpoint, posData{0, size}}},
		"write after stop":    {start, {RecInterrupted, stopData{0, 0, "x"}}, {RecCheckpoint, posData{0, 512}}},
		"resume elsewhere":    {start, {RecInterrupted, stopData{0, 1024, "x"}}, {RecResumed, ResumeData{Pass: 0, Offset: 0, After: StopInterrupted}}},
		"resume mislabelled":  {start, {RecInterrupted, stopData{0, 0, "x"}}, {RecResumed, ResumeData{After: StopUnclean}}},
		"unknown type":        {start, {"teleport", posData{}}},
		"two starts":          {start, start},
		"verified early":      {start, {RecVerified, VerifiedData{Mode: "full", OK: true}}},
		"invalid plan (keys)": {{RecStart, StartData{Plan: func() Plan { q := p; q.Passes = []Pass{{Pattern: PatternRandom}}; return q }()}}},
	}
	for name, recs := range cases {
		jpath := filepath.Join(t.TempDir(), "j")
		w, err := journal.Create(jpath, jkey)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if _, err := w.Append(r.typ, r.data); err != nil {
				t.Fatal(err)
			}
		}
		w.Close()
		if _, err := Replay(readLog(t, jpath)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPlanDefaultsAndNotes(t *testing.T) {
	id := backend.Identity{Path: "/dev/sdb", Fingerprint: "fp1:ab"}
	p, err := NewPlan(PlanInput{Target: id, Media: device.MediaNVMeSSD, SizeBytes: 1 << 30, SectorSize: 512})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Passes) != 1 || p.Passes[0].Pattern != PatternRandom || p.Passes[0].Key != "" {
		t.Fatalf("default passes %+v", p.Passes)
	}
	if p.Level != LevelClear || p.Method != "overwrite" || p.ChunkBytes != DefaultChunk {
		t.Fatalf("plan %+v", p)
	}
	all := strings.Join(p.Notes, "\n")
	for _, want := range []string{"Clear", "never reported as Purge", "Flash media", "HPA/DCO"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q:\n%s", want, all)
		}
	}
	if p.Validate() == nil {
		t.Fatal("plan without keys validated")
	}
	if err := p.GenerateKeys(nil); err != nil || p.Validate() != nil || len(p.Passes[0].Key) != 64 {
		t.Fatalf("keys: %v %v", err, p.Validate())
	}

	hdd, _ := NewPlan(PlanInput{Target: id, Media: device.MediaHDD, SizeBytes: 1 << 30, SectorSize: 512,
		Patterns: []string{PatternZero, PatternOne, PatternRandom}})
	all = strings.Join(hdd.Notes, "\n")
	if !strings.Contains(all, "reallocated") || !strings.Contains(all, "3 passes requested") {
		t.Fatalf("hdd notes:\n%s", all)
	}
	if hdd.EstimateSeconds <= p.EstimateSeconds {
		t.Fatal("3 HDD passes estimated faster than 1 NVMe pass")
	}
}

func TestPlanRejects(t *testing.T) {
	id := backend.Identity{Fingerprint: "fp1:ab"}
	ok := PlanInput{Target: id, Media: device.MediaHDD, SizeBytes: 1 << 20, SectorSize: 512}
	for name, mod := range map[string]func(*PlanInput){
		"odd size":      func(in *PlanInput) { in.SizeBytes = 1<<20 + 1 },
		"zero size":     func(in *PlanInput) { in.SizeBytes = 0 },
		"bad sector":    func(in *PlanInput) { in.SectorSize = 520 },
		"chunk unalign": func(in *PlanInput) { in.ChunkBytes = 6000 },
		"chunk huge":    func(in *PlanInput) { in.ChunkBytes = 128 << 20 },
		"bad pattern":   func(in *PlanInput) { in.Patterns = []string{"dod-5220"} },
		"too many":      func(in *PlanInput) { in.Patterns = make([]string, MaxPasses+1) },
		"no identity":   func(in *PlanInput) { in.Target = backend.Identity{} },
		"sync":          func(in *PlanInput) { in.SyncEvery = -1 },
	} {
		in := ok
		mod(&in)
		if _, err := NewPlan(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewPlan(ok); err != nil {
		t.Fatal(err)
	}
}

func TestReplayVerifiedAfterDone(t *testing.T) {
	tg := image(t, "", 4*64*kib, 512)
	p := planFor(t, tg, 64*kib, 64*kib)
	jpath := filepath.Join(t.TempDir(), "j")
	w, _ := journal.Create(jpath, jkey)
	rec := JournalRecorder{w}
	rec.Start("id", "t", p)
	if _, err := Run(context.Background(), tg, p, rec, RunOptions{}); err != nil {
		t.Fatal(err)
	}
	rec.Verified(VerifiedData{Mode: "full", OK: true, BytesRead: tg.Size(), FirstBad: -1})
	rec.Verified(VerifiedData{Mode: "sampled", OK: false, Samples: 10, SeedSource: SeedOperator, BadSectors: 1})
	w.Close()
	st, err := Replay(readLog(t, jpath))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Done || len(st.Verifications) != 2 || !st.Verifications[0].OK || st.Verifications[1].OK {
		t.Fatalf("%+v", st.Verifications)
	}
}
