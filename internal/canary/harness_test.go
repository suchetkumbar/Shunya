package canary

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/backend"
	"shunya/internal/engine"
)

const testSize = 8 << 20

func openImage(t *testing.T) *backend.File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "disk.img")
	if err := os.WriteFile(p, make([]byte, testSize), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := backend.OpenFile(p, backend.FileOptions{Options: backend.Options{Execute: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// prepare plants canaries and "stores" the planted files at sector-aligned offsets,
// as a file system would.
func prepare(t *testing.T) (*backend.File, *Set, []Planted) {
	t.Helper()
	tg := openImage(t)
	set := testSet(t)
	if err := Plant(context.Background(), tg, set, 1<<20); err != nil {
		t.Fatal(err)
	}
	files, err := GenerateFiles([]byte("harness"), 1)
	if err != nil {
		t.Fatal(err)
	}
	off := int64(1 << 20)
	for _, f := range files {
		n := (len(f.Data) + 511) / 512 * 512
		buf := make([]byte, n)
		copy(buf, f.Data)
		if _, err := tg.WriteAt(buf, off); err != nil {
			t.Fatal(err)
		}
		off += int64(n) + 4096
	}
	return tg, set, files
}

func scanTarget(t *testing.T, tg backend.Target, set *Set, files []Planted) Residue {
	t.Helper()
	r, err := NewScanner(set, Markers(files), 512).Scan(context.Background(), tg, tg.Size(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func wipe(t *testing.T, tg backend.Target) engine.Plan {
	t.Helper()
	p, err := engine.NewPlan(engine.PlanInput{Target: tg.Identity(), Media: engine.MediaImage, SizeBytes: tg.Size(),
		SectorSize: tg.SectorSize(), ChunkBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	p.GenerateKeys(nil)
	if _, err := engine.Run(context.Background(), tg, p, nopRecorder{}, engine.RunOptions{}); err != nil {
		t.Fatal(err)
	}
	return p
}

type nopRecorder struct{}

func (nopRecorder) Checkpoint(int, int64) error          { return nil }
func (nopRecorder) PassDone(int) error                   { return nil }
func (nopRecorder) Interrupted(int, int64, string) error { return nil }
func (nopRecorder) Failed(int, int64, error) error       { return nil }
func (nopRecorder) Done(int64) error                     { return nil }

func TestPlantScanWipeScan(t *testing.T) {
	tg, set, files := prepare(t)
	before := scanTarget(t, tg, set, files)
	if before.Tokens < testSize/TokenSize*9/10 || before.Displaced != 0 {
		t.Fatalf("before: %+v", before)
	}
	for _, f := range files {
		if before.Markers[f.Marker] < 2 {
			t.Fatalf("before: marker of %s found %d times", f.Name, before.Markers[f.Marker])
		}
	}
	wipe(t, tg)
	after := scanTarget(t, tg, set, files)
	if !after.Clean() || after.BytesScanned != testSize {
		t.Fatalf("after: %+v", after)
	}
	c := Case{Name: "image", Before: Phase{Residue: before}, After: Phase{Residue: after}}
	c.Evaluate(files)
	if !c.Pass {
		t.Fatalf("case failed: %v", c.Why)
	}
}

// A wipe that leaves the last 1 % is caught, and the residue is located in the tail.
func TestSkippedTailCaught(t *testing.T) {
	tg, set, files := prepare(t)
	before := scanTarget(t, tg, set, files)
	wipe(t, tg)
	skipFrom := int64(testSize - testSize/100/512*512)
	buf := make([]byte, testSize-skipFrom)
	for s := 0; s < len(buf); s += 512 {
		set.FillSector(buf[s:s+512], uint64((skipFrom+int64(s))/512))
	}
	tg.WriteAt(buf, skipFrom) // what the old data looks like where the wipe didn't reach
	after := scanTarget(t, tg, set, files)
	if after.Tokens != int64(len(buf)/TokenSize) || after.FirstOffset != skipFrom {
		t.Fatalf("after: %+v", after)
	}
	broken := Case{Name: "broken", Broken: true, SkipFrom: skipFrom, VerifyExit: 4,
		Before: Phase{Residue: before}, After: Phase{Residue: after}}
	broken.Evaluate(files)
	if !broken.Pass {
		t.Fatalf("broken case should pass (caught): %v", broken.Why)
	}
	// The same residue in a normal case is a failure.
	normal := broken
	normal.Broken = false
	normal.VerifyExit = 0
	normal.Evaluate(files)
	if normal.Pass || !strings.Contains(strings.Join(normal.Why, ";"), "residue after the wipe") {
		t.Fatalf("normal case with residue: %v", normal.Why)
	}
}

func TestEvaluateRejectsVacuousTest(t *testing.T) {
	files, _ := GenerateFiles([]byte("v"), 1)
	clean := Residue{FirstOffset: -1, LastOffset: -1, Markers: map[string]int64{}}
	for _, f := range files {
		clean.Markers[f.Marker] = 0
	}
	c := Case{Before: Phase{Residue: clean, Carve: Carve{Ran: true}}, After: Phase{Residue: clean}}
	c.Evaluate(files)
	why := strings.Join(c.Why, "\n")
	for _, want := range []string{"no canaries found before the wipe", "carver recovered 0 of 3", "not on disk before the wipe"} {
		if c.Pass || !strings.Contains(why, want) {
			t.Fatalf("vacuous test: reasons lack %q:\n%s", want, why)
		}
	}
}

func TestInspectCarved(t *testing.T) {
	files, _ := GenerateFiles([]byte("carve"), 1)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "r.1"), 0o755)
	os.WriteFile(filepath.Join(dir, "r.1", "f1.jpg"), files[0].Data, 0o644)                     // intact
	os.WriteFile(filepath.Join(dir, "r.1", "f2.pdf"), files[1].Data[:5000], 0o644)              // truncated, marker inside
	os.WriteFile(filepath.Join(dir, "r.1", "f3.zip"), bytes.Repeat([]byte{1}, 900), 0o644)      // junk
	os.WriteFile(filepath.Join(dir, "r.1", "report.xml"), []byte("<x>"+files[2].Marker), 0o644) // ignored
	c, err := InspectCarved("photorec", dir, files)
	if err != nil {
		t.Fatal(err)
	}
	if c.Total != 3 || c.WithMarker != 2 || c.Identical != 1 || len(c.Recovered) != 1 || c.ByType["jpg"] != 1 {
		t.Fatalf("%+v", c)
	}
}

func TestReportSummary(t *testing.T) {
	r := Report{Version: 1, Build: "dev", Cases: []Case{{Name: "x", Skipped: "exfat not supported"}}}
	r.Finish()
	if r.Pass {
		t.Fatal("report with only skipped cases passed")
	}
	dir := t.TempDir()
	if err := r.WriteFiles(dir, "canary-report"); err != nil {
		t.Fatal(err)
	}
	txt, _ := os.ReadFile(filepath.Join(dir, "canary-report.txt"))
	if !strings.Contains(string(txt), "FAIL") || !strings.Contains(string(txt), "SKIPPED: exfat not supported") {
		t.Fatalf("%s", txt)
	}
}
