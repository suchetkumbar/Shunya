package engine

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"shunya/internal/journal"
)

func TestJournalPlacement(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "disk.img")
	if err := CheckJournalPlacement(img, img, nil); !errors.Is(err, ErrJournalOnTarget) {
		t.Fatalf("journal = image: %v", err)
	}
	if err := CheckJournalPlacement(filepath.Join(dir, "sub", "..", "disk.img"), img, nil); !errors.Is(err, ErrJournalOnTarget) {
		t.Fatalf("journal = image via ..: %v", err)
	}
	if err := CheckJournalPlacement(filepath.Join(dir, "wipe.journal"), img, nil); err != nil {
		t.Fatalf("separate journal refused: %v", err)
	}
	if err := CheckJournalPlacement(filepath.Join(dir, "missing", "j"), img, nil); err == nil {
		t.Fatal("missing directory accepted")
	}
	if runtime.GOOS != "linux" {
		t.Skip("SKIPPED: device-number placement check is Linux-only")
	}
	dev, _, err := fsDevice(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckJournalPlacement(filepath.Join(dir, "j"), "", TargetDevs{"8:0", dev}); !errors.Is(err, ErrJournalOnTarget) {
		t.Fatalf("journal on target device (%s): %v", dev, err)
	}
	if err := CheckJournalPlacement(filepath.Join(dir, "j"), "", TargetDevs{"259:99"}); err != nil {
		t.Fatalf("journal elsewhere refused: %v", err)
	}
}

func TestJournalPlacementRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{dir, os.DevNull} {
		if err := CheckJournalPlacement(p, "", nil); !errors.Is(err, journal.ErrNotRegular) {
			t.Errorf("%s: %v", p, err)
		}
	}
}
