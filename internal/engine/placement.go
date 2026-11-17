package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"shunya/internal/journal"
)

// ErrJournalOnTarget: the journal would be written to the device being wiped.
var ErrJournalOnTarget = errors.New("journal must not live on the wipe target")

// TargetDevs are the device numbers ("major:minor") of a block target and all of its
// partitions; a journal on any of them would be overwritten by the wipe.
type TargetDevs []string

// CheckJournalPlacement refuses a journal that would live on the target. For an image
// file target (imagePath != ""), the journal must not be the image itself nor live in
// a file system mounted from that image through a loop device. For a block target, the
// journal's file system must not be on the target disk or any of its partitions.
// journalPath's directory must exist.
func CheckJournalPlacement(journalPath, imagePath string, devs TargetDevs) error {
	abs, err := filepath.Abs(journalPath)
	if err != nil {
		return err
	}
	if st, err := os.Lstat(abs); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is %v", journal.ErrNotRegular, abs, st.Mode().Type())
	}
	dir := filepath.Dir(abs)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("journal directory %s: not an existing directory", dir)
	}
	dev, loopBacking, err := fsDevice(dir)
	if err != nil {
		if len(devs) == 0 && imagePath != "" && errors.Is(err, errors.ErrUnsupported) {
			dev = ""
		} else {
			return fmt.Errorf("journal placement: %w", err)
		}
	}
	if imagePath != "" {
		img, err := filepath.Abs(imagePath)
		if err != nil {
			return err
		}
		if abs == img {
			return fmt.Errorf("%w: %s is the image being wiped", ErrJournalOnTarget, abs)
		}
		if a, err1 := os.Stat(abs); err1 == nil {
			if b, err2 := os.Stat(img); err2 == nil && os.SameFile(a, b) {
				return fmt.Errorf("%w: %s is the image being wiped", ErrJournalOnTarget, abs)
			}
		}
		if loopBacking != "" && loopBacking == img {
			return fmt.Errorf("%w: %s is on a file system mounted from the image (%s)", ErrJournalOnTarget, dir, dev)
		}
	}
	if dev != "" && slices.Contains(devs, dev) {
		return fmt.Errorf("%w: %s is on device %s, which is being wiped", ErrJournalOnTarget, dir, dev)
	}
	return nil
}
