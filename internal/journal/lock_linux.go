package journal

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lock takes an exclusive advisory lock so two shunya processes can't append to (or
// resume) the same journal at once. The lock is released when the file is closed.
func lock(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return fmt.Errorf("journal: %s is in use by another shunya process", f.Name())
		}
		return fmt.Errorf("journal: lock %s: %w", f.Name(), err)
	}
	return nil
}

func syncDirErr(err error) error { return err }

const noFollow = unix.O_NOFOLLOW
