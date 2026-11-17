package backend

import (
	"os"

	"golang.org/x/sys/unix"
)

const (
	directFlag   = unix.O_DIRECT
	noFollowFlag = unix.O_NOFOLLOW // a symlink swapped in after Lstat fails to open
)

func punchHole(f *os.File, off, length int64) error {
	return unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, off, length)
}
