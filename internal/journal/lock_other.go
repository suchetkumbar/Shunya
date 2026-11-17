//go:build !linux

package journal

import "os"

// lock is a no-op off Linux; wiping block devices is Linux-only until Milestone 10.
func lock(*os.File) error { return nil }

// syncDirErr ignores directory fsync errors: Windows can't fsync a directory handle.
func syncDirErr(error) error { return nil }

const noFollow = 0
