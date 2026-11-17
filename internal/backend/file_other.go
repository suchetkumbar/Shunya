//go:build !linux

package backend

import "os"

const (
	directFlag   = 0
	noFollowFlag = 0
)

func punchHole(*os.File, int64, int64) error { return ErrUnsupported }
