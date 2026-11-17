//go:build !linux

package backend

import (
	"errors"
	"runtime"
)

// Block is not implemented on this OS yet (Windows: Milestone 10).
type Block struct{ File }

// OpenBlock is unsupported off Linux.
func OpenBlock(Env, string, Options) (*Block, error) {
	return nil, errors.New("block devices are not supported on " + runtime.GOOS + " yet")
}

// LiveEnv is unsupported off Linux.
func LiveEnv() (Env, error) {
	return Env{}, errors.New("device discovery is not supported on " + runtime.GOOS + " yet")
}
