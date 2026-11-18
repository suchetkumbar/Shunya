//go:build !linux

package backend

import (
	"context"
	"errors"
	"runtime"
	"time"

	"shunya/internal/nvme"
)

// Block is not implemented on this OS yet (Windows: Milestone 10).
type Block struct{ File }

// OpenBlock is unsupported off Linux.
func OpenBlock(Env, string, Options) (*Block, error) {
	return nil, errors.New("block devices are not supported on " + runtime.GOOS + " yet")
}

// PassThrough is unsupported off Linux (Windows: Milestone 10).
func (b *Block) PassThrough(context.Context, [16]byte, []byte, time.Duration) ([]byte, error) {
	return nil, errors.New("ATA pass-through is not supported on " + runtime.GOOS + " yet")
}

// AdminCommand is unsupported off Linux.
func (b *Block) AdminCommand(context.Context, nvme.AdminCmd, []byte) (uint32, nvme.Status, error) {
	return 0, 0, errors.New("NVMe admin commands are not supported on " + runtime.GOOS + " yet")
}

// LiveEnv is unsupported off Linux.
func LiveEnv() (Env, error) {
	return Env{}, errors.New("device discovery is not supported on " + runtime.GOOS + " yet")
}
