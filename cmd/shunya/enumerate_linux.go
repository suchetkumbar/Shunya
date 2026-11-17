//go:build linux

package main

import (
	"errors"
	"os"

	"shunya/internal/device"
)

var errUnsupported = errors.New("unsupported")

// enumerate reads the live system's sysfs/procfs (read-only).
func enumerate() (*device.Report, error) { return device.Enumerate(os.DirFS("/")) }
