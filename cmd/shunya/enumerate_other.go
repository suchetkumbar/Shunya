//go:build !linux

package main

import (
	"errors"
	"runtime"

	"shunya/internal/device"
)

var errUnsupported = errors.New("device listing is not implemented on " + runtime.GOOS +
	" yet: reading drive properties there requires opening \\\\.\\PhysicalDriveN, which " +
	"Shunya's development builds do not do (Windows support is Milestone 10)")

func enumerate() (*device.Report, error) { return nil, errUnsupported }
