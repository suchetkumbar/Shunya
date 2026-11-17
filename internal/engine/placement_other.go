//go:build !linux

package engine

import "errors"

func fsDevice(string) (string, string, error) { return "", "", errors.ErrUnsupported }
