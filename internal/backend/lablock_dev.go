//go:build !release

package backend

import "shunya/internal/sysfs"

// BuildKind is "dev" for builds without -tags release.
const BuildKind = "dev"

// RequiresConfirmation: dev builds rely on the lab lock instead of typed confirmation.
func RequiresConfirmation() bool { return false }

func labLock(r *sysfs.Reader) []string { return devLabLock(r) }
