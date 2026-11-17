//go:build release

package backend

import "shunya/internal/sysfs"

// BuildKind is "release" for builds with -tags release.
const BuildKind = "release"

// RequiresConfirmation: release builds have no lab lock, so the operator must confirm
// each device (brief §2.3.3).
func RequiresConfirmation() bool { return true }

// labLock: release builds drop the VM check; every other guard stays.
func labLock(*sysfs.Reader) []string { return nil }

var _ = devLabLock // compiled and tested in both builds
