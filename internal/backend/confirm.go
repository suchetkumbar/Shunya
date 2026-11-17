package backend

import (
	"bufio"
	"bytes"
	"fmt"
	"slices"
	"strings"

	"shunya/internal/device"
)

// Confirmation is the operator's explicit consent to wipe one device (release builds).
type Confirmation struct {
	// Typed is what the operator typed: the last 4 characters of the serial number
	// (the whole serial if it is shorter than 4).
	Typed string
	// YesReally (fleet mode) skips typing, but only for devices whose fingerprint is
	// in Approved, a list prepared in advance.
	YesReally bool
	Approved  []string
}

// Check returns nil if c confirms d.
func (c *Confirmation) Check(d *device.Device) error {
	refuse := func(why string) error { return &RefusalError{Path: d.Path, Reasons: []string{"confirmation: " + why}} }
	if c == nil {
		return refuse("required: type the last 4 characters of the serial number")
	}
	if c.YesReally {
		if !slices.Contains(c.Approved, d.Fingerprint.Value) {
			return refuse("--yes-really given but fingerprint " + d.Fingerprint.Value + " is not in the approved list")
		}
		return nil
	}
	serial := strings.TrimSpace(d.Serial)
	if serial == "" {
		return refuse("device has no serial number to confirm against")
	}
	want := serial
	if len(serial) > 4 {
		want = serial[len(serial)-4:]
	}
	if !strings.EqualFold(strings.TrimSpace(c.Typed), want) {
		return refuse(fmt.Sprintf("typed %q does not match the last %d characters of the serial", strings.TrimSpace(c.Typed), len(want)))
	}
	return nil
}

// ParseApprovedList parses a fleet approval file: one fp1 fingerprint per line, "#"
// starts a comment. Fingerprints are normalised to lowercase.
func ParseApprovedList(b []byte) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fp := strings.ToLower(line)
		hexPart, ok := strings.CutPrefix(fp, "fp1:")
		if !ok || len(hexPart) != 64 || strings.Trim(hexPart, "0123456789abcdef") != "" {
			return nil, fmt.Errorf("approved list line %d: %q is not an fp1 fingerprint", n, line)
		}
		out = append(out, fp)
	}
	return out, sc.Err()
}
