package backend

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"shunya/internal/device"
	"shunya/internal/sysfs"
)

// Env is the view of the system the guards use: a file system rooted at "/" (sysfs,
// procfs, /etc) and extra devices to protect that sysfs can't reveal. LiveEnv builds
// it for the running system; tests pass fake trees.
type Env struct {
	FS      fs.FS
	Protect []device.Protect
	// Enumerate, if set, replaces the sysfs enumeration of FS (Windows, which has no
	// sysfs; FS then holds only the DMI strings the lab lock reads).
	Enumerate func() (*device.Report, error)
}

// Report enumerates the devices of env.
func (env Env) Report() (*device.Report, error) {
	if env.Enumerate != nil {
		return env.Enumerate()
	}
	return device.EnumerateWith(env.FS, device.Options{Protect: env.Protect})
}

// Verdict is the outcome of Check. Allowed is true only when Reasons is empty.
type Verdict struct {
	Path    string         `json:"path"`
	Allowed bool           `json:"allowed"`
	Build   string         `json:"build"`
	Reasons []string       `json:"reasons,omitempty"`
	Device  *device.Device `json:"device,omitempty"`
}

var reDevName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_:.-]*$`)

// deviceName accepts "/dev/NAME" or "NAME" where NAME is one path element. /dev/mapper,
// /dev/disk/by-* and other aliases are rejected: the operator must name the kernel
// device so that what is shown, checked and opened is the same thing.
func deviceName(p string) (string, error) {
	name := strings.TrimPrefix(p, "/dev/")
	if n, ok := strings.CutPrefix(p, `\\.\`); ok { // Windows: \\.\PhysicalDriveN
		name = n
	}
	if !reDevName.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid device %q: give a kernel device name such as /dev/sdb", p)
	}
	return name, nil
}

// Check decides whether path may be opened as a wipe target, from a fresh enumeration.
// It never opens the device. An error means the decision couldn't be made (treat it
// as a refusal); a Verdict with Allowed=false lists every reason.
func Check(env Env, path string) (*Verdict, error) {
	name, err := deviceName(path)
	if err != nil {
		return nil, err
	}
	rep, err := env.Report()
	if err != nil {
		return nil, fmt.Errorf("guard: cannot enumerate devices: %w", err)
	}
	v := &Verdict{Path: "/dev/" + name, Build: BuildKind}
	if strings.HasPrefix(path, `\\.\`) {
		v.Path = path
	}
	refuse := func(format string, a ...any) { v.Reasons = append(v.Reasons, fmt.Sprintf(format, a...)) }

	var d *device.Device
	for i := range rep.Devices {
		if rep.Devices[i].Name == name {
			d = &rep.Devices[i]
		}
		for _, p := range rep.Devices[i].Partitions {
			if p.Name == name {
				refuse("%s is a partition of %s: select the whole disk", v.Path, rep.Devices[i].Name)
			}
		}
	}
	if d == nil && len(v.Reasons) == 0 {
		refuse("no such block device in /sys/block (or it has no medium)")
	}
	if d != nil {
		v.Device = d
		if d.Status != device.StatusAvailable {
			for _, r := range d.Reasons {
				refuse("%s: %s", d.Status, r)
			}
			if len(d.Reasons) == 0 {
				refuse("%s", d.Status)
			}
		}
		if d.Media.Type == device.MediaLogical && d.Status != device.StatusIgnored {
			refuse("logical %s device: wipe the underlying disks instead", d.Transport)
		}
		if d.ReadOnly {
			refuse("device is read-only")
		}
		if d.Fingerprint.Weak {
			refuse("no serial number or WWID: a drive swap could not be detected, so the device can't be bound to a certificate")
		}
	}
	v.Reasons = append(v.Reasons, labLock(sysfs.New(env.FS))...)
	v.Allowed = len(v.Reasons) == 0
	return v, nil
}
