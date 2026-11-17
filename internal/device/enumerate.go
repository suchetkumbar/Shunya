package device

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strconv"
	"strings"

	"shunya/internal/sysfs"
)

// Enumerate discovers block devices from a file system rooted at "/" (os.DirFS("/") on
// a live system). It fails closed: if mounts cannot be read it returns an error rather
// than reporting disks as available.
func Enumerate(fsys fs.FS) (*Report, error) {
	r := sysfs.New(fsys)
	rep := &Report{System: System{
		DMIVendor:  r.String("sys/class/dmi/id/sys_vendor"),
		DMIProduct: r.String("sys/class/dmi/id/product_name"),
		LabMarker:  r.Exists("etc/shunya-lab"),
	}}
	g, err := buildGraph(r)
	if err != nil {
		return nil, err
	}
	mounts, err := readMounts(r, rep)
	if err != nil {
		return nil, err
	}
	swaps := readSwaps(r, rep)

	byName := map[string]*Device{}
	for _, name := range r.Names("sys/block") {
		n := g.nodes[name]
		if n == nil {
			return nil, fmt.Errorf("block device %s: in sys/block but not in sys/class/block", name)
		}
		d, err := newDevice(r, g, n)
		if err != nil {
			return nil, err
		}
		if d == nil {
			continue // no medium (empty loop, card reader without card)
		}
		byName[name] = d
	}

	// Trace every use of every device down to the disks underneath it.
	use := func(from string, reason func(chain []string) string, protect bool, add func(*Device, []string)) {
		g.descend(from, nil, func(disk string, chain []string) {
			d := byName[disk]
			if d == nil {
				return
			}
			d.Reasons = appendUnique(d.Reasons, reason(chain))
			if protect {
				d.Status = StatusProtected
			} else if d.Status != StatusProtected {
				d.Status = StatusInUse
			}
			if add != nil {
				add(d, chain)
			}
		})
	}
	for _, m := range mounts {
		name, ok := g.byDev[m.Dev]
		if !ok || m.Dev.Major == 0 {
			// Anonymous device (btrfs, overlay, tmpfs …): fall back to the source path.
			if name, ok = g.lookupDevPath(m.Source); !ok {
				continue
			}
		}
		role, protect := mountRole(m)
		use(name, func(chain []string) string { return role + via(chain) }, protect, func(d *Device, chain []string) {
			d.Mounts = append(d.Mounts, MountRef{MountPoint: m.MountPoint, FSType: m.FSType, Source: m.Source, Via: chain, Namespace: m.ns})
		})
	}
	for _, s := range swaps {
		name, ok := g.lookupDevPath(s.Path)
		if !ok {
			continue
		}
		use(name, func(chain []string) string { return "active swap " + s.Path + via(chain) }, false, func(d *Device, _ []string) {
			d.Swaps = appendUnique(d.Swaps, s.Path)
		})
	}
	// btrfs can span several devices but mountinfo names only one of them.
	for _, uuid := range r.Names("sys/fs/btrfs") {
		for _, member := range r.Names("sys/fs/btrfs/" + uuid + "/devices") {
			use(member, func([]string) string { return "member of btrfs filesystem " + uuid }, false, nil)
		}
	}
	// Any device stacked on a disk or its partitions keeps it busy.
	for _, d := range byName {
		var hs []string
		for _, h := range d.Holders {
			hs = append(hs, describeHolder(h))
		}
		for _, p := range d.Partitions {
			for _, h := range p.Holders {
				hs = append(hs, describeHolder(h)+" on "+p.Name)
			}
		}
		for _, h := range hs {
			d.Reasons = appendUnique(d.Reasons, "held by "+h)
			if d.Status != StatusProtected {
				d.Status = StatusInUse
			}
		}
	}

	for _, name := range slices.Sorted(maps.Keys(byName)) {
		d := byName[name]
		if d.Status == "" {
			d.Status = StatusAvailable
		}
		rep.Devices = append(rep.Devices, *d)
	}
	rep.Warnings = append(rep.Warnings, fmt.Sprintf(
		"mount checks covered %d mount namespace(s) visible to this process; mounts made in "+
			"other namespaces or by a hypervisor (other containers, other WSL distros) can be "+
			"missed. Milestone 2 also opens targets exclusively (O_EXCL), which the kernel "+
			"refuses for any device that is mounted or claimed anywhere.", rep.System.MountNamespaces))
	return rep, nil
}

// newDevice reads one whole device. It returns nil for a device with no medium.
func newDevice(r *sysfs.Reader, g *graph, n *node) (*Device, error) {
	sectors, err := r.Uint(n.devPath + "/size")
	if err != nil {
		return nil, fmt.Errorf("block device %s: size: %w", n.name, err)
	}
	if sectors == 0 {
		return nil, nil
	}
	d := &Device{
		Name:      n.name,
		Path:      "/dev/" + n.name,
		SysPath:   "/" + n.devPath,
		DevNum:    n.dev.String(),
		SizeBytes: sectors * 512, // sysfs "size" is always in 512-byte units
	}
	d.LogicalSectorSize = uint32(optUint(r, n.devPath+"/queue/logical_block_size"))
	d.PhysicalSectorSize = uint32(optUint(r, n.devPath+"/queue/physical_block_size"))
	d.Rotational = optUint(r, n.devPath+"/queue/rotational") == 1
	d.Removable = optUint(r, n.devPath+"/removable") == 1
	d.ReadOnly = optUint(r, n.devPath+"/ro") == 1
	d.Transport = detectTransport(n.name, n.devPath, r)
	readIdentity(d, r, n.devPath)
	d.typeHint = r.String(n.devPath + "/device/type")
	if strings.HasPrefix(n.name, "sr") {
		d.typeHint = "5"
	}

	for _, pn := range g.nodes {
		if pn.partOf != n.name {
			continue
		}
		num, _ := r.Uint(pn.devPath + "/partition")
		start, _ := r.Uint(pn.devPath + "/start")
		size, _ := r.Uint(pn.devPath + "/size")
		d.Partitions = append(d.Partitions, Partition{
			Name: pn.name, Path: "/dev/" + pn.name, Number: num,
			StartSector: start, SizeBytes: size * 512,
			Holders: g.holderTree(pn.name, 0),
		})
	}
	slices.SortFunc(d.Partitions, func(a, b Partition) int { return int(a.Number) - int(b.Number) })
	d.Holders = g.holderTree(n.name, 0)

	d.Media = classify(d)
	switch d.Transport {
	case TransportRAM:
		d.Status, d.Reasons = StatusIgnored, []string{"not a storage device (ram disk)"}
	case TransportLoop:
		d.Status = StatusIgnored
		if f := r.String(n.devPath + "/loop/backing_file"); f != "" {
			d.LoopBackingFile = f
			d.Reasons = append(d.Reasons, "backed by file "+f)
		}
		d.Reasons = append(d.Reasons, "logical device: wipe the backing file or disk instead")
	case TransportDM, TransportMD:
		d.Status, d.Reasons = StatusIgnored, []string{"logical device: wipe the underlying disks instead"}
	}
	if d.Media.Type == MediaOptical {
		d.Status, d.Reasons = StatusIgnored, []string{"optical drive"}
	}
	d.Fingerprint = ComputeFingerprint(FingerprintInput{
		Model: d.Model, Serial: d.Serial, WWID: d.WWID, Firmware: d.Firmware, CapacityBytes: d.SizeBytes,
	})
	return d, nil
}

// mountRole names a mount and says whether it makes the disk PROTECTED.
func mountRole(m nsMount) (string, bool) {
	if m.initial {
		switch m.MountPoint {
		case "/":
			return "root filesystem /", true
		case "/boot", "/boot/efi", "/efi":
			return "boot filesystem " + m.MountPoint, true
		}
	}
	s := "mounted at " + m.MountPoint
	if !m.initial {
		s += " (mount namespace " + m.ns + ")"
	}
	return s, false
}

type nsMount struct {
	sysfs.Mount
	ns string
	// initial: this process's or pid 1's namespace, the ones whose "/" is a running system.
	initial bool
}

// readMounts reads mountinfo of this process (required) and of every other mount
// namespace visible in /proc (best effort), deduplicated by namespace.
func readMounts(r *sysfs.Reader, rep *Report) ([]nsMount, error) {
	var out []nsMount
	seen := map[string]bool{}
	add := func(pid string, required, initial bool) error {
		ns, err := fs.ReadLink(r.FS(), "proc/"+pid+"/ns/mnt")
		b, rerr := r.Bytes("proc/" + pid + "/mountinfo")
		if rerr != nil {
			if required {
				return fmt.Errorf("read /proc/%s/mountinfo: %w", pid, rerr)
			}
			return nil
		}
		if err != nil {
			ns = fmt.Sprintf("unknown:%x", sha256.Sum256(b)) // dedupe by content
		}
		if seen[ns] {
			return nil
		}
		ms, err := sysfs.ParseMountInfo(b)
		if err != nil {
			if required {
				return fmt.Errorf("parse /proc/%s/mountinfo: %w", pid, err)
			}
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("skipped unparsable /proc/%s/mountinfo: %v", pid, err))
			return nil
		}
		seen[ns] = true
		for _, m := range ms {
			out = append(out, nsMount{Mount: m, ns: ns, initial: initial})
		}
		return nil
	}
	if err := add("self", true, true); err != nil {
		return nil, err
	}
	if err := add("1", false, true); err != nil {
		return nil, err
	}
	for _, e := range r.Names("proc") {
		if _, err := strconv.ParseUint(e, 10, 32); err != nil || e == "1" {
			continue
		}
		_ = add(e, false, false)
	}
	rep.System.MountNamespaces = len(seen)
	return out, nil
}

func readSwaps(r *sysfs.Reader, rep *Report) []sysfs.Swap {
	b, err := r.Bytes("proc/swaps")
	if err != nil {
		rep.Warnings = append(rep.Warnings, "cannot read /proc/swaps (kernel without swap support?): swap use not checked")
		return nil
	}
	s, err := sysfs.ParseSwaps(b)
	if err != nil {
		rep.Warnings = append(rep.Warnings, "cannot parse /proc/swaps: swap use not checked: "+err.Error())
		return nil
	}
	return s
}

func optUint(r *sysfs.Reader, p string) uint64 {
	v, _ := r.Uint(p)
	return v
}

func appendUnique(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}
