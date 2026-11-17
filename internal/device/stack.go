package device

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"shunya/internal/sysfs"
)

// node is one entry of /sys/class/block: a whole device or a partition.
type node struct {
	name    string
	devPath string // resolved fs path under sys/devices
	dev     sysfs.DevNum
	partOf  string // parent disk if this is a partition
	holders []string
	slaves  []string
	dmName  string
	dmUUID  string
	mdLevel string
}

// graph indexes every block device so mounts, swaps and holders can be traced from the
// device a filesystem sits on down to the physical disks underneath it.
type graph struct {
	nodes    map[string]*node
	byDev    map[sysfs.DevNum]string
	byDMName map[string]string
}

const maxStackDepth = 32 // dm/md stacks deeper than this are treated as a loop

func buildGraph(r *sysfs.Reader) (*graph, error) {
	names := r.Names("sys/class/block")
	if len(names) == 0 {
		return nil, fmt.Errorf("sys/class/block is empty or unreadable")
	}
	g := &graph{nodes: map[string]*node{}, byDev: map[sysfs.DevNum]string{}, byDMName: map[string]string{}}
	for _, name := range names {
		p, err := r.Resolve("sys/class/block/" + name)
		if err != nil {
			return nil, fmt.Errorf("block device %s: %w", name, err)
		}
		dev, err := sysfs.ParseDevNum(r.String(p + "/dev"))
		if err != nil {
			return nil, fmt.Errorf("block device %s: %w", name, err)
		}
		n := &node{
			name:    name,
			devPath: p,
			dev:     dev,
			holders: r.Names(p + "/holders"),
			slaves:  r.Names(p + "/slaves"),
			dmName:  r.String(p + "/dm/name"),
			dmUUID:  r.String(p + "/dm/uuid"),
			mdLevel: r.String(p + "/md/level"),
		}
		if r.Exists(p + "/partition") {
			n.partOf = path.Base(path.Dir(p))
		}
		g.nodes[name] = n
		g.byDev[dev] = name
		if n.dmName != "" {
			g.byDMName[n.dmName] = name
		}
	}
	return g, nil
}

// lookupDevPath maps "/dev/sda1", "/dev/dm-2" or "/dev/mapper/vg0-swap" to a node name.
func (g *graph) lookupDevPath(p string) (string, bool) {
	rest, ok := strings.CutPrefix(p, "/dev/")
	if !ok {
		return "", false
	}
	if dm, ok := strings.CutPrefix(rest, "mapper/"); ok {
		n, found := g.byDMName[dm]
		return n, found
	}
	if _, found := g.nodes[rest]; found {
		return rest, true
	}
	return "", false
}

// descend walks from node name down to the physical disks, calling visit for every
// whole device on the way (dm-1, dm-0, sda …) with the chain of devices above it.
func (g *graph) descend(name string, chain []string, visit func(disk string, chain []string)) {
	if len(chain) > maxStackDepth {
		return
	}
	n, ok := g.nodes[name]
	if !ok {
		return
	}
	if n.partOf != "" {
		g.descend(n.partOf, append(slices.Clone(chain), g.label(name)), visit)
		return
	}
	visit(name, chain)
	for _, s := range n.slaves {
		g.descend(s, append(slices.Clone(chain), g.label(name)), visit)
	}
}

// label is how a device appears in a chain: "dm-1 (vg0-root)" or "sda2".
func (g *graph) label(name string) string {
	if n := g.nodes[name]; n != nil && n.dmName != "" {
		return name + " (" + n.dmName + ")"
	}
	return name
}

// holderTree builds the forest of devices stacked on name.
func (g *graph) holderTree(name string, depth int) []Holder {
	n := g.nodes[name]
	if n == nil || depth > maxStackDepth {
		return nil
	}
	var out []Holder
	for _, h := range n.holders {
		hn := g.nodes[h]
		hd := Holder{Name: h, Kind: HolderOther}
		if hn != nil {
			hd.Kind = holderKind(hn)
			hd.DMName = hn.dmName
			hd.Level = hn.mdLevel
		}
		hd.Holders = g.holderTree(h, depth+1)
		out = append(out, hd)
	}
	return out
}

func holderKind(n *node) HolderKind {
	switch {
	case strings.HasPrefix(n.dmUUID, "CRYPT-"):
		return HolderCrypt
	case strings.HasPrefix(n.dmUUID, "LVM-"):
		return HolderLVM
	case strings.HasPrefix(n.dmUUID, "mpath-"):
		return HolderMultipath
	case strings.HasPrefix(n.name, "dm-"):
		return HolderDM
	case strings.HasPrefix(n.name, "md"):
		return HolderMD
	}
	return HolderOther
}

func describeHolder(h Holder) string {
	switch {
	case h.Kind == HolderMD && h.Level != "":
		return fmt.Sprintf("%s (md-%s)", h.Name, h.Level)
	case h.DMName != "":
		return fmt.Sprintf("%s (%s %s)", h.Name, h.Kind, h.DMName)
	}
	return fmt.Sprintf("%s (%s)", h.Name, h.Kind)
}

func via(chain []string) string {
	if len(chain) == 0 {
		return ""
	}
	return " via " + strings.Join(chain, " → ")
}
