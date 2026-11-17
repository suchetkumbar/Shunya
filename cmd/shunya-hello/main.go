// Command shunya-hello is the Milestone 0 smoke-test binary. It lists block
// devices by reading sysfs only — it never opens a device node — so it is safe
// to run on the host as well as inside the lab VM.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

type disk struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	Rotational bool   `json:"rotational"`
	Removable  bool   `json:"removable"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
}

type report struct {
	DMIVendor  string `json:"dmi_vendor"`
	DMIProduct string `json:"dmi_product"`
	LabMarker  bool   `json:"lab_marker"`
	Disks      []disk `json:"disks"`
}

func main() {
	asJSON := flag.Bool("json", false, "print JSON")
	flag.Parse()

	r, err := scan(os.DirFS("/"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "shunya-hello:", err)
		os.Exit(1)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return
	}
	fmt.Printf("system: %s / %s   lab marker: %v\n", r.DMIVendor, r.DMIProduct, r.LabMarker)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSIZE\tROTA\tRM\tMODEL\tSERIAL")
	for _, d := range r.Disks {
		fmt.Fprintf(tw, "%s\t%s\t%v\t%v\t%s\t%s\n", d.Name, human(d.SizeBytes), d.Rotational, d.Removable, d.Model, d.Serial)
	}
	_ = tw.Flush()
}

// scan reads everything through an fs.FS rooted at "/", so tests can pass a fake tree.
func scan(root fs.FS) (report, error) {
	r := report{
		DMIVendor:  readAttr(root, "sys/class/dmi/id/sys_vendor"),
		DMIProduct: readAttr(root, "sys/class/dmi/id/product_name"),
	}
	if _, err := fs.Stat(root, "etc/shunya-lab"); err == nil {
		r.LabMarker = true
	}
	entries, err := fs.ReadDir(root, "sys/block")
	if err != nil {
		return r, fmt.Errorf("read /sys/block: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") {
			continue
		}
		base := "sys/block/" + name
		sectors, _ := strconv.ParseInt(readAttr(root, base+"/size"), 10, 64)
		serial := readAttr(root, base+"/device/serial")
		if serial == "" {
			serial = readAttr(root, base+"/serial") // virtio-blk
		}
		if serial == "" {
			// SCSI/SAT: VPD page 0x80 (Unit Serial Number) — 4-byte header, then ASCII.
			if b, err := fs.ReadFile(root, base+"/device/vpd_pg80"); err == nil && len(b) > 4 {
				serial = strings.Trim(string(b[4:]), " \x00\n")
			}
		}
		r.Disks = append(r.Disks, disk{
			Name:       name,
			SizeBytes:  sectors * 512, // sysfs "size" is always in 512-byte units
			Rotational: readAttr(root, base+"/queue/rotational") == "1",
			Removable:  readAttr(root, base+"/removable") == "1",
			Model:      readAttr(root, base+"/device/model"),
			Serial:     serial,
		})
	}
	sort.Slice(r.Disks, func(i, j int) bool { return r.Disks[i].Name < r.Disks[j].Name })
	return r, nil
}

func readAttr(root fs.FS, p string) string {
	b, err := fs.ReadFile(root, p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
