// Command shunya is the Shunya CLI. Milestone 1 provides read-only device discovery:
//
//	shunya list [--json] [--all]
//
// Nothing in this milestone opens a device node or writes anything.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"shunya/internal/device"
)

const usage = `usage: shunya <command> [flags]

commands:
  list [--json] [--all]   list block devices, their media type and protection status
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "list":
		return cmdList(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "shunya: unknown command %q\n\n%s", args[0], usage)
	return 2
}

func cmdList(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("list", flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "print JSON")
	all := fl.Bool("all", false, "include logical devices (loop, dm, md, ram)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	rep, err := enumerate()
	if errors.Is(err, errUnsupported) {
		fmt.Fprintln(stderr, "shunya:", err)
		return 3
	}
	if err != nil {
		fmt.Fprintln(stderr, "shunya: list:", err)
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
		return 0
	}
	printTable(stdout, rep, *all)
	return 0
}

func printTable(w io.Writer, rep *device.Report, all bool) {
	fmt.Fprintf(w, "system: %s / %s   lab marker: %v   mount namespaces: %d\n\n",
		orDash(rep.System.DMIVendor), orDash(rep.System.DMIProduct), rep.System.LabMarker, rep.System.MountNamespaces)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE\tSTATUS\tBUS\tMEDIA\tSIZE\tMODEL\tSERIAL\tFINGERPRINT\tWHY")
	hidden := 0
	for _, d := range rep.Devices {
		if !all && d.Media.Type == device.MediaLogical {
			hidden++
			continue
		}
		media := string(d.Media.Type) + " (" + string(d.Media.Confidence) + ")"
		if d.Media.Virtual && d.Media.Type != device.MediaVirtual {
			media += " virt"
		}
		fp := d.Fingerprint.Value
		if len(fp) > 16 {
			fp = fp[:16]
		}
		if d.Fingerprint.Weak {
			fp += " weak"
		}
		why := ""
		if len(d.Reasons) > 0 {
			why = d.Reasons[0]
			if len(d.Reasons) > 1 {
				why += fmt.Sprintf(" (+%d)", len(d.Reasons)-1)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.Path, d.Status, d.Transport, media,
			human(d.SizeBytes), orDash(d.Model), orDash(d.Serial), fp, why)
	}
	_ = tw.Flush()
	if hidden > 0 {
		fmt.Fprintf(w, "\n%d logical device(s) hidden (loop, dm, md, ram); use --all to show them.\n", hidden)
	}
	for _, warn := range rep.Warnings {
		fmt.Fprintln(w, "\nnote:", warn)
	}
	fmt.Fprintln(w, "\nRead-only listing: no device was opened. Use --json for full details (partitions, holders, mounts).")
}

func human(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
