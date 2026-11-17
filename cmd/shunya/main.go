// Command shunya is the Shunya CLI.
//
//	shunya list [--json] [--all]     read-only device discovery (Milestone 1)
//	shunya guard [--json] /dev/X     would the safety guards allow opening X? (Milestone 2)
//	shunya wipe ...                  overwrite wipe, dry run unless --execute (Milestone 3)
//	shunya journal show ...          verify and print a progress journal
//	shunya keys gen-dev FILE         temporary station signing key
//
// list and guard never open a device node or write anything; wipe writes only with
// --execute, after every guard in internal/backend.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"

	"shunya/internal/backend"
	"shunya/internal/device"
)

const usage = `usage: shunya <command> [flags]

commands:
  list [--json] [--all]   list block devices, their media type and protection status
  guard [--json] DEVICE   show whether the safety guards would allow DEVICE as a wipe
                          target, and why (never opens the device)
  wipe [flags] DEVICE     overwrite DEVICE (NIST SP 800-88 Clear). Without --execute it
  wipe [flags] --image F  prints the plan and writes nothing. See shunya wipe -h.
  wipe --resume ...       continue an interrupted wipe from its journal
  verify --journal J ...  re-verify a finished wipe (full, or --sample N --seed HEX)
  journal show JOURNAL    verify a progress journal and show its history
  keys gen-dev FILE       create a temporary station signing key (until Milestone 7)
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
	case "guard":
		return cmdGuard(args[1:], stdout, stderr)
	case "wipe":
		return cmdWipe(args[1:], stdout, stderr)
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	case "journal":
		return cmdJournal(args[1:], stdout, stderr)
	case "keys":
		return cmdKeys(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "shunya: unknown command %q\n\n%s", args[0], usage)
	return 2
}

// liveEnv returns the running system's environment, or an exit code.
func liveEnv(stderr io.Writer) (backend.Env, int) {
	env, err := backend.LiveEnv()
	if err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		if runtime.GOOS != "linux" {
			return env, 3
		}
		return env, 1
	}
	return env, 0
}

func writeJSON(w, stderr io.Writer, v any) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		return 1
	}
	return 0
}

func cmdList(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("list", flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "print JSON")
	all := fl.Bool("all", false, "include logical devices (loop, dm, md, ram)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	env, code := liveEnv(stderr)
	if code != 0 {
		return code
	}
	rep, err := device.EnumerateWith(env.FS, device.Options{Protect: env.Protect})
	if err != nil {
		fmt.Fprintln(stderr, "shunya: list:", err)
		return 1
	}
	if *asJSON {
		return writeJSON(stdout, stderr, rep)
	}
	printTable(stdout, rep, *all)
	return 0
}

func cmdGuard(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("guard", flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "print JSON")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fmt.Fprint(stderr, "usage: shunya guard [--json] /dev/NAME\n")
		return 2
	}
	env, code := liveEnv(stderr)
	if code != 0 {
		return code
	}
	v, err := backend.Check(env, fl.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "shunya: guard:", err)
		return 1
	}
	if *asJSON {
		if c := writeJSON(stdout, stderr, v); c != 0 {
			return c
		}
	} else {
		printVerdict(stdout, v)
	}
	if !v.Allowed {
		return 1
	}
	return 0
}

func printVerdict(w io.Writer, v *backend.Verdict) {
	token := "no lab token"
	if backend.HasLabToken() {
		token = "lab token compiled in"
	}
	fmt.Fprintf(w, "build: %s (%s)\n", v.Build, token)
	if v.Allowed {
		d := v.Device
		fmt.Fprintf(w, "ALLOWED  %s  %s %s  serial %s  %s\n", v.Path, d.Transport, d.Media.Type, orDash(d.Serial), d.Fingerprint.Value)
		if backend.RequiresConfirmation() {
			fmt.Fprintln(w, "         opening it will still require typed confirmation (last 4 characters of the serial)")
		}
	} else {
		fmt.Fprintf(w, "REFUSED  %s\n", v.Path)
		for _, r := range v.Reasons {
			fmt.Fprintf(w, "  - %s\n", r)
		}
	}
	fmt.Fprintln(w, "(checked from sysfs/procfs only; the device was not opened)")
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
