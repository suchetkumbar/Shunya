// Command check verifies `shunya list --json` output collected from the lab VM against
// the disks lab/lab.sh attaches. It runs on the host side of the lab, reads one JSON
// file and touches nothing else.
//
//	go run ./lab/check lab/results/latest/list.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"shunya/internal/device"
)

type expect struct {
	transport device.Transport
	media     device.MediaType
	status    device.Status
}

// Keep in sync with cmd_up in lab/lab.sh.
var lab = map[string]expect{
	"SHUNYA-BOOT-0":      {device.TransportVirtio, device.MediaVirtual, device.StatusProtected},
	"SHUNYA-VIRTIO-01":   {device.TransportVirtio, device.MediaVirtual, device.StatusAvailable},
	"SHUNYA-SATA-SSD-01": {device.TransportSATA, device.MediaSSD, device.StatusAvailable},
	"SHUNYA-SATA-HDD-01": {device.TransportSATA, device.MediaHDD, device.StatusAvailable},
	"SHUNYA-NVME-01":     {device.TransportNVMe, device.MediaNVMeSSD, device.StatusAvailable},
	"SHUNYA-USB-01":      {device.TransportUSB, device.MediaUSBFlash, device.StatusAvailable},
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: check LIST.json")
		os.Exit(2)
	}
	b, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var rep device.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}
	fails := check(&rep)
	for _, f := range fails {
		fmt.Println("FAIL", f)
	}
	if len(fails) > 0 {
		os.Exit(1)
	}
	fmt.Printf("PASS lab discovery: %d expected disks found with correct bus, media and status; boot disk PROTECTED\n", len(lab))
}

func check(rep *device.Report) []string {
	var fails []string
	if rep.System.DMIVendor != "QEMU" || !rep.System.LabMarker {
		fails = append(fails, fmt.Sprintf("system %+v: want QEMU with lab marker", rep.System))
	}
	seen := map[string]bool{}
	for _, d := range rep.Devices {
		e, ok := lab[d.Serial]
		if !ok {
			continue
		}
		seen[d.Serial] = true
		if d.Transport != e.transport || d.Media.Type != e.media || d.Status != e.status {
			fails = append(fails, fmt.Sprintf("%s (%s): got %s/%s/%s, want %s/%s/%s (reasons %q)",
				d.Path, d.Serial, d.Transport, d.Media.Type, d.Status, e.transport, e.media, e.status, d.Reasons))
		}
		if d.Fingerprint.Weak {
			fails = append(fails, d.Path+": fingerprint weak despite serial")
		}
	}
	for s := range lab {
		if !seen[s] {
			fails = append(fails, "no device with serial "+s)
		}
	}
	return fails
}
