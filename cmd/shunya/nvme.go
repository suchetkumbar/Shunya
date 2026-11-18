package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/engine"
	"shunya/internal/nvme"
)

// nvmeDevice returns the NVMe admin interface of an opened target, if it has one.
func nvmeDevice(tg backend.Target) (nvme.Device, bool) {
	tr, ok := tg.(nvme.Transport)
	return nvme.Device{T: tr}, ok
}

var nsName = regexp.MustCompile(`^nvme\d+n(\d+)$`)

// nsidOf derives the namespace ID from the block device name (nvmeXnY → Y). The
// identity cross-check below confirms it: the namespace's size and EUI-64/NGUID must
// match what sysfs reports for the device.
func nsidOf(path string) (uint32, error) {
	m := nsName.FindStringSubmatch(filepath.Base(path))
	if m == nil {
		return 0, fmt.Errorf("%s: not an NVMe namespace block device name", path)
	}
	n, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%s: bad namespace number", path)
	}
	return uint32(n), nil
}

// probeNVMe reads Identify Controller, Identify Namespace and the active namespace
// list of an NVMe target (read-only commands only). It returns nil for other targets.
func probeNVMe(spec *targetSpec, f wipeFlags, stderr io.Writer) (*engine.NVMePlan, string, int) {
	if spec.isImage || spec.transport != device.TransportNVMe {
		return nil, "", 0
	}
	if backend.RequiresConfirmation() && f.confirm == "" && !f.yesReally {
		return nil, "not probed: a release build opens a drive (even read-only) only after confirmation; add --confirm", 0
	}
	nsid, err := nsidOf(spec.path)
	if err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		return nil, "", 1
	}
	tg, code := spec.open(f, false, stderr)
	if code != 0 {
		return nil, "", code
	}
	defer tg.Close()
	dev, ok := nvmeDevice(tg)
	if !ok {
		return nil, "this target has no NVMe admin pass-through", 0
	}
	ctx := context.Background()
	c, _, err := dev.Controller(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: NVMe Identify Controller:", err)
		return nil, "", 1
	}
	n, _, err := dev.Namespace(ctx, nsid)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: NVMe Identify Namespace:", err)
		return nil, "", 1
	}
	active, err := dev.ActiveNamespaces(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: NVMe active namespace list:", err)
		return nil, "", 1
	}
	if why := nvmeMismatch(spec, c, n); why != "" {
		fmt.Fprintf(stderr, "shunya: refusing %s: %s\n", spec.path, why)
		return nil, "", 1
	}
	return &engine.NVMePlan{Controller: *c, Namespace: *n, Active: active}, "", 0
}

// nvmeMismatch compares Identify with what sysfs reported at selection.
func nvmeMismatch(spec *targetSpec, c *nvme.Controller, n *nvme.Namespace) string {
	var why []string
	if s := strings.TrimSpace(spec.id.Serial); s != "" && s != c.Serial {
		why = append(why, fmt.Sprintf("controller serial %q, the system reports %q", c.Serial, s))
	}
	if m := strings.TrimSpace(spec.id.Model); m != "" && m != c.Model {
		why = append(why, fmt.Sprintf("controller model %q, the system reports %q", c.Model, m))
	}
	if got := int64(n.SizeBytes()); got != spec.size || n.BlockBytes() != spec.sector {
		why = append(why, fmt.Sprintf("namespace %d is %d bytes in %d-byte blocks, the kernel sees %d / %d", n.NSID, got, n.BlockBytes(), spec.size, spec.sector))
	}
	w := spec.id.WWID
	switch {
	case strings.HasPrefix(w, "eui.") && n.EUI64 != "" && strings.TrimPrefix(w, "eui.") != n.EUI64:
		why = append(why, fmt.Sprintf("EUI-64 %s, the system reports %s", n.EUI64, w))
	case strings.HasPrefix(w, "eui.") && n.NGUID != "" && strings.TrimPrefix(w, "eui.") != n.NGUID && n.EUI64 == "":
		why = append(why, fmt.Sprintf("NGUID %s, the system reports %s", n.NGUID, w))
	}
	return strings.Join(why, "; ")
}

// cmdNVMe: shunya nvme identify|sanitize-log.
func cmdNVMe(args []string, stdout, stderr io.Writer) int {
	const usage = "usage: shunya nvme identify [--json] [--save-dir DIR] DEVICE\n       shunya nvme identify --ctrl FILE [--ns FILE]   (parse saved Identify data)\n       shunya nvme sanitize-log [--json] DEVICE\n"
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "identify":
		return cmdNVMeIdentify(args[1:], stdout, stderr)
	case "sanitize-log":
		return cmdNVMeSanitizeLog(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

func openForNVMe(path, confirm string, stderr io.Writer) (*targetSpec, backend.Target, nvme.Device, int) {
	spec, code := inspect(path, false, 0, stderr)
	if code != 0 {
		return nil, nil, nvme.Device{}, code
	}
	if spec.transport != device.TransportNVMe {
		fmt.Fprintf(stderr, "shunya: %s is a %s device, not NVMe\n", spec.path, spec.transport)
		return nil, nil, nvme.Device{}, 1
	}
	tg, code := spec.open(wipeFlags{confirm: confirm}, false, stderr)
	if code != 0 {
		return nil, nil, nvme.Device{}, code
	}
	dev, ok := nvmeDevice(tg)
	if !ok {
		tg.Close()
		fmt.Fprintln(stderr, "shunya: no NVMe admin pass-through on this target")
		return nil, nil, nvme.Device{}, 1
	}
	return spec, tg, dev, 0
}

func cmdNVMeIdentify(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("nvme identify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "print JSON")
	saveDir := fl.String("save-dir", "", "also write the raw Identify data (id-ctrl.bin, id-ns.bin) to DIR")
	ctrlFile := fl.String("ctrl", "", "parse this saved Identify Controller file instead of asking a device")
	nsFile := fl.String("ns", "", "with --ctrl: a saved Identify Namespace file")
	confirm := fl.String("confirm", "", "release builds: last 4 characters of the serial")
	if err := fl.Parse(args); err != nil || (fl.NArg() == 1) == (*ctrlFile != "") {
		fmt.Fprint(stderr, "usage: shunya nvme identify [--json] [--save-dir DIR] DEVICE | --ctrl FILE [--ns FILE]\n")
		return 2
	}
	var cb, nb []byte
	nsid := uint32(1)
	if *ctrlFile != "" {
		var err error
		if cb, err = os.ReadFile(*ctrlFile); err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
		if *nsFile != "" {
			if nb, err = os.ReadFile(*nsFile); err != nil {
				fmt.Fprintln(stderr, "shunya:", err)
				return 1
			}
		}
	} else {
		spec, tg, dev, code := openForNVMe(fl.Arg(0), *confirm, stderr)
		if code != 0 {
			return code
		}
		defer tg.Close()
		var err error
		if nsid, err = nsidOf(spec.path); err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
		ctx := context.Background()
		if _, cb, err = dev.Controller(ctx); err != nil && cb == nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
		if _, nb, err = dev.Namespace(ctx, nsid); err != nil && nb == nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
	}
	c, err := nvme.ParseController(cb)
	if err != nil {
		fmt.Fprintln(stderr, "shunya:", err)
		return 1
	}
	var n *nvme.Namespace
	if nb != nil {
		if n, err = nvme.ParseNamespace(nsid, nb); err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
	}
	if *saveDir != "" {
		os.MkdirAll(*saveDir, 0o755)
		if err := os.WriteFile(filepath.Join(*saveDir, "id-ctrl.bin"), cb, 0o644); err != nil {
			fmt.Fprintln(stderr, "shunya:", err)
			return 1
		}
		if nb != nil {
			os.WriteFile(filepath.Join(*saveDir, "id-ns.bin"), nb, 0o644)
		}
	}
	if *asJSON {
		return writeJSON(stdout, stderr, map[string]any{"controller": c, "namespace": n})
	}
	printNVMe(stdout, c, n)
	return 0
}

func printNVMe(w io.Writer, c *nvme.Controller, n *nvme.Namespace) {
	fmt.Fprintf(w, "model:     %s\nserial:    %s\nfirmware:  %s\nversion:   NVMe %s, vid %#04x, OUI %s\n", c.Model, c.Serial, c.Firmware, c.Version, c.VID, c.IEEE)
	s := c.Sanicap
	fmt.Fprintf(w, "sanitize:  crypto erase %v, block erase %v, overwrite %v (SANICAP %#x)\n", s.Crypto, s.Block, s.Overwrite, s.Raw)
	fmt.Fprintf(w, "format:    supported %v; crypto erase %v; applies to all namespaces: format %v, secure erase %v (FNA %#x)\n",
		c.FormatSupported, c.FNA.CryptoErase, c.FNA.FormatAllNamespaces, c.FNA.SecureEraseAllNamespaces, c.FNA.Raw)
	fmt.Fprintf(w, "subsystem: %s; max NSID %d; multiple controllers %v\n", c.SubNQN, c.NN, c.CMIC&2 != 0)
	if n == nil {
		return
	}
	f := n.Formats[n.LBAF]
	fmt.Fprintf(w, "namespace: %d, %d blocks of %d bytes (%s), metadata %d, PI type %d; shared %v\n",
		n.NSID, n.Size, f.DataBytes, human(n.SizeBytes()), f.MetadataBytes, n.PIType, n.Shared)
	dealloc := map[int]string{0: "not reported", 1: "zeros", 2: "ones"}[n.DeallocRead]
	fmt.Fprintf(w, "           deallocated blocks read as: %s; EUI-64 %s; NGUID %s\n", dealloc, orDash(n.EUI64), orDash(n.NGUID))
}

func cmdNVMeSanitizeLog(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("nvme sanitize-log", flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "print JSON")
	confirm := fl.String("confirm", "", "release builds: last 4 characters of the serial")
	if err := fl.Parse(args); err != nil || fl.NArg() != 1 {
		fmt.Fprint(stderr, "usage: shunya nvme sanitize-log [--json] DEVICE\n")
		return 2
	}
	_, tg, dev, code := openForNVMe(fl.Arg(0), *confirm, stderr)
	if code != 0 {
		return code
	}
	defer tg.Close()
	l, err := dev.SanitizeStatus(context.Background())
	if err != nil {
		fmt.Fprintln(stdout, "sanitize status log not available:", err)
		return 1
	}
	if *asJSON {
		return writeJSON(stdout, stderr, l)
	}
	st := map[int]string{0: "never sanitized", 1: "completed", 2: "IN PROGRESS", 3: "FAILED (failure mode)", 4: "completed (no-deallocate)"}[l.Status]
	fmt.Fprintf(stdout, "status: %s; progress %.1f%%; global data erased %v; last action %s\n", st, 100*l.Progress, l.GlobalDataErased, orDash(nvme.ActionName(l.Action())))
	return 0
}
