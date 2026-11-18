package nvme_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shunya/internal/backend"
	"shunya/internal/nvme"
	"shunya/internal/nvme/nvmefake"
	"shunya/internal/sanitize"
)

// Scenario tests against the simulated controller (pending-real-hardware for Sanitize:
// QEMU has none).

var ctx = context.Background()

func ctrl(t *testing.T, o nvmefake.Options) (*nvmefake.Controller, nvme.Device) {
	t.Helper()
	c, _ := os.ReadFile(filepath.Join("testdata", "qemu-id-ctrl.bin"))
	n, _ := os.ReadFile(filepath.Join("testdata", "qemu-id-ns.bin"))
	f, err := nvmefake.New(c, n, o)
	if err != nil {
		t.Fatal(err)
	}
	return f, nvme.Device{T: f}
}

func ident(t *testing.T, d nvme.Device) (*nvme.Controller, *nvme.Namespace, []uint32) {
	t.Helper()
	c, _, err := d.Controller(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n, _, err := d.Namespace(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	a, err := d.ActiveNamespaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return c, n, a
}

type checkFn func(*nvme.Controller, *nvme.Namespace, []uint32) error

func san(action int) checkFn {
	return func(c *nvme.Controller, _ *nvme.Namespace, a []uint32) error { return nvme.CheckSanitize(c, a, action) }
}

func format(ses int) checkFn {
	return func(c *nvme.Controller, n *nvme.Namespace, a []uint32) error { return nvme.CheckFormat(c, n, a, ses) }
}

func TestChecks(t *testing.T) {
	tests := []struct {
		name   string
		o      nvmefake.Options
		check  checkFn
		refuse string
	}{
		{"qemu: no sanitize", nvmefake.Options{Blocks: 64}, san(nvme.SanactBlockErase), "SANICAP = 0"},
		{"qemu: crypto format without FNA bit", nvmefake.Options{Blocks: 64, CryptoLies: true}, format(nvme.SESCryptoErs), "FNA bit 2"},
		{"qemu: user-data format ok (shared NMIC, one controller)", nvmefake.Options{Blocks: 64}, format(nvme.SESUserData), ""},
		{"no format", nvmefake.Options{Blocks: 64, NoFormat: true}, format(nvme.SESUserData), "OACS bit 1"},
		{"block only, crypto asked", nvmefake.Options{Blocks: 64, SanitizeBlock: true}, san(nvme.SanactCryptoErase), "SANICAP bit 0"},
		{"other namespaces", nvmefake.Options{Blocks: 64, SanitizeCrypto: true, ExtraNamespaces: 2}, san(nvme.SanactCryptoErase), "2 other namespace"},
		{"format all namespaces", nvmefake.Options{Blocks: 64, FNA: 1, ExtraNamespaces: 1}, format(nvme.SESUserData), "1 other namespace"},
		{"format one of several ok", nvmefake.Options{Blocks: 64, ExtraNamespaces: 1}, format(nvme.SESUserData), ""},
		{"multi-controller", nvmefake.Options{Blocks: 64, SanitizeBlock: true, MultiController: true}, san(nvme.SanactBlockErase), "more than one controller"},
		{"shared namespace, multi-controller", nvmefake.Options{Blocks: 64, MultiController: true}, format(nvme.SESUserData), "another controller"},
		{"crypto supported", nvmefake.Options{Blocks: 64, FNA: 4}, format(nvme.SESCryptoErs), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, d := ctrl(t, tc.o)
			err := tc.check(ident(t, d))
			var r *nvme.Refusal
			switch {
			case tc.refuse == "" && err != nil:
				t.Fatal(err)
			case tc.refuse != "" && (!errors.As(err, &r) || !strings.Contains(err.Error(), tc.refuse)):
				t.Fatalf("%v", err)
			}
		})
	}
}

func plant(t *testing.T, f *nvmefake.Controller) {
	t.Helper()
	if _, err := f.Visible(backend.Identity{}, true).WriteAt(bytes.Repeat([]byte("secret!!"), 512), 0); err != nil {
		t.Fatal(err)
	}
}

type evs []sanitize.Event

func (e *evs) rec(x sanitize.Event) error { *e = append(*e, x); return nil }

func quick(e *evs, resume bool) sanitize.Options {
	return sanitize.Options{Resume: resume, Record: e.rec, Sleep: func(context.Context, time.Duration) error { return nil }}
}

func TestSanitizeRun(t *testing.T) {
	f, d := ctrl(t, nvmefake.Options{Blocks: 64, SanitizeCrypto: true, SanitizeBlock: true, SanitizePolls: 4})
	plant(t, f)
	var e evs
	op := nvme.SanitizeOp{D: d, Action: nvme.SanactBlockErase}
	st, err := sanitize.Run(ctx, op, quick(&e, false))
	if err != nil || st.Phase != sanitize.Completed || !st.Attested {
		t.Fatalf("%v %+v", err, st)
	}
	if !bytes.Equal(f.Block(0), make([]byte, 512)) || f.Sanitizes != 1 {
		t.Fatal("not erased")
	}
	// Resume after the sanitize finished: the controller attests it (Global Data Erased,
	// same action), so it is not run again.
	e = nil
	if _, err := sanitize.Run(ctx, op, quick(&e, true)); err != nil || f.Sanitizes != 1 || e[0].Event != sanitize.EvAttested {
		t.Fatalf("%v %v", err, e)
	}
	// A write since the sanitize clears Global Data Erased: the resume sanitizes again.
	plant(t, f)
	if _, err := sanitize.Run(ctx, op, quick(&e, true)); err != nil || f.Sanitizes != 2 {
		t.Fatalf("%v sanitizes %d", err, f.Sanitizes)
	}
	// A different action than the last one is not attested.
	cop := nvme.SanitizeOp{D: d, Action: nvme.SanactCryptoErase}
	if st, _ := cop.Status(ctx); st.Attested {
		t.Fatal("block erase attested a crypto erase")
	}
}

func TestSanitizeOverwritePattern(t *testing.T) {
	f, d := ctrl(t, nvmefake.Options{Blocks: 64, SanitizeOverwrite: true})
	plant(t, f)
	var e evs
	if _, err := sanitize.Run(ctx, nvme.SanitizeOp{D: d, Action: nvme.SanactOverwrite, Passes: 1, Pattern: 0}, quick(&e, false)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Block(3), make([]byte, 512)) {
		t.Fatal("overwrite pattern not applied")
	}
}

func TestSanitizeFailedAndIOBlocked(t *testing.T) {
	f, d := ctrl(t, nvmefake.Options{Blocks: 64, SanitizeBlock: true, SanitizeFails: true, SanitizePolls: 3})
	op := nvme.SanitizeOp{D: d, Action: nvme.SanactBlockErase}
	if err := op.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Visible(backend.Identity{}, false).ReadAt(make([]byte, 512), 0); err == nil {
		t.Fatal("I/O during sanitize succeeded")
	}
	if err := op.Start(ctx); !nvme.HasStatus(err, nvme.StatusSanitizeInProgress) {
		t.Fatalf("second start: %v", err)
	}
	var e evs
	if _, err := sanitize.Run(ctx, op, quick(&e, true)); !errors.Is(err, sanitize.ErrFailed) {
		t.Fatalf("%v", err)
	}
}

func TestFormat(t *testing.T) {
	f, d := ctrl(t, nvmefake.Options{Blocks: 64, BlockBytes: 4096})
	plant(t, f)
	_, n, _ := ident(t, d)
	if n.BlockBytes() != 4096 || n.LBAF != 4 {
		t.Fatalf("%+v", n)
	}
	c, err := nvme.FormatCmd(n, nvme.SESUserData)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Block(0), make([]byte, 4096)) || f.Formats != 1 {
		t.Fatal("not formatted")
	}
	// QEMU-like: crypto erase "succeeds" without FNA bit 2. The status is not proof.
	f2, d2 := ctrl(t, nvmefake.Options{Blocks: 64, CryptoLies: true})
	cc, nn, aa := ident(t, d2)
	c, _ = nvme.FormatCmd(nn, nvme.SESCryptoErs)
	if _, err := d2.Exec(ctx, c, nil); err != nil || f2.Formats != 1 {
		t.Fatalf("the simulated QEMU accepts it: %v", err)
	}
	if err := nvme.CheckFormat(cc, nn, aa, nvme.SESCryptoErs); err == nil {
		t.Fatal("the check must still refuse")
	}
}

func TestSanitizeLogUnsupported(t *testing.T) {
	_, d := ctrl(t, nvmefake.Options{Blocks: 64, NoSanitizeLog: true})
	if _, err := d.SanitizeStatus(ctx); !nvme.HasStatus(err, nvme.StatusInvalidField) {
		t.Fatalf("%v", err)
	}
}
