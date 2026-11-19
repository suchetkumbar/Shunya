package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shunya/internal/backend"
	"shunya/internal/certcheck"
	"shunya/internal/engine"
	"shunya/internal/manifest"
	"shunya/internal/note"
)

func fingerprintOf(t *testing.T, img string) string {
	t.Helper()
	tg, err := backend.OpenFile(img, backend.FileOptions{SectorSize: 512})
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()
	return tg.Identity().Fingerprint
}

// Three images wiped in parallel by fleet mode: each gets its own journal and a valid,
// logged certificate; the signed manifest lists all three plus one disk that was not
// approved (refused, never opened for writing), and is itself logged and complete.
func TestFleetEndToEnd(t *testing.T) {
	f := newFixture(t, 1<<20)
	r := newRoot(t, f)
	skey, _, _ := note.GenerateKey("127.0.0.1/log")
	s, _ := note.ParseSignerKey(skey)
	lg := startLog(t, r, filepath.Join(f.dir, "log"), s)

	var imgs []string
	var approved bytes.Buffer
	for i, size := range []int{1<<20 + 3*512, 777 * 512, 1 << 19} {
		p := filepath.Join(f.dir, "disk"+string(rune('a'+i))+".img")
		os.WriteFile(p, bytes.Repeat([]byte("secret!"), size/7+1)[:size], 0o600)
		imgs = append(imgs, p)
		approved.WriteString(fingerprintOf(t, p) + "  # " + filepath.Base(p) + "\n")
	}
	stranger := filepath.Join(f.dir, "stranger.img")
	os.WriteFile(stranger, bytes.Repeat([]byte("keep me!"), 1024), 0o600)
	appr := filepath.Join(f.dir, "approved.txt")
	os.WriteFile(appr, approved.Bytes(), 0o600)
	out := filepath.Join(f.dir, "batch")
	os.Mkdir(out, 0o700)

	args := []string{"fleet", "--execute", "--approved", appr, "--yes-really", "--journal-dir", out, "--key", f.key,
		"--station-cert", r.stationCert, "--log", lg.srv.URL, "--log-key", lg.vkey, "--parallel", "3"}
	for _, p := range append(imgs, stranger) {
		args = append(args, "--image", p)
	}
	code, stdout, stderr := runCLI(t, args...)
	if code != 1 { // one disk refused
		t.Fatalf("fleet: %d\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"BATCH RESULT", "MANIFEST ", "LOGGED as entry", "not in the approved list", "what to do:"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("output lacks %q:\n%s\n%s", want, stdout, stderr)
		}
	}
	if strings.Count(stdout, "  certified ") != 3 && strings.Count(stdout, "certified") < 3 {
		t.Fatalf("not three certified:\n%s", stdout)
	}
	if got, _ := os.ReadFile(stranger); !bytes.Equal(got, bytes.Repeat([]byte("keep me!"), 1024)) {
		t.Fatal("the unapproved image was changed")
	}
	for _, p := range imgs {
		if got, _ := os.ReadFile(p); bytes.Contains(got, []byte("secret!")) {
			t.Fatalf("%s still holds old data", p)
		}
	}
	mfs, _ := filepath.Glob(filepath.Join(out, "batch-*.manifest.json"))
	certs, _ := filepath.Glob(filepath.Join(out, "*.cert.json"))
	journals, _ := filepath.Glob(filepath.Join(out, "*.journal"))
	if len(mfs) != 1 || len(certs) != 3 || len(journals) != 3 {
		t.Fatalf("files: %v %v %v", mfs, certs, journals)
	}
	o := certcheck.Options{Root: r.pub, Revocations: r.crl, LogKey: lg.vkey, RequireLog: true}
	res, err := certcheck.VerifyManifest(mfs[0], []string{out}, o)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete() || res.Certified() != 3 || res.Failed() != 1 || !res.Logged.Checked || len(res.Certificates) != 3 {
		t.Fatalf("manifest: complete %v, %d certified, problems %v, invalid %v", res.Complete(), res.Certified(), res.Problems, res.Invalid)
	}
	var refused manifest.Item
	for _, it := range res.Manifest.Items {
		if it.Outcome == manifest.OutcomeRefused {
			refused = it
		}
	}
	if !strings.Contains(refused.Error, "not in the approved list") || refused.CertificateID != "" {
		t.Fatalf("refused item: %+v", refused)
	}
	// A batch whose certificates are not all there is reported incomplete.
	os.Remove(certs[0])
	res, err = certcheck.VerifyManifest(mfs[0], []string{out}, o)
	if err != nil || res.Complete() || len(res.Problems) != 1 {
		t.Fatalf("missing certificate: %v %v", err, res.Problems)
	}
}

func TestFleetDryRunAndUsage(t *testing.T) {
	f := newFixture(t, 1<<20)
	code, out, errs := runCLI(t, "fleet", "--image", f.img)
	if code != 0 || !strings.Contains(out, "DRY RUN of 1 disk") || !strings.Contains(out, "method: auto → overwrite") {
		t.Fatalf("dry run: %d\n%s\n%s", code, out, errs)
	}
	if got, _ := os.ReadFile(f.img); !bytes.Equal(got, f.orig) {
		t.Fatal("dry run changed the image")
	}
	for _, args := range [][]string{
		{"fleet"},
		{"fleet", "--execute", "--journal-dir", f.dir, "--key", f.key, "--image", f.img},                                    // no approval
		{"fleet", "--execute", "--approved", "x", "--yes-really", "--key", f.key, "--image", f.img},                         // no dir
		{"fleet", "--method", "dd", "--image", f.img},                                                                       // bad method
		{"fleet", "--parallel", "0", "--image", f.img},                                                                      // bad parallel
		{"fleet", "--execute", "--approved", "x", "--yes-really", "--journal-dir", f.img, "--key", f.key, "--image", f.img}, // dir is a file
	} {
		if code, _, errs := runCLI(t, args...); code != 2 {
			t.Errorf("%v: %d %s", args, code, errs)
		}
	}
}

// --approved without --yes-really is refused before anything is opened.
func TestFleetNeedsYesReally(t *testing.T) {
	f := newFixture(t, 1<<20)
	appr := filepath.Join(f.dir, "approved.txt")
	os.WriteFile(appr, []byte(fingerprintOf(t, f.img)+"\n"), 0o600)
	if code, _, errs := runCLI(t, "fleet", "--execute", "--approved", appr, "--journal-dir", f.dir, "--key", f.key, "--image", f.img); code != 2 || !strings.Contains(errs, "--yes-really") {
		t.Fatalf("%d %s", code, errs)
	}
	if got, _ := os.ReadFile(f.img); !bytes.Equal(got, f.orig) {
		t.Fatal("image changed")
	}
}

// The method shown in the TUI's plan is the one the run uses, whatever the batch
// default is (here a default that cannot apply to an image file at all).
func TestBatchUsesPinnedMethod(t *testing.T) {
	f := newFixture(t, 1<<20)
	out := filepath.Join(f.dir, "out")
	os.Mkdir(out, 0o700)
	w := wipeFlags{method: engine.MethodATAErase, verify: true, key: f.key, offlineSeed: offlineFull, hpa: engine.HPARestore, sector: 512,
		patterns: engine.PatternRandom, chunkMiB: engine.DefaultChunk >> 20, syncMiB: engine.DefaultSyncEvery >> 20, execute: true, autoVerify: true}
	ts := inspectTargets(nil, []string{f.img}, 512)
	ts[0].method = engine.MethodOverwrite
	rs := runBatch(context.Background(), w, ts, out, 1, func(deviceEvent) {})
	if rs[0].code != 0 || rs[0].res.Method != engine.MethodOverwrite {
		t.Fatalf("code %d method %q: %s", rs[0].code, rs[0].res.Method, rs[0].err)
	}
}
