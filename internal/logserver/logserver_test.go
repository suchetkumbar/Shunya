package logserver_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shunya/internal/audit"
	"shunya/internal/cert"
	"shunya/internal/cert/certtest"
	"shunya/internal/jcs"
	"shunya/internal/keys"
	"shunya/internal/logclient"
	"shunya/internal/logentry"
	"shunya/internal/logserver"
	"shunya/internal/manifest"
	"shunya/internal/note"
	"shunya/internal/tilestore"
)

const origin = "127.0.0.1:8080/log"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	org    *certtest.Org
	signer *note.Signer
	dir    string
	log    *tilestore.Log
	srv    *httptest.Server
	client *logclient.Client
	clk    *clock
	logBuf *bytes.Buffer
}

func newEnv(t *testing.T, rate float64) *env {
	e := &env{org: certtest.NewOrg(t), signer: certtest.LogKey(t, origin), dir: t.TempDir(),
		clk: &clock{t: certtest.T0.AddDate(0, 1, 0)}, logBuf: &bytes.Buffer{}}
	var err error
	if e.log, err = tilestore.Create(e.dir, e.signer); err != nil {
		t.Fatal(err)
	}
	e.start(t, rate)
	return e
}

func (e *env) start(t *testing.T, rate float64) {
	crl, _ := jcs.Marshal(e.org.CRL)
	s, err := logserver.New(logserver.Config{Log: e.log, Dir: e.dir, LogKey: &e.signer.Verifier, Policy: e.org.Policy(), RevocationsFile: crl,
		Logger: slog.New(slog.NewJSONHandler(e.logBuf, nil)), Rate: rate, Burst: rate * 4, Now: e.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(s.Handler())
	t.Cleanup(e.srv.Close)
	e.client = logclient.New(e.srv.URL, &e.signer.Verifier)
}

// logged runs the station's flow: seed request after the wipe, sampled verification
// seeded by the answer, certificate, submission.
func (e *env) logged(t *testing.T, serial string) ([]byte, string) {
	ctx := context.Background()
	fin := e.clk.now().Add(-time.Minute)
	body := e.org.Body(serial, fin)
	q := e.org.SeedRequest(t, body, e.clk.now())
	in, seed, n, err := e.client.Seed(ctx, q)
	if err != nil || n != 1 {
		t.Fatalf("seed: %v (%d)", err, n)
	}
	body = certtest.WithSeed(body, q, in, seed)
	file := e.org.Sign(t, body)
	out, r, err := e.client.Submit(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	return out, r.ID
}

func get(t *testing.T, url string) (int, string) {
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t, 1000)
	file, id := e.logged(t, "SN-1")
	p := e.org.Policy()
	p.LogKey, p.RequireLog = &e.signer.Verifier, true
	r, err := cert.Verify(file, p)
	if err != nil || r.ID != id || !r.Logged.Checked || r.Logged.Index != 2 {
		t.Fatalf("%v %+v", err, r)
	}
	// The recycler page (the QR target) shows the verdict and the device.
	code, page := get(t, e.srv.URL+"/c/"+id)
	if code != 200 || !strings.Contains(page, ">VALID<") || !strings.Contains(page, "SN-1") || !strings.Contains(page, "CLEAR") {
		t.Fatalf("%d\n%s", code, page)
	}
	// The certificate download verifies offline, with the current proof.
	code, dl := get(t, e.srv.URL+"/cert/"+id)
	if code != 200 {
		t.Fatal(code)
	}
	if _, err := cert.Verify([]byte(dl), p); err != nil {
		t.Fatal(err)
	}
	// Submitting again is not a second entry.
	_, r2, err := e.client.Submit(context.Background(), file)
	if err != nil || !r2.Duplicate || r2.Inclusion.Index != 2 || e.log.Size() != 3 {
		t.Fatalf("%v %+v size %d", err, r2, e.log.Size())
	}
	// Unknown and malformed IDs.
	if code, page := get(t, e.srv.URL+"/c/"+strings.Repeat("0", 64)); code != 404 || !strings.Contains(page, "NOT FOUND") {
		t.Fatalf("%d %s", code, page)
	}
	if code, _ := get(t, e.srv.URL+"/c/xyz"); code != 400 {
		t.Fatal(code)
	}
	if code, _ := get(t, e.srv.URL+"/?id="+strings.ToUpper(id)); code != 200 { // redirected to /c/id
		t.Fatal(code)
	}
	// Checkpoint and tiles are served for auditors; the audit passes.
	if code, cp := get(t, e.srv.URL+"/checkpoint"); code != 200 || !strings.HasPrefix(cp, origin+"\n3\n") {
		t.Fatalf("%d %q", code, cp)
	}
	res, err := audit.Run(e.client.FS(context.Background()), &e.signer.Verifier, nil)
	if err != nil || res.Certificates != 1 || res.SeedRequests != 1 || res.Beacons != 1 || len(res.Repeated) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	// The current revocation list is published and verifies against the root.
	if code, rl := get(t, e.srv.URL+"/revocations"); code != 200 {
		t.Fatal(code)
	} else if _, err := keys.ParseRevocationList([]byte(rl), e.org.RootPub); err != nil {
		t.Fatal(err)
	}
	// Consistency endpoint.
	var cr logserver.ConsistencyResponse
	_, body := get(t, e.srv.URL+"/consistency?from=1")
	if err := json.Unmarshal([]byte(body), &cr); err != nil || len(cr.Proof) == 0 {
		t.Fatalf("%v %s", err, body)
	}
	// Access log: one JSON line per request, no query strings.
	for _, line := range strings.Split(strings.TrimSpace(e.logBuf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil || m["msg"] != "request" {
			t.Fatalf("log line %q", line)
		}
		if strings.Contains(line, "?") {
			t.Fatalf("query string logged: %s", line)
		}
	}
}

func TestRefusals(t *testing.T) {
	e := newEnv(t, 1000)
	ctx := context.Background()
	body := e.org.Body("SN-2", e.clk.now().Add(-time.Minute))

	// A dev-key certificate is not logged.
	dev := body
	dev.Station.Certificate, dev.Station.Name = nil, ""
	if _, _, err := e.client.Submit(ctx, e.org.Sign(t, dev)); !errors.Is(err, logclient.ErrRefused) {
		t.Fatalf("dev key: %v", err)
	}
	// Nor a certificate from another organisation.
	other := certtest.NewOrg(t)
	ob := other.Body("SN-3", e.clk.now().Add(-time.Minute))
	if _, _, err := e.client.Submit(ctx, other.Sign(t, ob)); !errors.Is(err, logclient.ErrRefused) {
		t.Fatalf("other root: %v", err)
	}
	// A seed request from another organisation's station is refused.
	if _, _, _, err := e.client.Seed(ctx, other.SeedRequest(t, ob, e.clk.now())); !errors.Is(err, logclient.ErrRefused) {
		t.Fatalf("other root seed: %v", err)
	}
	// A seed request from an uncertified (dev) key is refused.
	dq, err := logentry.NewSeedRequest(e.org.StPriv, nil, body.WipeID, body.Device.Fingerprint, [32]byte{}, keys.FormatTime(e.clk.now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.client.Seed(ctx, dq); !errors.Is(err, logclient.ErrRefused) {
		t.Fatalf("dev-key seed: %v", err)
	}
	// A tampered seed request is refused.
	q := e.org.SeedRequest(t, body, e.clk.now())
	q.Fingerprint = "fp2:" + strings.Repeat("9", 64)
	if _, _, _, err := e.client.Seed(ctx, q); !errors.Is(err, logclient.ErrRefused) {
		t.Fatalf("tampered seed request: %v", err)
	}
	// Oversized and malformed bodies.
	for path, b := range map[string][]byte{"/add": bytes.Repeat([]byte("a"), 70000), "/seed": bytes.Repeat([]byte("a"), 20000)} {
		resp, err := http.Post(e.srv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil || resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s: %v %v", path, err, resp.Status)
		}
		resp.Body.Close()
	}
	resp, _ := http.Post(e.srv.URL+"/seed", "application/json", strings.NewReader(`{"format":"x","extra":1}`))
	if resp.StatusCode != 400 {
		t.Fatal(resp.Status)
	}
	resp.Body.Close()
	// Tile paths: only the tile namespace, canonical paths; never a temporary file
	// left by an interrupted write.
	e.logged(t, "SN-4")
	os.WriteFile(filepath.Join(e.dir, "tile", "0", ".tmp-1"), []byte("debris"), 0o644)
	os.WriteFile(filepath.Join(e.dir, "tile", "0", "000.p", "3.bak"), []byte("debris"), 0o644)
	for p, want := range map[string]int{
		"/tile/0/000.p/3": 200, "/tile/entries/000.p/3": 200, "/tile/0/../checkpoint": 404,
		"/tile/0/.tmp-1": 404, "/tile/0/000.p/3.bak": 404, "/tile/0/00": 404, "/tile/00/000.p/3": 404, "/tile/0/000.p/03": 404, "/tile/x/000": 404, "/tile/0/x000": 404,
	} {
		if code, _ := get(t, e.srv.URL+p); code != want {
			t.Errorf("%s: %d, want %d", p, code, want)
		}
	}
	// A revoked station gets no seeds.
	l, err := e.org.CRL.Revoke(e.org.RootPriv, keys.KeyID(e.org.StPriv.Public().(ed25519.PublicKey)), "compromised", e.clk.now().Add(-time.Hour), e.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	e.org.CRL = l
	e.start(t, 1000)
	if _, _, _, err := e.client.Seed(ctx, e.org.SeedRequest(t, body, e.clk.now())); !errors.Is(err, logclient.ErrRefused) {
		t.Fatalf("revoked station: %v", err)
	}
}

func TestPageEscapes(t *testing.T) {
	e := newEnv(t, 1000)
	_, id := e.logged(t, `<script>alert(1)</script>`)
	_, page := get(t, e.srv.URL+"/c/"+id)
	if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("serial not escaped")
	}
	resp, _ := http.Get(e.srv.URL + "/c/" + id)
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("no CSP")
	}
	resp.Body.Close()
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, 1) // 1 token/s, burst 4
	codes := map[int]int{}
	for i := 0; i < 10; i++ {
		c, _ := get(t, e.srv.URL+"/checkpoint")
		codes[c]++
	}
	if codes[200] != 4 || codes[429] != 6 {
		t.Fatalf("%v", codes)
	}
	e.clk.add(2 * time.Second)
	if c, _ := get(t, e.srv.URL+"/checkpoint"); c != 200 {
		t.Fatal("tokens not refilled")
	}
	// A POST costs 5 tokens: more than the whole burst.
	resp, _ := http.Post(e.srv.URL+"/add", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != 429 {
		t.Fatal(resp.Status)
	}
	resp.Body.Close()
	// The client treats 429 as "unreachable" (retry later), not as a refusal.
	if _, _, err := e.client.Submit(context.Background(), e.org.Sign(t, e.org.Body("SN-9", e.clk.now()))); !errors.Is(err, logclient.ErrUnreachable) {
		t.Fatal(err)
	}
}

// Acceptance: a log that deletes or edits a published entry and re-signs everything
// (so its files are self-consistent) is caught by the audit's consistency check
// against the checkpoint the auditor saved before.
func TestAuditCatchesRewrittenHistory(t *testing.T) {
	e := newEnv(t, 1000)
	e.logged(t, "SN-A")
	e.logged(t, "SN-B")
	saved := e.log.Checkpoint()
	if _, err := audit.Run(os.DirFS(e.dir), &e.signer.Verifier, saved); err != nil {
		t.Fatal(err)
	}
	e.logged(t, "SN-C") // the log grows honestly: still consistent
	if r, err := audit.Run(os.DirFS(e.dir), &e.signer.Verifier, saved); err != nil || r.Previous.Size != 6 || r.Entries != 9 {
		t.Fatalf("%v %+v", err, r)
	}
	var entries [][]byte
	e.log.Entries(func(_ uint64, b []byte) { entries = append(entries, append([]byte(nil), b...)) })

	rebuild := func(es [][]byte) string {
		dir := t.TempDir()
		l, err := tilestore.Create(dir, e.signer) // same key: the operator re-signs
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append(es...); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	edited := append([][]byte{}, entries...)
	edited[2] = bytes.Replace(edited[2], []byte("SN-A"), []byte("SN-Z"), 1)
	deleted := append(append([][]byte{}, entries[:2]...), entries[3:]...)
	for name, dir := range map[string]string{"edited": rebuild(edited), "deleted": rebuild(deleted)} {
		// Without the saved checkpoint the rewritten log looks fine on its own ...
		if _, err := audit.Run(os.DirFS(dir), &e.signer.Verifier, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// ... with it, the consistency proof fails.
		if _, err := audit.Run(os.DirFS(dir), &e.signer.Verifier, saved); !errors.Is(err, audit.ErrInconsistent) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Tampering behind the log's back (no re-signing) fails the content check.
	b := filepath.Join(e.dir, "tile", "entries", "000.p", "9")
	raw, _ := os.ReadFile(b)
	os.WriteFile(b, bytes.Replace(raw, []byte("SN-B"), []byte("SN-Y"), 1), 0o644)
	if _, err := audit.Run(os.DirFS(e.dir), &e.signer.Verifier, saved); !errors.Is(err, audit.ErrContent) {
		t.Fatalf("edited bundle: %v", err)
	}
	// A log that shrank.
	if _, err := audit.Run(os.DirFS(rebuild(entries[:3])), &e.signer.Verifier, saved); !errors.Is(err, audit.ErrInconsistent) {
		t.Fatalf("shrunk: %v", err)
	}
}

func TestAuditFlagsRepeatedSeeds(t *testing.T) {
	e := newEnv(t, 1000)
	body := e.org.Body("SN-R", e.clk.now().Add(-time.Minute))
	for i := 0; i < 2; i++ {
		_, _, n, err := e.client.Seed(context.Background(), e.org.SeedRequest(t, body, e.clk.now()))
		if err != nil || n != i+1 {
			t.Fatal(err, n)
		}
	}
	r, err := audit.Run(os.DirFS(e.dir), &e.signer.Verifier, nil)
	if err != nil || len(r.Repeated) != 1 || !strings.Contains(r.Repeated[0], "2 seed requests") {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestReloadIndexes(t *testing.T) {
	e := newEnv(t, 1000)
	_, id := e.logged(t, "SN-L")
	l, err := tilestore.Load(e.dir, e.signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.log = l
	e.start(t, 1000)
	if code, page := get(t, e.srv.URL+"/c/"+id); code != 200 || !strings.Contains(page, ">VALID<") {
		t.Fatal(code)
	}
}

// A fleet batch manifest is logged like a certificate: verified under the root and the
// revocation list first, logged once, its proof checked by the client; a reload keeps it.
func TestManifest(t *testing.T) {
	e := newEnv(t, 1000)
	ctx := context.Background()
	file, _ := e.logged(t, "SN-M1")
	cr, err := cert.Verify(file, e.org.Policy())
	if err != nil {
		t.Fatal(err)
	}
	pub := e.org.StPriv.Public().(ed25519.PublicKey)
	st := e.org.Station
	m := manifest.Manifest{BatchID: strings.Repeat("0c", 16), Created: keys.FormatTime(e.clk.now()), Tool: "shunya test",
		Station: cert.StationFor(pub, &st), Items: []manifest.Item{manifest.ItemFor(cr)}}
	mf, err := manifest.Sign(m, e.org.StPriv)
	if err != nil {
		t.Fatal(err)
	}
	out, r, err := e.client.SubmitManifest(ctx, mf)
	if err != nil || r.Duplicate {
		t.Fatalf("submit: %v %+v", err, r)
	}
	p := e.org.Policy()
	p.LogKey, p.RequireLog = &e.signer.Verifier, true
	if mr, err := manifest.Verify(out, p); err != nil || !mr.Logged.Checked {
		t.Fatalf("logged manifest: %v", err)
	}
	if _, r2, err := e.client.SubmitManifest(ctx, mf); err != nil || !r2.Duplicate || r2.Inclusion.Index != r.Inclusion.Index {
		t.Fatalf("resubmit: %v %+v", err, r2)
	}
	// A certificate is not a manifest, and a dev-key manifest is refused.
	if _, _, err := e.client.SubmitManifest(ctx, file); err == nil {
		t.Error("certificate accepted at /manifest")
	}
	_, dev, _ := ed25519.GenerateKey(nil)
	m.Station = cert.StationFor(dev.Public().(ed25519.PublicKey), nil)
	devFile, _ := manifest.Sign(m, dev)
	if _, _, err := e.client.SubmitManifest(ctx, devFile); !errors.Is(err, logclient.ErrRefused) {
		t.Errorf("dev-key manifest: %v", err)
	}
	ar, err := audit.Run(os.DirFS(e.dir), &e.signer.Verifier, nil)
	if err != nil || ar.Manifests != 1 {
		t.Fatalf("audit: %v %+v", err, ar)
	}
	l, err := tilestore.Load(e.dir, e.signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.log = l
	e.start(t, 1000)
	if _, r3, err := e.client.SubmitManifest(ctx, mf); err != nil || !r3.Duplicate {
		t.Fatalf("after reload: %v %+v", err, r3)
	}
}
