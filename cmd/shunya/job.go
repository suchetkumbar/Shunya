package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"shunya/internal/backend"
	"shunya/internal/cert"
	"shunya/internal/engine"
	"shunya/internal/journal"
	"shunya/internal/keys"
	"shunya/internal/logclient"
	"shunya/internal/manifest"
)

// methodAuto selects the planner's recommendation (engine.Recommend: the strongest
// method whose preconditions the drive meets; overwrite, labelled Clear, otherwise).
const methodAuto = "auto"

// jobResult is what one wipe produced, filled in as it goes (wipeFlags.result).
type jobResult struct {
	Method   string
	Plan     *engine.Plan
	WipeID   string
	Started  bool // the journal exists: the wipe began
	CertID   string
	CertJSON string
	CertPDF  string
	QR       string
	Logged   bool
	LogIndex uint64
}

// batchTarget is one device (or image) of a batch, inspected before anything runs.
type batchTarget struct {
	path    string
	isImage bool
	spec    *targetSpec // nil: refused at inspection
	refusal string      // why, if refused
	confirm string      // what the operator typed for this disk (TUI), passed as --confirm
	method  string      // the method the operator was shown (TUI): the run uses exactly it
}

// label is a short name for the target: the device name or image file name.
func (t batchTarget) label() string { return filepath.Base(t.path) }

// identity of the target as far as it is known.
func (t batchTarget) identity() backend.Identity {
	if t.spec != nil {
		return t.spec.id
	}
	return backend.Identity{Path: t.path}
}

// itemResult is the outcome of one target of a batch.
type itemResult struct {
	target  batchTarget
	code    int
	res     jobResult
	journal string
	logFile string
	outcome string
	err     string // a short, human summary (failed, refused, interrupted)
	explain []Explanation
}

// deviceEvent reports one target's progress to whoever shows the batch.
type deviceEvent struct {
	idx      int
	line     string           // one line of the wipe's output
	progress *engine.Progress // overwrite progress
	done     *itemResult
}

// inspectTargets resolves every target read-only; refused ones keep the reason.
func inspectTargets(paths []string, images []string, sector int) []batchTarget {
	var out []batchTarget
	add := func(p string, img bool) {
		var buf bytes.Buffer
		spec, code := inspect(p, img, sector, &buf)
		t := batchTarget{path: p, isImage: img, spec: spec}
		if code != 0 {
			t.spec = nil
			t.refusal = strings.TrimSpace(buf.String())
			if t.refusal == "" {
				t.refusal = fmt.Sprintf("inspection failed (exit %d)", code)
			}
		} else if spec != nil {
			t.path = spec.path
		}
		out = append(out, t)
	}
	for _, p := range paths {
		add(p, false)
	}
	for _, p := range images {
		add(p, true)
	}
	return out
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// journalFor names a new journal for target i of a batch in dir: position, device
// name, serial and the batch's start time.
func journalFor(dir string, i int, t batchTarget, at time.Time) string {
	name := fmt.Sprintf("%02d-%s", i+1, t.label())
	if s := t.identity().Serial; s != "" && !t.isImage {
		name += "-" + s
	}
	name = strings.Trim(unsafeName.ReplaceAllString(name, "_"), "_")
	return filepath.Join(dir, name+"-"+at.UTC().Format("20060102T150405Z")+".journal")
}

// lineWriter turns writes into whole lines for an event callback, and keeps a copy.
type lineWriter struct {
	mu   sync.Mutex
	buf  []byte
	copy io.Writer
	emit func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.copy != nil {
		w.copy.Write(p)
	}
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexAny(w.buf, "\n\r")
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(w.buf[:i])); line != "" {
			w.emit(line)
		}
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

func (w *lineWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if line := strings.TrimSpace(string(w.buf)); line != "" {
		w.emit(line)
	}
	w.buf = nil
}

// runBatch wipes the targets with at most parallel at once. Each runs the exact path
// of "shunya wipe" (freshWipe, then the certificate), with its own journal and log
// file in f.journal's directory; refused targets are reported without running.
// emit may be called from several goroutines at once.
func runBatch(ctx context.Context, f wipeFlags, targets []batchTarget, dir string, parallel int, emit func(deviceEvent)) []itemResult {
	results := make([]itemResult, len(targets))
	sem := make(chan struct{}, max(parallel, 1))
	var wg sync.WaitGroup
	start := now()
	for i, t := range targets {
		results[i].target = t
		if t.spec == nil {
			r := &results[i]
			r.outcome, r.err, r.code = manifest.OutcomeRefused, firstLine(t.refusal), 1
			r.explain = Explain(t.refusal)
			emit(deviceEvent{idx: i, line: "REFUSED: " + r.err})
			emit(deviceEvent{idx: i, done: r})
			continue
		}
		wg.Add(1)
		go func(i int, t batchTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				r := &results[i]
				r.outcome, r.err, r.code = manifest.OutcomeInterrupted, "cancelled before it started", exitInterrupted
				emit(deviceEvent{idx: i, done: r})
				return
			}
			results[i] = runOne(ctx, f, i, t, dir, start, func(e deviceEvent) { e.idx = i; emit(e) })
			emit(deviceEvent{idx: i, done: &results[i]})
		}(i, t)
	}
	wg.Wait()
	return results
}

// runOne runs one target's wipe and certificate, as "shunya wipe --execute" would.
func runOne(ctx context.Context, f wipeFlags, i int, t batchTarget, dir string, at time.Time, emit func(deviceEvent)) itemResult {
	r := itemResult{target: t, journal: journalFor(dir, i, t, at)}
	r.logFile = r.journal + ".log"
	logf, err := os.OpenFile(r.logFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		r.code, r.outcome, r.err = 1, manifest.OutcomeFailed, err.Error()
		return r
	}
	defer logf.Close()
	var errText bytes.Buffer
	out := &lineWriter{copy: logf, emit: func(l string) { emit(deviceEvent{line: l}) }}
	errw := &lineWriter{copy: io.MultiWriter(logf, &errText), emit: func(l string) { emit(deviceEvent{line: l}) }}
	g := f
	g.ctx, g.result, g.journal = ctx, &r.res, r.journal
	if t.method != "" {
		g.method = t.method
	}
	if t.confirm != "" {
		g.confirm, g.yesReally = t.confirm, false
	}
	g.onProgress = func(p engine.Progress) { emit(deviceEvent{progress: &p}) }
	dev := t.path
	if t.isImage {
		g.image, dev = t.path, ""
	}
	r.code = certifyAfter(g, freshWipe(g, dev, out, errw), out, errw)
	out.flush()
	errw.flush()
	r.outcome = outcomeOf(r.code, r.res)
	if r.outcome != manifest.OutcomeCertified {
		text := errText.String()
		r.explain = Explain(text)
		r.err = summary(r, text)
		if r.outcome == manifest.OutcomeNotCertified && g.stationCert == "" {
			r.err = "no station certificate was given (--station-cert), so no certificate was issued"
		}
	}
	return r
}

func outcomeOf(code int, res jobResult) string {
	switch {
	case code == 0 && res.CertID != "":
		return manifest.OutcomeCertified
	case code == 0:
		return manifest.OutcomeNotCertified
	case code == exitVerifyFail:
		return manifest.OutcomeVerifyFailed
	case code == exitInterrupted:
		return manifest.OutcomeInterrupted
	case !res.Started:
		return manifest.OutcomeRefused
	}
	return manifest.OutcomeFailed
}

func summary(r itemResult, stderrText string) string {
	if len(r.explain) > 0 {
		return r.explain[0].What
	}
	switch r.outcome {
	case manifest.OutcomeNotCertified:
		return "the wipe has no passing verification, so no certificate was issued"
	case manifest.OutcomeVerifyFailed:
		return "the read-back found sectors that were not erased"
	case manifest.OutcomeInterrupted:
		return "interrupted; resume it from its journal"
	}
	if l := lastLine(stderrText); l != "" {
		return strings.TrimPrefix(l, "shunya: ")
	}
	return fmt.Sprintf("failed (exit %d)", r.code)
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimPrefix(l, "shunya: ")
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// writeManifest signs the batch manifest into dir (and logs it with --log).
func writeManifest(f wipeFlags, results []itemResult, dir string, stdout io.Writer) (string, error) {
	priv, err := journal.LoadKeyFile(f.key)
	if err != nil {
		return "", err
	}
	var sc *keys.StationCert
	if f.stationCert != "" {
		b, err := os.ReadFile(f.stationCert)
		if err != nil {
			return "", err
		}
		c, err := keys.DecodeStationCert(b)
		if err != nil {
			return "", err
		}
		sc = &c
	}
	m := manifest.Manifest{BatchID: engine.NewWipeID(), Created: keys.FormatTime(now()), Tool: "shunya " + version,
		Station: cert.StationFor(priv.Public().(ed25519.PublicKey), sc)}
	seen := map[string]bool{}
	for _, r := range results {
		id := r.target.identity()
		fp := id.Fingerprint
		if fp == "" || seen[fp] {
			fp = "unknown:" + r.target.path // refused before it could be identified
		}
		seen[fp] = true
		it := manifest.Item{Path: r.target.path, Model: id.Model, Serial: id.Serial, Fingerprint: fp,
			Method: r.res.Method, Outcome: r.outcome, WipeID: r.res.WipeID, Error: r.err}
		if p := r.res.Plan; p != nil {
			it.NISTLevel = string(p.Level)
		}
		if r.outcome == manifest.OutcomeCertified {
			it.CertificateID, it.Error = r.res.CertID, ""
		}
		m.Items = append(m.Items, it)
	}
	file, err := manifest.Sign(m, priv)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "batch-"+m.BatchID+".manifest.json")
	if err := writeFile(path, file, false); err != nil {
		return "", err
	}
	id, _ := manifest.FileID(file)
	fmt.Fprintf(stdout, "MANIFEST %s\n  %s\n", id, path)
	if f.logURL != "" {
		c, err := newLogClient(f)
		if err != nil {
			return path, err
		}
		out, r, err := c.SubmitManifest(context.Background(), file)
		switch {
		case err == nil:
			if err := writeFile(path, out, true); err != nil {
				return path, err
			}
			fmt.Fprintf(stdout, "  LOGGED as entry %d; proof verified and added\n", r.Inclusion.Index)
		case errors.Is(err, logclient.ErrUnreachable):
			fmt.Fprintf(stdout, "  log unreachable (%v): the manifest is valid but not logged\n", err)
		default:
			return path, fmt.Errorf("log submission: %w", err)
		}
	}
	return path, nil
}
