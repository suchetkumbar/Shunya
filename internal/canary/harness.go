package canary

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"shunya/internal/backend"
)

// Plant fills the whole target with this run's canaries, chunk bytes at a time.
func Plant(ctx context.Context, t backend.Target, set *Set, chunk int) error {
	sector := t.SectorSize()
	if chunk <= 0 || chunk%sector != 0 || chunk%TokenSize != 0 {
		return fmt.Errorf("plant: bad chunk %d", chunk)
	}
	buf := backend.AlignedBuffer(chunk, max(4096, t.PhysicalSectorSize()))
	size := t.Size()
	for off := int64(0); off < size; off += int64(chunk) {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := int(min(int64(chunk), size-off))
		for s := 0; s < n; s += sector {
			set.FillSector(buf[s:s+sector], uint64((off+int64(s))/int64(sector)))
		}
		if _, err := t.WriteAt(buf[:n], off); err != nil {
			return fmt.Errorf("plant at %d: %w", off, err)
		}
	}
	return t.Sync()
}

// Carve is what a file carver recovered.
type Carve struct {
	Tool       string         `json:"tool"`
	Ran        bool           `json:"ran"`
	SkipReason string         `json:"skip_reason,omitempty"`
	Total      int            `json:"total"`               // files carved (any content)
	ByType     map[string]int `json:"by_type"`             // by extension
	WithMarker int            `json:"with_marker"`         // carved files containing a planted marker
	Identical  int            `json:"identical"`           // carved files byte-identical to a planted file
	Recovered  []string       `json:"recovered,omitempty"` // planted files found intact
}

// InspectCarved walks a carver's output directory and matches every carved file
// against the planted files (by marker and by SHA-256). Carver bookkeeping files
// (report.xml) are ignored.
func InspectCarved(tool, dir string, planted []Planted) (Carve, error) {
	c := Carve{Tool: tool, Ran: true, ByType: map[string]int{}}
	byHash := map[string]string{}
	for _, p := range planted {
		byHash[p.SHA256] = p.Name
	}
	found := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "report.xml" || strings.HasSuffix(d.Name(), ".log") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		c.Total++
		c.ByType[strings.TrimPrefix(filepath.Ext(path), ".")]++
		for _, p := range planted {
			if bytes.Contains(b, []byte(p.Marker)) {
				c.WithMarker++
				break
			}
		}
		h := sha256.Sum256(b)
		if name, ok := byHash[hex.EncodeToString(h[:])]; ok {
			c.Identical++
			found[name] = true
		}
		return nil
	})
	for n := range found {
		c.Recovered = append(c.Recovered, n)
	}
	sort.Strings(c.Recovered)
	return c, err
}

// Phase is one look at the target: raw scan plus carving.
type Phase struct {
	Residue Residue `json:"residue"`
	Carve   Carve   `json:"carve"`
}

// Case is one target × file system run.
type Case struct {
	Name       string   `json:"name"`
	Device     string   `json:"device"`
	Serial     string   `json:"serial"`
	FS         string   `json:"fs"`
	Broken     bool     `json:"broken_wipe"` // negative test: the wipe skipped the last 1 %
	Skipped    string   `json:"skipped,omitempty"`
	SizeBytes  int64    `json:"size_bytes"`
	SkipFrom   int64    `json:"skip_from,omitempty"` // broken: first byte the wipe did not write
	Before     Phase    `json:"before"`
	WipeExit   int      `json:"wipe_exit"`
	VerifyExit int      `json:"verify_exit"` // full read-back after the wipe (4 = mismatch)
	After      Phase    `json:"after"`
	Pass       bool     `json:"pass"`
	Why        []string `json:"why,omitempty"` // reasons for failure
	Seconds    float64  `json:"seconds"`
}

// Evaluate decides whether a case passed.
//
// Normal case: the test was not vacuous (before the wipe the scan found canaries and
// every marker, and the carver, if it ran, recovered every planted file intact), and
// after the wipe nothing remains (no token, partial or marker; no carved file with
// planted content) and verification passed.
//
// Broken case: the harness must catch the incomplete wipe: residue is found after the
// wipe, all of it at or beyond the first unwritten byte.
func (c *Case) Evaluate(planted []Planted) {
	c.Why = nil
	fail := func(f string, a ...any) { c.Why = append(c.Why, fmt.Sprintf(f, a...)) }
	if c.Skipped != "" {
		c.Pass = false
		return
	}
	b := c.Before
	if b.Residue.Tokens == 0 {
		fail("vacuous: no canaries found before the wipe")
	}
	for mk, n := range b.Residue.Markers {
		if n == 0 {
			fail("vacuous: marker %s not on disk before the wipe", mk)
		}
	}
	if b.Carve.Ran && len(b.Carve.Recovered) < len(planted) {
		fail("vacuous: carver recovered %d of %d planted files before the wipe", len(b.Carve.Recovered), len(planted))
	}
	a := c.After
	if c.Broken {
		if a.Residue.Tokens == 0 {
			fail("broken wipe NOT caught: no canaries found after a wipe that skipped the last 1%%")
		} else if a.Residue.FirstOffset < c.SkipFrom {
			fail("residue at %d, before the skipped tail at %d", a.Residue.FirstOffset, c.SkipFrom)
		}
		if c.VerifyExit != 4 {
			fail("full verification exit %d after a broken wipe, want 4", c.VerifyExit)
		}
	} else {
		if !a.Residue.Clean() {
			fail("residue after the wipe: %d tokens, %d partial, %d marker hits (first at %d)",
				a.Residue.Tokens, a.Residue.Partial, a.Residue.MarkerHits(), a.Residue.FirstOffset)
		}
		if a.Carve.WithMarker > 0 || a.Carve.Identical > 0 {
			fail("carver recovered %d file(s) with planted content after the wipe", a.Carve.WithMarker)
		}
		if c.WipeExit != 0 || c.VerifyExit != 0 {
			fail("wipe exit %d, verify exit %d", c.WipeExit, c.VerifyExit)
		}
	}
	c.Pass = len(c.Why) == 0
}

// Report is the harness's output.
type Report struct {
	Version  int       `json:"version"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Build    string    `json:"build"`
	Planted  []Planted `json:"planted"`
	Cases    []Case    `json:"cases"`
	Pass     bool      `json:"pass"` // every non-skipped case passed and at least one ran
}

// Finish evaluates every case and the overall result.
func (r *Report) Finish() {
	r.Finished = time.Now().UTC()
	ran := 0
	r.Pass = true
	for i := range r.Cases {
		r.Cases[i].Evaluate(r.Planted)
		if r.Cases[i].Skipped != "" {
			continue
		}
		ran++
		r.Pass = r.Pass && r.Cases[i].Pass
	}
	r.Pass = r.Pass && ran > 0
}

// WriteFiles writes report.json and the human summary report.txt into dir.
func (r *Report) WriteFiles(dir, base string) error {
	j, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, base+".json"), append(j, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, base+".txt"), []byte(r.Summary()), 0o644)
}

// Summary is the human-readable report.
func (r *Report) Summary() string {
	var b strings.Builder
	verdict := "PASS"
	if !r.Pass {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "Shunya forensic canary harness: %s (%s build, %s)\n", verdict, r.Build, r.Finished.Format(time.RFC3339))
	fmt.Fprintf(&b, "Planted: per-sector HMAC canaries over the whole disk, plus %d files:", len(r.Planted))
	for _, p := range r.Planted {
		fmt.Fprintf(&b, " %s (%d B)", p.Name, p.Size)
	}
	b.WriteString("\n\n")
	for _, c := range r.Cases {
		res := "PASS"
		switch {
		case c.Skipped != "":
			res = "SKIPPED: " + c.Skipped
		case !c.Pass:
			res = "FAIL"
		}
		kind := "wipe"
		if c.Broken {
			kind = "BROKEN wipe (skips last 1%; must be caught)"
		}
		fmt.Fprintf(&b, "%-28s %-8s %s — %s\n", c.Name, c.FS, kind, res)
		if c.Skipped != "" {
			continue
		}
		fmt.Fprintf(&b, "  before: %d canary tokens, %d marker hits; %s carved %d file(s), %d intact planted: %s\n",
			c.Before.Residue.Tokens, c.Before.Residue.MarkerHits(), carver(c.Before.Carve), c.Before.Carve.Total,
			len(c.Before.Carve.Recovered), strings.Join(c.Before.Carve.Recovered, ", "))
		fmt.Fprintf(&b, "  wipe exit %d, full verify exit %d\n", c.WipeExit, c.VerifyExit)
		fmt.Fprintf(&b, "  after:  %d canary tokens, %d partial, %d marker hits", c.After.Residue.Tokens, c.After.Residue.Partial, c.After.Residue.MarkerHits())
		if c.After.Residue.FirstOffset >= 0 {
			fmt.Fprintf(&b, " (bytes %d..%d", c.After.Residue.FirstOffset, c.After.Residue.LastOffset)
			if c.Broken {
				fmt.Fprintf(&b, "; unwritten tail starts at %d", c.SkipFrom)
			}
			b.WriteString(")")
		}
		fmt.Fprintf(&b, "; %s carved %d file(s), %d with planted content\n", carver(c.After.Carve), c.After.Carve.Total, c.After.Carve.WithMarker)
		for _, w := range c.Why {
			fmt.Fprintf(&b, "  ! %s\n", w)
		}
	}
	b.WriteString("\nNotes: a scan finds any surviving fragment of 8+ bytes holding the canary magic, at any byte\n" +
		"offset; shorter fragments are not detectable. Files carved after the wipe that contain no planted\n" +
		"content are coincidences in the random pattern and are counted but not failures.\n")
	return b.String()
}

func carver(c Carve) string {
	if !c.Ran {
		return c.Tool + " (not run: " + c.SkipReason + ")"
	}
	return c.Tool
}
