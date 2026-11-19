package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"shunya/internal/certcheck"
	"shunya/internal/engine"
	"shunya/internal/manifest"
	"shunya/internal/note"
)

// pump runs cmd and feeds every message it produces back into the model, until there
// is nothing left (or the deadline passes): the TUI's event loop without a terminal.
func pump(t *testing.T, m *tuiModel, cmd tea.Cmd) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 {
		if time.Now().After(deadline) {
			t.Fatal("TUI did not settle")
		}
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		msg := c()
		if b, ok := msg.(tea.BatchMsg); ok {
			queue = append(queue, b...)
			continue
		}
		if msg == nil {
			continue
		}
		if _, ok := msg.(tea.QuitMsg); ok {
			continue
		}
		_, next := m.Update(msg)
		queue = append(queue, next)
	}
}

func press(t *testing.T, m *tuiModel, keys ...string) {
	t.Helper()
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "up":
			msg = tea.KeyMsg{Type: tea.KeyUp}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "space":
			msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(" ")}
		case "backspace":
			msg = tea.KeyMsg{Type: tea.KeyBackspace}
		case "ctrl+c":
			msg = tea.KeyMsg{Type: tea.KeyCtrlC}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		_, cmd := m.Update(msg)
		pump(t, m, cmd)
	}
}

func mustView(t *testing.T, m *tuiModel, wants ...string) {
	t.Helper()
	v := m.View()
	for _, w := range wants {
		if !strings.Contains(v, w) {
			t.Fatalf("view lacks %q:\n%s", w, v)
		}
	}
}

// fakeBE plans and "wipes" without touching anything.
type fakeBE struct {
	plans     map[string]planInfo
	started   [][]string // confirms per Start
	devs      []tuiDevice
	cancelled bool
	hold      chan struct{} // if set, Start waits for it before finishing

	mu           sync.Mutex
	planConfirms map[string]string // path → the confirmation its plan was made with
}

func (f *fakeBE) Plan(d tuiDevice, confirm string) planInfo {
	f.mu.Lock()
	if f.planConfirms == nil {
		f.planConfirms = map[string]string{}
	}
	f.planConfirms[d.path] = confirm
	f.mu.Unlock()
	if p, ok := f.plans[d.path]; ok {
		return p
	}
	return planInfo{method: engine.MethodOverwrite, level: "Clear", estimate: "1m0s", verify: "full read-back of every sector"}
}

func (f *fakeBE) Start(devs []tuiDevice, confirms []string) <-chan tea.Msg {
	f.started, f.devs = append(f.started, confirms), devs
	ch := make(chan tea.Msg, 16)
	go func() {
		defer close(ch)
		var rs []itemResult
		for i, d := range devs {
			ch <- devMsg{deviceEvent{idx: i, line: "wipe 00 started; journal x"}}
			ch <- devMsg{deviceEvent{idx: i, progress: &engine.Progress{Done: 50, Total: 100, BytesPerSec: 2e6}}}
			if f.hold != nil {
				<-f.hold
			}
			r := itemResult{target: batchTarget{path: d.path}, outcome: manifest.OutcomeCertified,
				res: jobResult{CertID: strings.Repeat("ab", 32), CertJSON: d.path + ".cert.json", Method: d.method}}
			ch <- devMsg{deviceEvent{idx: i, done: &r}}
			rs = append(rs, r)
		}
		ch <- doneMsg{results: rs, manifest: "MANIFEST 1234\n"}
	}()
	return ch
}

func (f *fakeBE) Cancel() { f.cancelled = true }

func fakeDevs() []tuiDevice {
	return []tuiDevice{
		{path: "/dev/vda", model: "QEMU boot", serial: "SHUNYA-BOOT-0", why: "PROTECTED: root filesystem / via vda3"},
		{path: "/dev/vdb", model: "QEMU disk", serial: "SHUNYA-VIRTIO-01", media: "virtual", size: "1.0GiB"},
		{path: "/dev/sdb", model: "SHUNYA LAB SATA HDD", serial: "SHUNYA-SATA-HDD-01", media: "hdd", size: "1.0GiB"},
		{path: "/dev/nvme0n1", model: "QEMU NVMe Ctrl", serial: "SHUNYA-NVME-01", media: "nvme", size: "1.0GiB"},
	}
}

func TestTUIFlow(t *testing.T) {
	be := &fakeBE{plans: map[string]planInfo{"/dev/nvme0n1": {method: engine.MethodNVMeFormatUserData, level: "Purge", estimate: "1s", verify: "marker check"}}}
	m := newTUIModel(fakeDevs(), be, false)
	if m.cursor != 1 {
		t.Fatalf("cursor starts on %d, not the first selectable disk", m.cursor)
	}
	mustView(t, m, "PROTECTED: root filesystem", "[ ] /dev/vdb")
	press(t, m, "up", "space") // the protected disk cannot be selected
	if len(m.selected) != 0 && m.selected[0] {
		t.Fatal("protected disk selected")
	}
	press(t, m, "down", "space", "down", "space", "down", "space")
	mustView(t, m, "[x] /dev/vdb", "[x] /dev/sdb", "[x] /dev/nvme0n1")
	press(t, m, "enter")
	// Confirmation comes first: release builds may only identify a drive (NVMe
	// Identify) once the operator has confirmed it.
	if m.scr != scrConfirm {
		t.Fatalf("screen %d", m.scr)
	}
	mustView(t, m, "CONFIRM 1 of 3", "SHUNYA-VIRTIO-01", "LAST 4 CHARACTERS")
	if len(be.planConfirms) != 0 {
		t.Fatal("planned before confirmation")
	}
	// A wrong confirmation starts nothing and says so.
	press(t, m, "0", "0", "0", "0", "enter")
	mustView(t, m, "is not the end of the serial number. Nothing was wiped")
	if len(be.started) != 0 {
		t.Fatal("started after a wrong confirmation")
	}
	press(t, m, "-", "0", "1", "backspace", "1", "enter") // "-01" → "-0" → "-01"? no: types "-01", deletes, retypes
	if m.confIdx != 0 {
		t.Fatalf("accepted a 3-character confirmation for a 4-character tail")
	}
	press(t, m, "o", "-", "0", "1", "enter") // case-insensitive "O-01"
	mustView(t, m, "CONFIRM 2 of 3", "SHUNYA-SATA-HDD-01")
	press(t, m, "D", "-", "0", "1", "enter")
	press(t, m, "E", "-", "0", "1", "enter")
	// The plan: made with each disk's own confirmation, and nothing starts yet.
	if m.scr != scrPlan || len(be.started) != 0 {
		t.Fatalf("screen %d, started %v", m.scr, be.started)
	}
	if got := be.planConfirms; got["/dev/vdb"] != "o-01" || got["/dev/sdb"] != "D-01" || got["/dev/nvme0n1"] != "E-01" {
		t.Fatalf("plans made with confirmations %v", got)
	}
	mustView(t, m, "PLAN — nothing has been written yet", "nvme-format-user-data-erase — NIST SP 800-88 Purge", "method overwrite — NIST SP 800-88 Clear")
	press(t, m, "esc") // back to the list: confirmations and plans are discarded
	if m.scr != scrPick {
		t.Fatalf("esc on the plan: screen %d", m.scr)
	}
	press(t, m, "enter")
	if m.scr != scrConfirm || m.confIdx != 0 || len(m.plans) != 0 {
		t.Fatalf("re-entry kept old confirmations: screen %d idx %d plans %d", m.scr, m.confIdx, len(m.plans))
	}
	press(t, m, "O", "-", "0", "1", "enter", "D", "-", "0", "1", "enter", "E", "-", "0", "1", "enter", "enter")
	if len(be.started) != 1 || strings.Join(be.started[0], ",") != "O-01,D-01,E-01" {
		t.Fatalf("started with %v", be.started)
	}
	if be.devs[2].method != engine.MethodNVMeFormatUserData || be.devs[0].method != engine.MethodOverwrite {
		t.Fatalf("the run does not use the planned methods: %+v", be.devs)
	}
	if m.scr != scrDone || m.code != 0 {
		t.Fatalf("screen %d code %d", m.scr, m.code)
	}
	mustView(t, m, "RESULT — 3 disk(s)", "erased and verified", strings.Repeat("ab", 32), "MANIFEST 1234")
}

func TestTUIRefusedPlanBlocks(t *testing.T) {
	be := &fakeBE{plans: map[string]planInfo{"/dev/vdb": {err: "PRECONDITIONS NOT MET: frozen", explain: Explain(FrozenText())}}}
	m := newTUIModel(fakeDevs(), be, false)
	press(t, m, "enter") // nothing selected: the disk under the cursor
	press(t, m, "O", "-", "0", "1", "enter")
	mustView(t, m, "CANNOT WIPE THIS DISK", "What to do:", "Suspend the computer")
	press(t, m, "enter")
	if m.scr != scrPlan {
		t.Fatal("continued past a refused plan")
	}
	press(t, m, "esc")
	if m.scr != scrPick {
		t.Fatal("esc did not go back")
	}
}

func FrozenText() string { return "The drive is in Security FROZEN mode: …" }

func TestTUISimpleAndStop(t *testing.T) {
	be := &fakeBE{hold: make(chan struct{})}
	m := newTUIModel(fakeDevs(), be, true)
	mustView(t, m, "one-click wipe", "Which disk do you want to erase?")
	press(t, m, "enter", "O", "-", "0", "1", "enter")
	mustView(t, m, "█", "READY", "overwrite every sector with random data", "cannot be undone", "Press Enter to start")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	// The wipe runs (held by the fake): the big status shows its progress.
	msg := cmd()
	m.Update(msg) // started line
	m.Update(m.wait()())
	mustView(t, m, "WIPING 50%", "do not unplug")
	press(t, m, "ctrl+c")
	mustView(t, m, "Press Ctrl+C again to stop")
	if be.cancelled {
		t.Fatal("one Ctrl+C cancelled")
	}
	press(t, m, "esc")
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if !be.cancelled {
		t.Fatal("two Ctrl+C did not cancel")
	}
	close(be.hold)
	pump(t, m, m.wait())
	mustView(t, m, "DONE", "erased and verified")
}

func TestBigText(t *testing.T) {
	for _, w := range []string{"READY", "WIPING 100%", "CHECKING", "DONE", "FAILED", "0123456789"} {
		out := bigText(w)
		lines := strings.Split(out, "\n")
		if len(lines) != 6 || lines[5] != w {
			t.Fatalf("%q: %q", w, out)
		}
		for _, r := range w {
			if _, ok := bigGlyphs[r]; !ok {
				t.Errorf("%q: no glyph for %q", w, r)
			}
		}
	}
}

func TestPhaseOf(t *testing.T) {
	for line, want := range map[string]string{
		"wipe 1a started; journal /x":           "wiping",
		"  sanitize in progress: 40%":           "erasing (drive firmware)",
		"DONE: 1 pass(es), 1.0MiB written":      "verifying",
		"VERIFIED (full): all 1.0MiB read back": "certifying",
		"CERTIFICATE abc":                       "certificate issued",
		"FAILED: boom":                          "failed",
	} {
		if got, _, ok := phaseOf(strings.TrimSpace(line)); !ok || got != want {
			t.Errorf("%q: %q", line, got)
		}
	}
	if _, f, _ := phaseOf("sanitize in progress: 40%"); f != 0.4 {
		t.Errorf("sanitize fraction %v", f)
	}
}

// The real TUI backend on three image files: keypresses alone select, confirm and wipe
// all three in parallel; each gets a valid certificate, and the manifest is complete.
func TestTUILiveImages(t *testing.T) {
	f := newFixture(t, 1<<20)
	r := newRoot(t, f)
	skey, _, _ := note.GenerateKey("127.0.0.1/log")
	s, _ := note.ParseSignerKey(skey)
	lg := startLog(t, r, filepath.Join(f.dir, "log"), s)
	out := filepath.Join(f.dir, "out")
	os.Mkdir(out, 0o700)
	var imgs []string
	for i := range 3 {
		p := filepath.Join(f.dir, "t"+string(rune('a'+i))+".img")
		os.WriteFile(p, bytes.Repeat([]byte("private"), (1<<20)/7+400)[:1<<20+i*512], 0o600)
		imgs = append(imgs, p)
	}
	w := wipeFlags{method: methodAuto, verify: true, key: f.key, stationCert: r.stationCert, logURL: lg.srv.URL, logKey: lg.vkey,
		offlineSeed: offlineFull, hpa: engine.HPARestore, sector: 512, patterns: engine.PatternRandom,
		chunkMiB: engine.DefaultChunk >> 20, syncMiB: engine.DefaultSyncEvery >> 20, execute: true, autoVerify: true}
	m := newTUIModel(tuiDevices(nil, imgs, 512), &liveTUI{f: w, dir: out, parallel: 3}, false)
	// Move to the first image (live disks of the test machine are listed first, and are
	// protected or refused by the lab lock outside the VM).
	for m.devs[m.cursor].path != imgs[0] {
		press(t, m, "down")
	}
	press(t, m, "space", "down", "space", "down", "space", "enter")
	if m.scr != scrConfirm || len(m.order) != 3 {
		t.Fatalf("confirm screen with %d disks:\n%s", len(m.order), m.View())
	}
	for range 3 {
		d := m.devs[m.order[m.confIdx]]
		press(t, m, strings.Split(d.last4(), "")...)
		press(t, m, "enter")
	}
	if m.scr != scrPlan {
		t.Fatalf("screen %d:\n%s", m.scr, m.View())
	}
	mustView(t, m, "method overwrite — NIST SP 800-88 Clear", "full read-back")
	press(t, m, "enter")
	if m.scr != scrDone {
		t.Fatalf("screen %d:\n%s", m.scr, m.View())
	}
	if m.code != 0 {
		t.Fatalf("code %d:\n%s", m.code, m.View())
	}
	mustView(t, m, "erased and verified", "logged in the transparency log", "MANIFEST ")
	for _, p := range imgs {
		if b, _ := os.ReadFile(p); bytes.Contains(b, []byte("private")) {
			t.Fatalf("%s not wiped", p)
		}
	}
	mfs, _ := filepath.Glob(filepath.Join(out, "batch-*.manifest.json"))
	if len(mfs) != 1 {
		t.Fatalf("manifests %v", mfs)
	}
	res, err := certcheck.VerifyManifest(mfs[0], []string{out}, certcheck.Options{Root: r.pub, Revocations: r.crl, LogKey: lg.vkey, RequireLog: true})
	if err != nil || !res.Complete() || res.Certified() != 3 {
		t.Fatalf("manifest: %v %+v", err, res)
	}
}
