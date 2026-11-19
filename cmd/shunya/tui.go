package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"shunya/internal/backend"
	"shunya/internal/device"
	"shunya/internal/engine"
	"shunya/internal/manifest"
)

// The TUI is a state machine over five screens. Every wipe it starts goes through
// runBatch, the same code as "shunya wipe" and "shunya fleet"; the TUI adds only the
// picker, the typed confirmation and the display.
type screen int

const (
	scrPick screen = iota
	scrPlan
	scrConfirm
	scrRun
	scrDone
)

// tuiDevice is one row of the picker.
type tuiDevice struct {
	path, model, serial, media, size, fingerprint string
	isImage                                       bool
	method                                        string // set from the plan when the run starts
	why                                           string // non-empty: not selectable (protected, in use, lab lock …)
}

func (d tuiDevice) label() string {
	if d.isImage {
		return "image " + d.path
	}
	return d.path
}

// last4 is what the operator must type: the serial's last 4 characters (all of a
// shorter one), as the release build's backend checks it.
func (d tuiDevice) last4() string {
	s := strings.TrimSpace(d.serial)
	if len(s) > 4 {
		s = s[len(s)-4:]
	}
	return s
}

// planInfo is a device's dry-run plan.
type planInfo struct {
	method, level, estimate, verify string
	notes                           []string
	err                             string // the plan was refused (with explanations)
	explain                         []Explanation
}

// tuiBackend is what the TUI needs from the rest of Shunya (faked in tests).
type tuiBackend interface {
	// Plan is a dry run on d after the operator typed confirm, the end of its serial
	// (release builds need it before they may send even a read-only NVMe Identify).
	Plan(d tuiDevice, confirm string) planInfo
	// Start runs the batch; the channel delivers devMsg values, then one doneMsg, then
	// closes. Cancel stops the running wipes (resumable from their journals).
	Start(devs []tuiDevice, confirms []string) <-chan tea.Msg
	Cancel()
}

type planMsg struct {
	idx  int
	plan planInfo
}
type devMsg struct{ ev deviceEvent }
type doneMsg struct {
	results  []itemResult
	manifest string // the manifest output (path, log status)
	err      string
}

// runState is one device's live state on the progress screen.
type runState struct {
	phase    string
	last     string
	fraction float64
	rate     float64
	eta      time.Duration
	done     *itemResult
}

type tuiModel struct {
	simple   bool
	be       tuiBackend
	scr      screen
	devs     []tuiDevice
	cursor   int
	selected map[int]bool
	order    []int // selected devices, in list order
	plans    map[int]planInfo
	confIdx  int
	typed    string
	confirms []string
	confErr  string
	events   <-chan tea.Msg
	runs     []*runState
	results  []itemResult
	manifest string
	runErr   string
	stopAsk  bool
	width    int
	quitting bool
	code     int
}

func newTUIModel(devs []tuiDevice, be tuiBackend, simple bool) *tuiModel {
	m := &tuiModel{simple: simple, be: be, devs: devs, selected: map[int]bool{}, plans: map[int]planInfo{}, width: 100}
	for i, d := range devs { // start on the first selectable device
		if d.why == "" {
			m.cursor = i
			break
		}
	}
	return m
}

func (m *tuiModel) Init() tea.Cmd { return nil }

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case planMsg:
		m.plans[msg.idx] = msg.plan
		return m, nil
	case devMsg:
		m.apply(msg.ev)
		return m, m.wait()
	case doneMsg:
		m.results, m.manifest, m.runErr = msg.results, msg.manifest, msg.err
		m.scr = scrDone
		m.code = 0
		for _, r := range m.results {
			if r.outcome != manifest.OutcomeCertified && r.outcome != manifest.OutcomeNotCertified {
				m.code = 1
			}
		}
		if m.runErr != "" {
			m.code = 1
		}
		return m, nil
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *tuiModel) wait() tea.Cmd {
	ch := m.events
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return nil
		}
		return msg
	}
}

func (m *tuiModel) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	if s == "ctrl+c" && m.scr != scrRun {
		m.quitting = true
		return m, tea.Quit
	}
	switch m.scr {
	case scrPick:
		switch s {
		case "q", "esc":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			m.move(-1)
		case "down", "j":
			m.move(1)
		case " ", "space":
			if !m.simple && m.devs[m.cursor].why == "" {
				m.selected[m.cursor] = !m.selected[m.cursor]
			}
		case "enter":
			if m.simple || len(m.selected) == 0 {
				if m.devs[m.cursor].why != "" {
					return m, nil
				}
				m.selected = map[int]bool{m.cursor: true}
			}
			m.order = m.order[:0]
			for i := range m.devs {
				if m.selected[i] {
					m.order = append(m.order, i)
				}
			}
			if len(m.order) == 0 {
				return m, nil
			}
			// Confirm first, then plan: the plan is made with the confirmations (so a
			// release build may identify the drive), and it is the plan that runs.
			m.scr, m.confIdx, m.typed, m.confErr, m.confirms = scrConfirm, 0, "", "", nil
			m.plans = map[int]planInfo{}
		}
	case scrPlan:
		switch s {
		case "esc", "b":
			m.scr = scrPick
		case "q":
			m.quitting = true
			return m, tea.Quit
		case "enter":
			if !m.plansReady() {
				return m, nil
			}
			return m, m.start()
		}
	case scrConfirm:
		switch {
		case s == "esc":
			m.scr = scrPick
		case s == "backspace":
			if m.typed != "" {
				m.typed = m.typed[:len(m.typed)-1]
			}
		case s == "enter":
			d := m.devs[m.order[m.confIdx]]
			if !strings.EqualFold(strings.TrimSpace(m.typed), d.last4()) {
				m.confErr = fmt.Sprintf("%q is not the end of the serial number. Nothing was wiped. Look again and retype.", m.typed)
				m.typed = ""
				return m, nil
			}
			m.confirms = append(m.confirms, m.typed)
			m.typed, m.confErr = "", ""
			m.confIdx++
			if m.confIdx == len(m.order) {
				m.scr = scrPlan
				cmds := make([]tea.Cmd, len(m.order))
				for j, i := range m.order {
					d, c := m.devs[i], m.confirms[j]
					cmds[j] = func() tea.Msg { return planMsg{i, m.be.Plan(d, c)} }
				}
				return m, tea.Batch(cmds...)
			}
		case k.Type == tea.KeyRunes:
			if len(m.typed) < 16 {
				m.typed += string(k.Runes)
			}
		}
	case scrRun:
		if s == "ctrl+c" || s == "x" {
			if m.stopAsk {
				m.be.Cancel()
				return m, nil
			}
			m.stopAsk = true
			return m, nil
		}
		if s == "esc" || s == "n" {
			m.stopAsk = false
		}
	case scrDone:
		switch s {
		case "q", "enter", "esc":
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *tuiModel) move(d int) {
	n := len(m.devs)
	if n == 0 {
		return
	}
	m.cursor = (m.cursor + d + n) % n
}

// plansReady: every selected device has a plan and none was refused.
func (m *tuiModel) plansReady() bool {
	for _, i := range m.order {
		p, ok := m.plans[i]
		if !ok || p.err != "" {
			return false
		}
	}
	return true
}

func (m *tuiModel) start() tea.Cmd {
	devs := make([]tuiDevice, len(m.order))
	m.runs = make([]*runState, len(m.order))
	for j, i := range m.order {
		devs[j] = m.devs[i]
		devs[j].method = m.plans[i].method
		m.runs[j] = &runState{phase: "waiting"}
	}
	m.scr = scrRun
	m.events = m.be.Start(devs, m.confirms)
	return m.wait()
}

// apply folds one device event into the progress screen.
func (m *tuiModel) apply(e deviceEvent) {
	if e.idx < 0 || e.idx >= len(m.runs) {
		return
	}
	r := m.runs[e.idx]
	switch {
	case e.done != nil:
		r.done = e.done
		r.phase = e.done.outcome
		if e.done.outcome == manifest.OutcomeCertified || e.done.outcome == manifest.OutcomeNotCertified {
			r.fraction = 1
		}
	case e.progress != nil:
		p := e.progress
		r.fraction = float64(p.Done) / float64(max(p.Total, 1))
		r.rate, r.eta, r.phase = p.BytesPerSec, p.ETA, "wiping"
	case e.line != "":
		r.last = e.line
		if ph, f, ok := phaseOf(e.line); ok {
			r.phase = ph
			if f >= 0 {
				r.fraction = f
			}
		}
	}
}

// phaseOf reads the wipe's progress from its output lines (the same lines "shunya
// wipe" prints). f is a progress fraction, or -1 when the line carries none.
func phaseOf(line string) (phase string, f float64, ok bool) {
	switch {
	case strings.HasPrefix(line, "method: auto"):
		return "planning", -1, true
	case strings.Contains(line, " started; journal "):
		return "wiping", 0, true
	case strings.HasPrefix(line, "planted ") && strings.Contains(line, "markers"):
		return "erasing (drive firmware)", -1, true
	case strings.Contains(line, "sanitize in progress:"):
		var pct float64
		if _, err := fmt.Sscanf(line[strings.Index(line, ":")+1:], "%f%%", &pct); err == nil {
			return "erasing (drive firmware)", pct / 100, true
		}
		return "erasing (drive firmware)", -1, true
	case strings.HasPrefix(line, "DONE:"):
		return "verifying", 1, true
	case strings.HasPrefix(line, "VERIFIED"):
		return "certifying", 1, true
	case strings.HasPrefix(line, "VERIFY FAILED"):
		return "verify failed", -1, true
	case strings.HasPrefix(line, "CERTIFICATE "):
		return "certificate issued", 1, true
	case strings.HasPrefix(line, "LOGGED "):
		return "logged", 1, true
	case strings.HasPrefix(line, "FAILED") || strings.HasPrefix(line, "INTERRUPTED"):
		return strings.ToLower(strings.TrimSuffix(strings.Fields(line)[0], ":")), -1, true
	}
	return "", 0, false
}

// ---- view ----

var (
	stTitle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	stDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	stWarn  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	stGood  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	stSel   = lipgloss.NewStyle().Bold(true).Reverse(true)
	stBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
)

func (m *tuiModel) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder
	title := "SHUNYA — verifiable disk wiping"
	if m.simple {
		title = "SHUNYA — one-click wipe"
	}
	b.WriteString(stTitle.Render(title) + "\n\n")
	switch m.scr {
	case scrPick:
		m.viewPick(&b)
	case scrPlan:
		m.viewPlan(&b)
	case scrConfirm:
		m.viewConfirm(&b)
	case scrRun:
		m.viewRun(&b)
	case scrDone:
		m.viewDone(&b)
	}
	return b.String()
}

func (m *tuiModel) viewPick(b *strings.Builder) {
	if m.simple {
		b.WriteString("Which disk do you want to erase? Use ↑/↓ and press Enter.\n\n")
	} else {
		b.WriteString("Choose the disks to wipe: ↑/↓ move, Space select, Enter continue, q quit.\n\n")
	}
	if len(m.devs) == 0 {
		b.WriteString(stWarn.Render("No disks found.") + "\n")
	}
	for i, d := range m.devs {
		mark := "   "
		if !m.simple {
			mark = "[ ]"
			if m.selected[i] {
				mark = "[x]"
			}
		}
		line := fmt.Sprintf("%s %-22s %-24s serial %-20s %-8s %8s", mark, d.label(), trunc(d.model, 24), trunc(orDash(d.serial), 20), d.media, d.size)
		if d.why != "" {
			// why carries its own status (PROTECTED: …, IN-USE: …) from the guard.
			line = stDim.Render(fmt.Sprintf("    %-22s %-24s %s", d.label(), trunc(d.model, 24), trunc(d.why, 72)))
		}
		if i == m.cursor {
			line = stSel.Render(line)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString("\n" + stDim.Render("Protected disks (this computer's system disk, mounted or in-use disks) cannot be chosen.") + "\n")
}

func (m *tuiModel) viewPlan(b *strings.Builder) {
	if m.simple {
		d, p := m.devs[m.order[0]], m.plans[m.order[0]]
		b.WriteString(bigText("READY") + "\n\n")
		fmt.Fprintf(b, "Disk:     %s  %s  (serial %s, %s)\n", d.label(), d.model, orDash(d.serial), d.size)
		if p.method == "" && p.err == "" {
			b.WriteString("\nWorking out the safest, strongest way to erase it…\n")
			return
		}
		if p.err != "" {
			m.viewRefused(b, p)
			return
		}
		fmt.Fprintf(b, "How:      %s (%s, NIST SP 800-88 %s)\n", plainMethod(p.method), p.method, p.level)
		fmt.Fprintf(b, "Check:    %s\nTime:     about %s\n\n", p.verify, p.estimate)
		b.WriteString(stWarn.Render("Everything on this disk will be destroyed. This cannot be undone.") + "\n")
		b.WriteString("Press Enter to start, or Esc to choose another disk.\n")
		return
	}
	b.WriteString("PLAN — nothing has been written yet. Enter: start wiping, Esc: back to the disk list.\n\n")
	for _, i := range m.order {
		d := m.devs[i]
		p, ok := m.plans[i]
		var body strings.Builder
		fmt.Fprintf(&body, "%s  %s  serial %s  %s, %s\n", d.label(), d.model, orDash(d.serial), d.media, d.size)
		switch {
		case !ok:
			body.WriteString("planning…")
		case p.err != "":
			m.viewRefused(&body, p)
		default:
			fmt.Fprintf(&body, "method %s — NIST SP 800-88 %s — about %s\nverification: %s", p.method, p.level, p.estimate, p.verify)
			for _, n := range p.notes {
				body.WriteString("\n  · " + trunc(n, max(m.width-10, 40)))
			}
		}
		b.WriteString(stBox.Render(body.String()) + "\n")
	}
	if !m.plansReady() {
		b.WriteString(stDim.Render("Waiting for every plan; a refused disk must be deselected (Esc) before continuing.") + "\n")
	}
}

func (m *tuiModel) viewRefused(b *strings.Builder, p planInfo) {
	b.WriteString(stWarn.Render("CANNOT WIPE THIS DISK") + "\n" + trunc(p.err, 300) + "\n")
	for _, e := range p.explain {
		fmt.Fprintf(b, "\nWhat happened: %s\nWhy:           %s\nWhat to do:    %s\n", e.What, e.Why, e.Do)
	}
}

func (m *tuiModel) viewConfirm(b *strings.Builder) {
	d := m.devs[m.order[m.confIdx]]
	if !m.simple {
		fmt.Fprintf(b, "CONFIRM %d of %d\n\n", m.confIdx+1, len(m.order))
	}
	fmt.Fprintf(b, "Disk: %s  %s\nSerial number: %s\n\n", d.label(), d.model, stTitle.Render(orDash(d.serial)))
	b.WriteString(stWarn.Render("All data on this disk will be destroyed.") + "\n\n")
	fmt.Fprintf(b, "To confirm, type the LAST %d CHARACTERS of the serial number, then Enter:\n\n    > %s_\n", len(d.last4()), m.typed)
	if m.confErr != "" {
		b.WriteString("\n" + stWarn.Render(m.confErr) + "\n")
	}
	b.WriteString("\n" + stDim.Render("Esc: back to the disk list. The plan comes next; nothing starts until you press Enter there.") + "\n")
}

func (m *tuiModel) viewRun(b *strings.Builder) {
	if m.simple && len(m.runs) == 1 {
		r := m.runs[0]
		word := fmt.Sprintf("WIPING %d%%", int(100*r.fraction))
		switch r.phase {
		case "verifying", "certifying":
			word = "CHECKING"
		case "certificate issued", "logged":
			word = "DONE"
		}
		b.WriteString(bigText(word) + "\n\n")
		fmt.Fprintf(b, "%s\n%s\n", bar(r.fraction, min(max(m.width-8, 20), 60)), r.last)
		b.WriteString("\nPlease do not unplug the disk or turn the computer off.\n")
	} else {
		fmt.Fprintf(b, "WIPING %d disk(s)\n\n", len(m.runs))
		for j, r := range m.runs {
			d := m.devs[m.order[j]]
			info := ""
			if r.rate > 0 && r.fraction < 1 {
				info = fmt.Sprintf("%.0f MB/s ETA %s", r.rate/1e6, r.eta.Round(time.Second))
			}
			fmt.Fprintf(b, "%-22s %s %3d%%  %-20s %s\n", trunc(d.label(), 22), bar(r.fraction, 30), int(100*r.fraction), trunc(r.phase, 20), info)
			fmt.Fprintf(b, "%-22s %s\n", "", stDim.Render(trunc(r.last, max(m.width-24, 40))))
		}
	}
	if m.stopAsk {
		b.WriteString("\n" + stWarn.Render("Stop the wipes? Press Ctrl+C again to stop (they can be resumed from their journals), Esc to continue.") + "\n")
	} else {
		b.WriteString("\n" + stDim.Render("Ctrl+C: stop") + "\n")
	}
}

func (m *tuiModel) viewDone(b *strings.Builder) {
	ok := m.code == 0
	if m.simple && len(m.results) == 1 {
		if ok {
			b.WriteString(stGood.Render(bigText("DONE")) + "\n\n")
		} else {
			b.WriteString(stWarn.Render(bigText("FAILED")) + "\n\n")
		}
	} else {
		fmt.Fprintf(b, "RESULT — %d disk(s)\n\n", len(m.results))
	}
	for _, r := range m.results {
		name := r.target.label()
		switch r.outcome {
		case manifest.OutcomeCertified:
			fmt.Fprintf(b, "%s %s: erased and verified.\n  certificate %s\n  %s\n  %s\n", stGood.Render("✔"), name, r.res.CertID, r.res.CertJSON, r.res.CertPDF)
			if r.res.Logged {
				fmt.Fprintf(b, "  logged in the transparency log as entry %d; anyone can check it at %s\n", r.res.LogIndex, r.res.QR)
			} else if r.res.QR != "" {
				fmt.Fprintf(b, "  verify at %s\n", r.res.QR)
			}
		case manifest.OutcomeNotCertified:
			fmt.Fprintf(b, "%s %s: erased, but %s.\n", stWarn.Render("!"), name, r.err)
		default:
			fmt.Fprintf(b, "%s %s: %s — %s\n", stWarn.Render("✘"), name, strings.ToUpper(r.outcome), r.err)
			for _, e := range r.explain {
				fmt.Fprintf(b, "  What happened: %s\n  Why:           %s\n  What to do:    %s\n", e.What, e.Why, e.Do)
			}
		}
		if r.journal != "" {
			fmt.Fprintf(b, "  journal %s\n", r.journal)
		}
	}
	if m.manifest != "" {
		b.WriteString("\n" + m.manifest)
	}
	if m.runErr != "" {
		b.WriteString("\n" + stWarn.Render(m.runErr) + "\n")
	}
	b.WriteString("\nPress Enter to exit.\n")
}

func plainMethod(m string) string {
	switch {
	case m == engine.MethodOverwrite:
		return "overwrite every sector with random data"
	case strings.Contains(m, "crypto"):
		return "the drive destroys its encryption key (crypto erase)"
	case strings.Contains(m, "block"):
		return "the drive erases all its flash blocks (block erase)"
	case strings.Contains(m, "format"):
		return "the drive formats itself with secure erase"
	case strings.Contains(m, "security"):
		return "the drive's built-in Security Erase"
	}
	return "the drive's own erase command"
}

func bar(f float64, w int) string {
	f = min(max(f, 0), 1)
	n := int(f * float64(w))
	return "[" + strings.Repeat("█", n) + strings.Repeat("░", w-n) + "]"
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:max(n-1, 0)]) + "…"
}

// ---- the real backend ----

type liveTUI struct {
	f        wipeFlags
	dir      string
	parallel int
	cancel   context.CancelFunc
}

func (l *liveTUI) Plan(d tuiDevice, confirm string) planInfo {
	g := l.f
	g.execute = false
	if !d.isImage {
		g.confirm = confirm
	}
	var res jobResult
	g.result = &res
	var out, errb bytes.Buffer
	dev := d.path
	if d.isImage {
		g.image, dev = d.path, ""
	}
	code := freshWipe(g, dev, &out, &errb)
	text := out.String() + errb.String()
	if code != 0 || res.Plan == nil {
		msg := strings.TrimSpace(errb.String())
		if i := strings.Index(out.String(), "PRECONDITIONS NOT MET"); i >= 0 {
			msg = strings.TrimSpace(out.String()[i:])
		}
		if msg == "" {
			msg = fmt.Sprintf("planning failed (exit %d)", code)
		}
		return planInfo{err: strings.TrimPrefix(msg, "shunya: "), explain: Explain(text)}
	}
	p := *res.Plan
	v := "full read-back of every sector"
	switch {
	case g.sample > 0:
		v = fmt.Sprintf("%d sectors at positions from the transparency log", g.sample)
	case p.VerifyPattern == "" || strings.Contains(text, "verification: the marker check"):
		v = "marker check (planted markers must not survive the erase)"
	}
	return planInfo{method: p.Method, level: levelName(p.Level), estimate: estimate(p).String(), verify: v, notes: p.Notes}
}

func (l *liveTUI) Start(devs []tuiDevice, confirms []string) <-chan tea.Msg {
	ch := make(chan tea.Msg, 64)
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	var paths, images []string
	for _, d := range devs {
		if d.isImage {
			images = append(images, d.path)
		} else {
			paths = append(paths, d.path)
		}
	}
	targets := inspectTargets(paths, images, l.f.sector)
	// inspectTargets lists devices first, then images: put the confirmations in the
	// same order.
	conf, method := map[string]string{}, map[string]string{}
	for i, d := range devs {
		conf[d.path], method[d.path] = confirms[i], d.method
	}
	byPath := map[string]int{}
	for i, d := range devs {
		byPath[d.path] = i
	}
	order := make([]int, len(targets))
	for j, t := range targets {
		targets[j].confirm, targets[j].method = conf[t.path], method[t.path]
		order[j] = byPath[t.path]
	}
	go func() {
		defer close(ch)
		results := runBatch(ctx, l.f, targets, l.dir, l.parallel, func(e deviceEvent) {
			e.idx = order[e.idx]
			ch <- devMsg{e}
		})
		var mo bytes.Buffer
		errText := ""
		if _, err := writeManifest(l.f, results, l.dir, &mo); err != nil {
			errText = "manifest: " + err.Error()
		}
		sorted := make([]itemResult, len(results))
		for j, r := range results {
			sorted[order[j]] = r
		}
		ch <- doneMsg{results: sorted, manifest: mo.String(), err: errText}
	}()
	return ch
}

func (l *liveTUI) Cancel() {
	if l.cancel != nil {
		l.cancel()
	}
}

// tuiDevices lists the live system's disks (with the guard's verdict, read-only) and
// the given image files. If only is not empty, just the disks it names are listed.
func tuiDevices(only, images []string, sector int) []tuiDevice {
	var out []tuiDevice
	want := map[string]bool{}
	for _, p := range only {
		want["/dev/"+strings.TrimPrefix(p, "/dev/")] = true
	}
	if env, err := backend.LiveEnv(); err == nil {
		if rep, err := env.Report(); err == nil {
			for _, d := range rep.Devices {
				if d.Media.Type == device.MediaLogical || len(want) > 0 && !want[d.Path] {
					continue
				}
				delete(want, d.Path)
				td := tuiDevice{path: d.Path, model: d.Model, serial: d.Serial, media: string(d.Media.Type), size: human(d.SizeBytes), fingerprint: d.Fingerprint.Value}
				if v, err := backend.Check(env, d.Path); err != nil {
					td.why = err.Error()
				} else if !v.Allowed {
					td.why = strings.Join(v.Reasons, "; ")
				}
				out = append(out, td)
			}
		}
	}
	for p := range want {
		out = append(out, tuiDevice{path: p, why: "no such block device"})
	}
	for _, t := range inspectTargets(nil, images, sector) {
		td := tuiDevice{path: t.path, isImage: true, media: "image", model: "image file"}
		if t.spec != nil {
			td.serial, td.size, td.fingerprint = t.spec.id.Serial, human(uint64(t.spec.size)), t.spec.id.Fingerprint
		} else {
			td.why = firstLine(t.refusal)
		}
		out = append(out, td)
	}
	return out
}

const tuiUsage = `usage: shunya tui [--simple] --journal-dir DIR --key FILE [--station-cert FILE] [flags] [DEVICE...]

Full-screen wiping: pick disks, review the plan, confirm each by typing the end of its
serial number, watch progress, get the certificates. Several disks run in parallel and
get a signed batch manifest, exactly as in "shunya fleet".

--simple is the one-click mode: one disk, the recommended method, large status text.
DEVICE... limits the list to those disks; --image FILE adds image files.
`

func cmdTUI(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("tui", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.Usage = func() { fmt.Fprint(stderr, tuiUsage); fl.PrintDefaults() }
	var f wipeFlags
	var o fleetOptions
	batchFlags(fl, &f, &o)
	simple := fl.Bool("simple", false, "one-click mode: one disk, the recommended method, large status text")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	f.patterns, f.chunkMiB, f.syncMiB, f.offlineSeed = engine.PatternRandom, engine.DefaultChunk>>20, engine.DefaultSyncEvery>>20, orDefault(f.offlineSeed, offlineFull)
	if f.sample > 0 {
		f.verify = false
	}
	f.autoVerify = true
	f.execute = true
	if err := checkBatch(f, o, max(len(o.images), 1), false); err != nil {
		fmt.Fprintln(stderr, "shunya: tui:", err)
		return 2
	}
	if *simple {
		f.method = methodAuto
	}
	be := &liveTUI{f: f, dir: o.dir, parallel: o.parallel}
	m := newTUIModel(tuiDevices(fl.Args(), o.images, f.sector), be, *simple)
	opts := []tea.ProgramOption{tea.WithAltScreen()}
	if stdout != os.Stdout {
		opts = append(opts, tea.WithOutput(stdout))
	}
	if _, err := tea.NewProgram(m, opts...).Run(); err != nil {
		fmt.Fprintln(stderr, "shunya: tui:", err)
		return 1
	}
	// Leave a plain record in the terminal after the full-screen view closes.
	if len(m.results) > 0 {
		m.quitting = false
		var b strings.Builder
		m.viewDone(&b)
		fmt.Fprint(stdout, b.String())
	}
	return m.code
}
