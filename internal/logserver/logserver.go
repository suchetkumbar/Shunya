// Package logserver is the HTTP face of Shunya's transparency log and public
// verifier ("shunya-verify serve").
//
//	GET  /checkpoint          the signed checkpoint (C2SP tlog-checkpoint)
//	GET  /tile/...            tiles and entry bundles (C2SP tlog-tiles), for auditors
//	GET  /log.vkey            the log's verifier key (convenience; pin it out of band)
//	GET  /revocations         the root's revocation list the server checks against (root-signed)
//	POST /add                 submit a certificate file → its inclusion proof
//	POST /seed                submit a signed seed request → checkpoint + inclusion proof
//	GET  /proof/{id}          inclusion proof of a logged certificate, current checkpoint
//	GET  /consistency?from=N  consistency proof from size N to the current checkpoint
//	GET  /cert/{id}           the logged certificate file with its current proof attached
//	GET  /c/{id}              the recycler page: verifies the certificate, shows the result
//	GET  /                    a form to look up a certificate ID
//
// Submissions are verified in full (root, revocation, form) before they are logged;
// a certificate already in the log is not added twice. Every request is rate-limited
// per client address, bodies are size-limited, and each request is logged as one JSON
// line (no bodies, no query strings).
package logserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"shunya/internal/cert"
	"shunya/internal/keys"
	"shunya/internal/logentry"
	"shunya/internal/note"
	"shunya/internal/tilestore"
)

const (
	maxSeedBody = 16 << 10
	maxCertBody = logentry.MaxEntry + 1
)

// Config is what a server needs.
type Config struct {
	Log    *tilestore.Log
	Dir    string // the log's directory (tiles are served from it)
	LogKey *note.Verifier
	Policy cert.Policy // root and revocations for submissions; LogKey is set by New
	// RevocationsFile is the signed revocation list as loaded, served as is so offline
	// verifiers can fetch the newest list (it verifies against the root on its own).
	RevocationsFile []byte
	Logger          *slog.Logger
	// Rate limits per client address: Rate tokens per second, bursts of Burst. A POST
	// costs PostCost tokens. Zero values take the defaults.
	Rate     float64
	Burst    float64
	PostCost float64
	Now      func() time.Time
}

// Server serves one log.
type Server struct {
	cfg     Config
	limiter *limiter
	page    *template.Template

	mu    sync.Mutex
	byID  map[string]uint64 // certificate ID → entry index
	seeds map[string]int    // station key | wipe | fingerprint → seed requests
}

// New indexes the log's certificates and seed requests.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil || cfg.LogKey == nil || cfg.Dir == "" {
		return nil, errors.New("logserver: log, its directory and its key are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rate == 0 {
		cfg.Rate = 5
	}
	if cfg.Burst == 0 {
		cfg.Burst = 20
	}
	if cfg.PostCost == 0 {
		cfg.PostCost = 5
	}
	cfg.Policy.LogKey = cfg.LogKey
	s := &Server{cfg: cfg, limiter: newLimiter(cfg.Rate, cfg.Burst, cfg.Now), byID: map[string]uint64{}, seeds: map[string]int{},
		page: template.Must(template.New("page").Parse(pageHTML))}
	var bad error
	cfg.Log.Entries(func(i uint64, e []byte) {
		if bad == nil {
			bad = s.index(i, e)
		}
	})
	return s, bad
}

// index records entry i (called with the log lock held or before serving).
func (s *Server) index(i uint64, e []byte) error {
	typ, payload, err := logentry.Split(e)
	if err != nil {
		return fmt.Errorf("logserver: entry %d: %v", i, err)
	}
	switch typ {
	case logentry.TypeCertificate:
		var env struct {
			Certificate json.RawMessage `json:"certificate"`
		}
		if err := json.Unmarshal(payload, &env); err != nil {
			return fmt.Errorf("logserver: entry %d: %v", i, err)
		}
		id := cert.ID(env.Certificate)
		if _, dup := s.byID[id]; !dup {
			s.byID[id] = i
		}
	case logentry.TypeSeedRequest:
		var q logentry.SeedRequest
		if err := json.Unmarshal(payload, &q); err != nil {
			return fmt.Errorf("logserver: entry %d: %v", i, err)
		}
		s.seeds[seedKey(q)]++
	}
	return nil
}

func seedKey(q logentry.SeedRequest) string {
	return q.StationKeyID + "|" + q.WipeID + "|" + q.Fingerprint
}

// Handler is the server's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /checkpoint", s.checkpoint)
	mux.HandleFunc("GET /tile/", s.tile)
	mux.HandleFunc("GET /log.vkey", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, s.cfg.LogKey.VerifierKey()+"\n")
	})
	mux.HandleFunc("GET /revocations", func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.RevocationsFile == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, max-age=0")
		w.Write(s.cfg.RevocationsFile)
	})
	mux.HandleFunc("POST /add", s.add)
	mux.HandleFunc("POST /seed", s.seed)
	mux.HandleFunc("GET /proof/{id}", s.proof)
	mux.HandleFunc("GET /consistency", s.consistency)
	mux.HandleFunc("GET /cert/{id}", s.certFile)
	mux.HandleFunc("GET /c/{id}", s.recycler)
	mux.HandleFunc("GET /{$}", s.index0)
	return s.middleware(mux)
}

// statusWriter records the status and size for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host // X-Forwarded-For is not trusted: there is no proxy in front
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.cfg.Now()
		sw := &statusWriter{ResponseWriter: w}
		h := sw.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
		cost := 1.0
		if r.Method == http.MethodPost {
			cost = s.cfg.PostCost
		}
		ip := clientIP(r)
		if !s.limiter.allow(ip, cost) {
			h.Set("Retry-After", "2")
			http.Error(sw, "rate limit exceeded", http.StatusTooManyRequests)
		} else {
			next.ServeHTTP(sw, r)
		}
		p := r.URL.Path
		if len(p) > 200 {
			p = p[:200]
		}
		s.cfg.Logger.Info("request", "method", r.Method, "path", p, "status", sw.status, "bytes", sw.bytes,
			"ms", s.cfg.Now().Sub(start).Milliseconds(), "client", ip)
	})
}

func (s *Server) checkpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, max-age=0")
	w.Write(s.cfg.Log.Checkpoint())
}

// tile serves tile/<L>/<N>[.p/<W>] and tile/entries/... files; nothing else.
func (s *Server) tile(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/")
	if path.Clean(rel) != rel || !validTilePath(rel) {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join(s.cfg.Dir, filepath.FromSlash(rel)))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(b)
}

func validTilePath(p string) bool {
	parts := strings.Split(p, "/")
	if len(parts) < 3 || parts[0] != "tile" {
		return false
	}
	if parts[1] != "entries" {
		if l, err := strconv.Atoi(parts[1]); err != nil || l < 0 || l > 63 || strconv.Itoa(l) != parts[1] {
			return false
		}
	}
	rest := parts[2:]
	// Optional ".p/<W>" suffix: the element before W ends in ".p".
	if n := len(rest); n >= 2 && strings.HasSuffix(rest[n-2], ".p") {
		w, err := strconv.Atoi(rest[n-1])
		if err != nil || w < 1 || w > 255 || strconv.Itoa(w) != rest[n-1] {
			return false
		}
		rest = append(append([]string{}, rest[:n-2]...), strings.TrimSuffix(rest[n-2], ".p"))
	}
	for i, e := range rest {
		d := e
		if i < len(rest)-1 {
			if !strings.HasPrefix(e, "x") {
				return false
			}
			d = e[1:]
		}
		if len(d) != 3 || strings.Trim(d, "0123456789") != "" {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func fail(w http.ResponseWriter, status int, f string, a ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(f, a...)})
}

func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			fail(w, http.StatusRequestEntityTooLarge, "body larger than %d bytes", max)
		} else {
			fail(w, http.StatusBadRequest, "reading body: %v", err)
		}
		return nil, false
	}
	return b, true
}

// AddResponse answers POST /add.
type AddResponse struct {
	ID        string             `json:"id"`
	Duplicate bool               `json:"duplicate"`
	Inclusion logentry.Inclusion `json:"inclusion"`
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	file, ok := readBody(w, r, maxCertBody)
	if !ok {
		return
	}
	res, err := cert.Verify(file, s.cfg.Policy)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "certificate refused: %v", err)
		return
	}
	entry, err := cert.LogEntry(file)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "certificate refused: %v", err)
		return
	}
	s.mu.Lock()
	i, dup := s.byID[res.ID]
	if !dup {
		if i, err = s.cfg.Log.Append(entry); err == nil {
			s.byID[res.ID] = i
		}
	}
	s.mu.Unlock()
	if err != nil {
		s.cfg.Logger.Error("append", "err", err.Error())
		fail(w, http.StatusInternalServerError, "the log could not store the entry")
		return
	}
	in, err := s.inclusion(i)
	if err != nil {
		fail(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, AddResponse{ID: res.ID, Duplicate: dup, Inclusion: in})
}

func (s *Server) inclusion(i uint64) (logentry.Inclusion, error) {
	p, cp, err := s.cfg.Log.Prove(i)
	if err != nil {
		return logentry.Inclusion{}, err
	}
	return logentry.NewInclusion(i, cp, p), nil
}

// SeedResponse answers POST /seed.
type SeedResponse struct {
	Inclusion logentry.Inclusion `json:"inclusion"`
	// Requests is how many seed requests this station has made for this wipe and
	// device, this one included. More than one is visible to every auditor.
	Requests int `json:"requests"`
}

func (s *Server) seed(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r, maxSeedBody)
	if !ok {
		return
	}
	var q logentry.SeedRequest
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&q); err != nil {
		fail(w, http.StatusBadRequest, "seed request: %v", err)
		return
	}
	if err := q.Verify(); err != nil {
		fail(w, http.StatusUnprocessableEntity, "seed request refused: %v", err)
		return
	}
	if err := s.stationOK(q); err != nil {
		fail(w, http.StatusUnprocessableEntity, "seed request refused: %v", err)
		return
	}
	entry, err := q.Entry()
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "seed request refused: %v", err)
		return
	}
	beacon, err := logentry.Beacon()
	if err != nil {
		fail(w, http.StatusInternalServerError, "randomness: %v", err)
		return
	}
	s.mu.Lock()
	i, err := s.cfg.Log.Append(entry, beacon)
	n := 0
	if err == nil {
		s.seeds[seedKey(q)]++
		n = s.seeds[seedKey(q)]
	}
	s.mu.Unlock()
	if err != nil {
		s.cfg.Logger.Error("append", "err", err.Error())
		fail(w, http.StatusInternalServerError, "the log could not store the request")
		return
	}
	in, err := s.inclusion(i)
	if err != nil {
		fail(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, SeedResponse{Inclusion: in, Requests: n})
}

// stationOK: seed requests come only from root-certified, unrevoked stations.
func (s *Server) stationOK(q logentry.SeedRequest) error {
	sc := q.StationCertificate
	if sc == nil {
		return errors.New("no station certificate (development keys cannot request log seeds)")
	}
	if err := sc.Verify(s.cfg.Policy.Root); err != nil {
		return err
	}
	now := s.cfg.Now()
	if !sc.ValidAt(now) {
		return fmt.Errorf("station certificate not valid at %s", keys.FormatTime(now))
	}
	if rl := s.cfg.Policy.Revocations; rl != nil {
		return rl.Check(q.StationKeyID, now)
	}
	return nil
}

func validID(id string) bool {
	return len(id) == 64 && strings.Trim(id, "0123456789abcdef") == ""
}

func (s *Server) lookup(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	id := r.PathValue("id")
	if !validID(id) {
		fail(w, http.StatusBadRequest, "a certificate ID is 64 lowercase hex digits")
		return 0, false
	}
	s.mu.Lock()
	i, ok := s.byID[id]
	s.mu.Unlock()
	if !ok {
		fail(w, http.StatusNotFound, "certificate %s is not in this log", id)
	}
	return i, ok
}

func (s *Server) proof(w http.ResponseWriter, r *http.Request) {
	i, ok := s.lookup(w, r)
	if !ok {
		return
	}
	in, err := s.inclusion(i)
	if err != nil {
		fail(w, http.StatusInternalServerError, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, in)
}

// ConsistencyResponse answers GET /consistency.
type ConsistencyResponse struct {
	From       uint64   `json:"from"`
	Checkpoint string   `json:"checkpoint"`
	Proof      []string `json:"proof"`
}

func (s *Server) consistency(w http.ResponseWriter, r *http.Request) {
	from, err := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
	if err != nil || from == 0 {
		fail(w, http.StatusBadRequest, "from: a tree size of at least 1")
		return
	}
	p, cp, err := s.cfg.Log.Consistency(from)
	if err != nil {
		fail(w, http.StatusBadRequest, "no consistency proof from size %d: %v", from, err)
		return
	}
	in := logentry.NewInclusion(0, cp, p)
	writeJSON(w, http.StatusOK, ConsistencyResponse{From: from, Checkpoint: in.Checkpoint, Proof: in.Proof})
}

// logged is a certificate from the log with its current proof attached.
func (s *Server) logged(i uint64) ([]byte, error) {
	e, ok := s.cfg.Log.Entry(i)
	if !ok {
		return nil, errors.New("entry missing")
	}
	file, err := cert.FromEntry(e)
	if err != nil {
		return nil, err
	}
	in, err := s.inclusion(i)
	if err != nil {
		return nil, err
	}
	return cert.WithLog(file, in)
}

func (s *Server) certFile(w http.ResponseWriter, r *http.Request) {
	i, ok := s.lookup(w, r)
	if !ok {
		return
	}
	file, err := s.logged(i)
	if err != nil {
		fail(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("id")+`.cert.json"`)
	w.Write(file)
}

// pageData is what the recycler page shows.
type pageData struct {
	ID, Verdict, Reason string
	Valid, Lookup       bool
	Rows                [][2]string
	Warnings            []string
}

func (s *Server) render(w http.ResponseWriter, status int, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := s.page.Execute(w, d); err != nil {
		s.cfg.Logger.Error("template", "err", err.Error())
	}
}

func (s *Server) index0(w http.ResponseWriter, r *http.Request) {
	if id := r.URL.Query().Get("id"); id != "" {
		id = strings.ToLower(strings.TrimSpace(id))
		if validID(id) {
			http.Redirect(w, r, "/c/"+id, http.StatusSeeOther)
			return
		}
		s.render(w, http.StatusBadRequest, pageData{Lookup: true, Verdict: "Not a certificate ID", Reason: "A certificate ID is 64 hexadecimal digits, printed under the QR code."})
		return
	}
	s.render(w, http.StatusOK, pageData{Lookup: true})
}

// recycler verifies the logged certificate exactly as shunya-verify would, with the
// server's root, revocation list and log key, and shows the verdict.
func (s *Server) recycler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(id) {
		s.render(w, http.StatusBadRequest, pageData{Lookup: true, Verdict: "Not a certificate ID", Reason: "A certificate ID is 64 lowercase hexadecimal digits."})
		return
	}
	s.mu.Lock()
	i, ok := s.byID[id]
	s.mu.Unlock()
	if !ok {
		s.render(w, http.StatusNotFound, pageData{ID: id, Verdict: "NOT FOUND", Reason: "No certificate with this ID is in this log. Do not accept the device as wiped on the strength of this certificate."})
		return
	}
	file, err := s.logged(i)
	var res *cert.Result
	if err == nil {
		p := s.cfg.Policy
		p.RequireLog = true
		res, err = cert.Verify(file, p)
	}
	if err != nil {
		s.render(w, http.StatusOK, pageData{ID: id, Verdict: "INVALID", Reason: err.Error()})
		return
	}
	c := res.Certificate
	modes := []string{}
	for _, v := range c.Verification {
		m := v.Mode
		if v.Mode == "sampled" {
			m += fmt.Sprintf(" (%d sectors, seed: %s)", v.Samples, v.SeedSource)
		}
		modes = append(modes, m)
	}
	rows := [][2]string{
		{"Device", fmt.Sprintf("%s, serial %s", c.Device.Model, c.Device.Serial)},
		{"Size", fmt.Sprintf("%d bytes (%s)", c.Device.SizeBytes, c.Device.Media)},
		{"Method", c.Erasure.Method},
		{"NIST SP 800-88 level", strings.ToUpper(c.Erasure.NISTLevel)},
		{"Finished", c.Erasure.Finished},
		{"Verified", strings.Join(modes, "; ")},
		{"Interruptions", strconv.Itoa(len(c.Interruptions))},
		{"Station", fmt.Sprintf("%s (%s)", c.Station.Name, c.Station.KeyID)},
		{"Issued", c.Issued},
		{"Log entry", fmt.Sprintf("%d of %d, log %s", res.Logged.Index, res.Logged.Checkpoint.Size, res.Logged.Checkpoint.Origin)},
	}
	if c.Device.Virtual {
		rows[1][1] += ", virtual disk"
	}
	s.render(w, http.StatusOK, pageData{ID: id, Valid: true, Verdict: "VALID", Rows: rows, Warnings: res.Warnings})
}

const pageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shunya certificate check</title>
<style>
body{font:17px/1.5 system-ui,sans-serif;margin:0;background:#f6f7f8;color:#16181b}
main{max-width:46rem;margin:0 auto;padding:1.5rem 1rem}
h1{font-size:1.2rem;margin:0 0 1rem}
.v{font-size:2.2rem;font-weight:700;padding:1rem 1.2rem;border-radius:.5rem;margin:1rem 0}
.ok{background:#dff3e4;color:#11622b}.bad{background:#fbe3e1;color:#8c1d13}
table{border-collapse:collapse;width:100%;background:#fff;border-radius:.5rem}
td{padding:.5rem .75rem;border-top:1px solid #e3e6e9;vertical-align:top;overflow-wrap:anywhere}
td:first-child{color:#555;width:13rem}
code{font-size:.85rem;overflow-wrap:anywhere}
.w{background:#fff6d6;padding:.5rem .75rem;border-radius:.4rem;margin:.5rem 0}
input{font:inherit;width:100%;box-sizing:border-box;padding:.5rem;margin:.5rem 0}
button{font:inherit;padding:.5rem 1.2rem}
</style></head><body><main>
<h1>Shunya data-erasure certificate check</h1>
{{if .Verdict}}<div class="v {{if .Valid}}ok{{else}}bad{{end}}">{{.Verdict}}</div>{{end}}
{{if .ID}}<p>Certificate <code>{{.ID}}</code></p>{{end}}
{{if .Reason}}<p>{{.Reason}}</p>{{end}}
{{if .Rows}}<table>{{range .Rows}}<tr><td>{{index . 0}}</td><td>{{index . 1}}</td></tr>{{end}}</table>{{end}}
{{range .Warnings}}<div class="w">Note: {{.}}</div>{{end}}
{{if .Valid}}<p>The certificate's signature, its station's certification by the organisation's root, its revocation status and its place in this transparency log were all checked by this server. To check without trusting this server, download the <a href="/cert/{{.ID}}">certificate file</a> and run <code>shunya-verify</code>.</p>{{end}}
{{if .Lookup}}<form action="/" method="get"><label>Certificate ID (under the QR code)<input name="id" autocomplete="off" spellcheck="false"></label><button>Check</button></form>{{end}}
</main></body></html>
`

// limiter is a per-client token bucket.
type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	now     func() time.Time
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate, burst float64, now func() time.Time) *limiter {
	return &limiter{rate: rate, burst: burst, now: now, buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string, cost float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= 10000 { // bound memory: forget clients whose buckets are full
			for k, o := range l.buckets {
				if o.tokens+now.Sub(o.last).Seconds()*l.rate >= l.burst {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= 10000 { // still full: start over rather than grow
				l.buckets = map[string]*bucket{}
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}
