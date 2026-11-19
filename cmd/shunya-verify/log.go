package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"shunya/internal/audit"
	"shunya/internal/cert"
	"shunya/internal/certcheck"
	"shunya/internal/keys"
	"shunya/internal/logclient"
	"shunya/internal/logserver"
	"shunya/internal/note"
	"shunya/internal/tilestore"
)

// cmdLogKey makes the log's signing key (DIR/log.key, 0600, never overwritten) and
// its verifier key (DIR/log.vkey, for everyone who checks the log).
func cmdLogKey(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("log-key", flag.ContinueOnError)
	fl.SetOutput(stderr)
	origin := fl.String("origin", "", "the log's name, e.g. its URL without the scheme (example.org/shunya-log)")
	out := fl.String("out", "", "directory for log.key and log.vkey")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *origin == "" || *out == "" || fl.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: shunya-verify log-key --origin NAME --out DIR")
		return 2
	}
	if !note.ValidName(*origin) {
		fmt.Fprintf(stderr, "shunya-verify: log-key: %q is not a valid key name (no spaces or '+')\n", *origin)
		return 2
	}
	skey, vkey, err := note.GenerateKey(*origin)
	if err == nil {
		err = os.MkdirAll(*out, 0o755)
	}
	if err == nil {
		err = writeNew(filepath.Join(*out, "log.key"), skey+"\n", 0o600)
	}
	if err == nil {
		err = writeNew(filepath.Join(*out, "log.vkey"), vkey+"\n", 0o644)
	}
	if err != nil {
		fmt.Fprintln(stderr, "shunya-verify: log-key:", err)
		return 1
	}
	fmt.Fprintf(stdout, "log key written: %s (secret, keep on the log server only)\nverifier key:   %s\n  %s\n",
		filepath.Join(*out, "log.key"), filepath.Join(*out, "log.vkey"), vkey)
	return 0
}

func writeNew(p, data string, mode os.FileMode) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readSigner(path string) (*note.Signer, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		return nil, fmt.Errorf("log key %s: permissions %v are too open (want 0600)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return note.ParseSignerKey(string(b))
}

// isLoopback: the server binds only to this machine unless --allow-public.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cmdServe(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	fl.SetOutput(stderr)
	dir := fl.String("dir", "", "the log's directory (created with --init)")
	keyFile := fl.String("log-key", "", "the log's signing key (shunya-verify log-key)")
	root := fl.String("root", "", "the organisation's root public key: only its stations' certificates are logged")
	revocations := fl.String("revocations", "", "the root's revocation list (re-read on restart)")
	listen := fl.String("listen", "127.0.0.1:8080", "address to listen on")
	public := fl.Bool("allow-public", false, "allow listening on a non-loopback address")
	initLog := fl.Bool("init", false, "create an empty log in --dir if it has none")
	rate := fl.Float64("rate", 5, "requests per second per client (bursts of 4×; a POST costs 5)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *dir == "" || *keyFile == "" || *root == "" || *revocations == "" || fl.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: shunya-verify serve --dir DIR --log-key LOG.key --root ROOT.pub --revocations FILE [--listen 127.0.0.1:8080] [--init]")
		return 2
	}
	if !isLoopback(*listen) && !*public {
		fmt.Fprintf(stderr, "shunya-verify: serve: %s is not a loopback address; add --allow-public to serve other machines\n", *listen)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	s, err := readSigner(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "shunya-verify: serve:", err)
		return 1
	}
	pol, revFile, err := policy(*root, *revocations)
	if err != nil {
		fmt.Fprintln(stderr, "shunya-verify: serve:", err)
		return 1
	}
	var lg *tilestore.Log
	if _, err := os.Stat(filepath.Join(*dir, "checkpoint")); errors.Is(err, fs.ErrNotExist) && *initLog {
		lg, err = tilestore.Create(*dir, s)
		if err != nil {
			fmt.Fprintln(stderr, "shunya-verify: serve:", err)
			return 1
		}
		logger.Info("created log", "dir", *dir, "origin", s.Name)
	} else if lg, err = tilestore.Load(*dir, s, nil); err != nil {
		fmt.Fprintln(stderr, "shunya-verify: serve: the log failed its integrity check, refusing to serve it:", err)
		return 1
	}
	srv, err := logserver.New(logserver.Config{Log: lg, Dir: *dir, LogKey: &s.Verifier, Policy: pol, RevocationsFile: revFile, Logger: logger, Rate: *rate, Burst: 4 * *rate})
	if err != nil {
		fmt.Fprintln(stderr, "shunya-verify: serve:", err)
		return 1
	}
	hs := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn)}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(stderr, "shunya-verify: serve:", err)
		return 1
	}
	logger.Info("serving", "url", "http://"+ln.Addr().String(), "origin", s.Name, "size", lg.Size())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "shunya-verify: serve:", err)
		return 1
	}
	logger.Info("stopped")
	return 0
}

// policy loads the root and its verified revocation list (and returns the list's bytes).
func policy(rootPath, revPath string) (cert.Policy, []byte, error) {
	b, err := os.ReadFile(rootPath)
	if err != nil {
		return cert.Policy{}, nil, err
	}
	root, err := keys.ParsePublic(string(b))
	if err != nil {
		return cert.Policy{}, nil, err
	}
	raw, err := os.ReadFile(revPath)
	if err != nil {
		return cert.Policy{}, nil, err
	}
	l, err := keys.ParseRevocationList(raw, ed25519.PublicKey(root))
	if err != nil {
		return cert.Policy{}, nil, err
	}
	return cert.Policy{Root: root, Revocations: &l}, raw, nil
}

func cmdAudit(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("audit", flag.ContinueOnError)
	fl.SetOutput(stderr)
	src := fl.String("log", "", "the log: its URL (http://…) or its directory")
	keyArg := fl.String("log-key", "", "the log's verifier key (file or key)")
	state := fl.String("state", "", "file holding the checkpoint seen last time (read, then replaced after a passing audit)")
	asJSON := fl.Bool("json", false, "print the result as JSON")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *src == "" || *keyArg == "" || *state == "" || fl.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: shunya-verify audit --log URL|DIR --log-key LOG.vkey --state FILE [--json]")
		return 2
	}
	key, err := certcheck.ReadLogKey(*keyArg)
	if err != nil {
		fmt.Fprintln(stderr, "shunya-verify: audit:", err)
		return 1
	}
	var fsys fs.FS
	if strings.HasPrefix(*src, "http://") || strings.HasPrefix(*src, "https://") {
		fsys = logclient.New(*src, key).FS(context.Background())
	} else {
		fsys = os.DirFS(*src)
	}
	prev, err := os.ReadFile(*state)
	if errors.Is(err, fs.ErrNotExist) {
		prev, err = nil, nil
	}
	if err != nil {
		fmt.Fprintln(stderr, "shunya-verify: audit:", err)
		return 1
	}
	r, err := audit.Run(fsys, key, prev)
	if err != nil {
		if *asJSON {
			json.NewEncoder(stdout).Encode(map[string]any{"passed": false, "error": err.Error()})
		} else {
			fmt.Fprintln(stdout, "AUDIT FAILED:", err)
		}
		return 1
	}
	if err := writeState(*state, r.Signed); err != nil {
		fmt.Fprintln(stderr, "shunya-verify: audit: saving state:", err)
		return 1
	}
	if *asJSON {
		out := map[string]any{"passed": true, "origin": r.Checkpoint.Origin, "size": r.Entries, "certificates": r.Certificates,
			"seed_requests": r.SeedRequests, "beacons": r.Beacons, "manifests": r.Manifests, "repeated_seed_requests": r.Repeated}
		if r.Previous != nil {
			out["previous_size"] = r.Previous.Size
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		return 0
	}
	fmt.Fprintf(stdout, "AUDIT PASSED: log %s, %d entries (%d certificates, %d batch manifest(s), %d seed requests, %d beacons)\n",
		r.Checkpoint.Origin, r.Entries, r.Certificates, r.Manifests, r.SeedRequests, r.Beacons)
	if r.Previous != nil {
		fmt.Fprintf(stdout, "  consistent with the checkpoint saved before (size %d)\n", r.Previous.Size)
	} else {
		fmt.Fprintln(stdout, "  first audit: no earlier checkpoint to compare; saved this one")
	}
	for _, s := range r.Repeated {
		fmt.Fprintln(stdout, "  WARNING repeated seed requests (possible seed grinding):", s)
	}
	return 0
}

func writeState(p string, b []byte) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
