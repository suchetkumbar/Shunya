package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"shunya/internal/backend"
	"shunya/internal/certcheck"
	"shunya/internal/engine"
	"shunya/internal/journal"
	"shunya/internal/keys"
	"shunya/internal/logclient"
	"shunya/internal/logentry"
)

// Offline fallbacks when the log cannot be reached for a sampling seed.
const (
	offlineFull  = "full"  // read the whole target back instead (default)
	offlineLocal = "local" // sample with a random seed the tool draws itself (labelled)
)

func logFlags(fl *flag.FlagSet, f *wipeFlags) {
	fl.StringVar(&f.logURL, "log", "", "transparency log URL: --sample takes its seed from the log, and the certificate is submitted to it")
	fl.StringVar(&f.logKey, "log-key", "", "the log's verifier key (file or key); required with --log")
	fl.StringVar(&f.offlineSeed, "offline-seed", offlineFull, "if the log is unreachable for --sample: full (read everything back instead) or local (sample with a tool-drawn random seed, labelled in the certificate)")
}

func checkLogFlags(f wipeFlags) error {
	switch {
	case (f.logURL == "") != (f.logKey == ""):
		return errors.New("--log URL and --log-key KEY go together")
	case f.offlineSeed != offlineFull && f.offlineSeed != offlineLocal:
		return errors.New("--offline-seed must be full or local")
	case f.logURL != "" && !strings.HasPrefix(f.logURL, "https://") && !strings.HasPrefix(f.logURL, "http://"):
		return errors.New("--log must be an http(s) URL")
	case f.logURL != "" && f.sample > 0 && f.stationCert == "":
		return errors.New("--log with --sample needs --station-cert: the log gives seeds only to certified stations")
	}
	return nil
}

func newLogClient(f wipeFlags) (*logclient.Client, error) {
	key, err := certcheck.ReadLogKey(f.logKey)
	if err != nil {
		return nil, err
	}
	return logclient.New(f.logURL, key), nil
}

// sampleSeed is the seed for a sampled verification of tg:
//   - --seed: the operator's (labelled operator);
//   - --log: from the log, asked now that the wipe is done (tlog-checkpoint); if the
//     log is unreachable, the --offline-seed fallback: full read-back instead
//     (full=true), or a random seed drawn here (local-random);
//   - neither (only with --offline-seed local): a random seed drawn here.
func sampleSeed(ctx context.Context, f wipeFlags, tg backend.Target, stdout io.Writer) (seed []byte, src string, q *logentry.SeedRequest, in *logentry.Inclusion, full bool, err error) {
	if f.seed != "" {
		return mustHex(f.seed), engine.SeedOperator, nil, nil, false, nil
	}
	local := func() ([]byte, string, *logentry.SeedRequest, *logentry.Inclusion, bool, error) {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		return b, engine.SeedLocal, nil, nil, false, err
	}
	if f.logURL == "" {
		return local()
	}
	req, err := seedRequest(f, tg.Identity().Fingerprint)
	if err != nil {
		return nil, "", nil, nil, false, err
	}
	c, err := newLogClient(f)
	if err != nil {
		return nil, "", nil, nil, false, err
	}
	inc, s, n, err := c.Seed(ctx, req)
	switch {
	case err == nil:
		if n > 1 {
			fmt.Fprintf(stdout, "note: the log now holds %d seed requests for this wipe; auditors see every one\n", n)
		}
		return s, engine.SeedTlog, &req, inc, false, nil
	case errors.Is(err, logclient.ErrUnreachable):
		if f.offlineSeed == offlineLocal {
			fmt.Fprintf(stdout, "log unreachable (%v): sampling with a random seed drawn by this tool (--offline-seed local; the certificate says so)\n", err)
			return local()
		}
		fmt.Fprintf(stdout, "log unreachable (%v): reading the whole target back instead of sampling (--offline-seed full)\n", err)
		return nil, "", nil, nil, true, nil
	}
	return nil, "", nil, nil, false, err
}

// seedRequest signs a request for the wipe in f.journal, hashing the journal as it
// stands (it ends with the "done" record, or later verifications).
func seedRequest(f wipeFlags, fingerprint string) (logentry.SeedRequest, error) {
	priv, err := journal.LoadKeyFile(f.key)
	if err != nil {
		return logentry.SeedRequest{}, err
	}
	raw, err := os.ReadFile(f.journal)
	if err != nil {
		return logentry.SeedRequest{}, err
	}
	log, err := journal.Read(bytes.NewReader(raw), priv.Public().(ed25519.PublicKey))
	if err != nil {
		return logentry.SeedRequest{}, err
	}
	st, err := engine.Replay(log)
	if err != nil {
		return logentry.SeedRequest{}, err
	}
	if !st.Done {
		return logentry.SeedRequest{}, errors.New("seed request: the wipe is not complete")
	}
	b, err := os.ReadFile(f.stationCert)
	if err != nil {
		return logentry.SeedRequest{}, err
	}
	sc, err := keys.DecodeStationCert(b)
	if err != nil {
		return logentry.SeedRequest{}, err
	}
	return logentry.NewSeedRequest(priv, &sc, st.WipeID, fingerprint, sha256.Sum256(raw), keys.FormatTime(now()))
}

// submit logs the certificate at path and rewrites it with the inclusion proof.
// An unreachable log leaves the certificate valid but unlogged, and says how to retry.
func submit(ctx context.Context, f wipeFlags, path string, stdout io.Writer) error {
	c, err := newLogClient(f)
	if err != nil {
		return err
	}
	file, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	out, r, err := c.Submit(ctx, file)
	if errors.Is(err, logclient.ErrUnreachable) {
		fmt.Fprintf(stdout, "log unreachable (%v): the certificate is valid but not logged yet; later run\n  shunya cert submit --log %s --log-key %s %s\n", err, f.logURL, f.logKey, path)
		return nil
	}
	if err != nil {
		return err
	}
	if err := writeFile(path, out, true); err != nil {
		return err
	}
	dup := ""
	if r.Duplicate {
		dup = " (already logged)"
	}
	fmt.Fprintf(stdout, "LOGGED %s as entry %d%s; proof verified and added to %s\n", r.ID, r.Inclusion.Index, dup, path)
	return nil
}

func certSubmit(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("cert submit", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var f wipeFlags
	fl.StringVar(&f.logURL, "log", "", "transparency log URL")
	fl.StringVar(&f.logKey, "log-key", "", "the log's verifier key (file or key)")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || f.logURL == "" || f.logKey == "" {
		fmt.Fprint(stderr, "usage: shunya cert submit --log URL --log-key KEY CERT.json\n")
		return 2
	}
	if err := submit(context.Background(), f, fl.Arg(0), stdout); err != nil {
		fmt.Fprintln(stderr, "shunya: cert submit:", err)
		return 1
	}
	return 0
}
