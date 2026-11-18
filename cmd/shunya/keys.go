package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"shunya/internal/journal"
	"shunya/internal/keys"
)

const keysUsage = `usage: shunya keys <command>

  gen-station FILE        new station signing key (mode 0600); prints its key id
  gen-dev FILE            the Milestone 3 name of gen-station (same key format)
  init-root DIR           new offline root: DIR/root.key (passphrase-encrypted),
                          DIR/root.pub and DIR/revocations.json (empty, number 1)
  issue-station           certify a station key with the root:
      --root DIR/root.key (--station-key FILE | --pub HEX) --name NAME
      [--days 365] [--not-before TIME] [--out FILE] [--passphrase-file FILE]
  revoke                  add a station key to the revocation list:
      --root DIR/root.key --revocations FILE --key-id ID --reason retired|compromised
      [--at TIME] [--note TEXT] [--passphrase-file FILE]
  show [--root PUB] FILE  print a root public key, station certificate or revocation list
                          (and verify it against --root)

Run init-root, issue-station and revoke on an offline machine; only root.pub,
station certificates and revocation lists leave it.
`

// now is the clock for key commands (tests pin it).
var now = time.Now

func cmdKeys(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, keysUsage)
		return 2
	}
	switch args[0] {
	case "gen-station", "gen-dev":
		return keysGenStation(args[0], args[1:], stdout, stderr)
	case "init-root":
		return keysInitRoot(args[1:], stdout, stderr)
	case "issue-station":
		return keysIssueStation(args[1:], stdout, stderr)
	case "revoke":
		return keysRevoke(args[1:], stdout, stderr)
	case "show":
		return keysShow(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, keysUsage)
		return 0
	}
	fmt.Fprintf(stderr, "shunya keys: unknown command %q\n\n%s", args[0], keysUsage)
	return 2
}

func keysGenStation(name string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "usage: shunya keys %s FILE\n", name)
		return 2
	}
	pub, err := journal.GenerateKeyFile(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys:", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (mode 0600)\nkey id: %s\npublic: %x\n", args[0], journal.KeyID(pub), []byte(pub))
	fmt.Fprintln(stdout, "Until the root certifies it (shunya keys issue-station), certificates it signs are marked dev-key and refused by verifiers.")
	return 0
}

// passphrase reads the root key passphrase from file (first line) or, without a file,
// from the terminal without echo. create asks twice and enforces a minimum length.
func passphrase(file string, create bool, stderr io.Writer) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		line, _, _ := bytes.Cut(b, []byte("\n"))
		p := bytes.TrimSuffix(line, []byte("\r"))
		if create && len(p) < 12 {
			return nil, errors.New("passphrase: at least 12 characters")
		}
		return p, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("passphrase: stdin is not a terminal; use --passphrase-file FILE")
	}
	fmt.Fprint(stderr, "root key passphrase: ")
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, err
	}
	if create {
		if len(p) < 12 {
			return nil, errors.New("passphrase: at least 12 characters")
		}
		fmt.Fprint(stderr, "again: ")
		q, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(p, q) {
			return nil, errors.New("passphrase: the two entries differ")
		}
	}
	return p, nil
}

func keysInitRoot(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("keys init-root", flag.ContinueOnError)
	fl.SetOutput(stderr)
	passFile := fl.String("passphrase-file", "", "read the passphrase from FILE (first line) instead of the terminal")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fmt.Fprint(stderr, "usage: shunya keys init-root [--passphrase-file FILE] DIR\n")
		return 2
	}
	dir := fl.Arg(0)
	paths := []string{filepath.Join(dir, "root.key"), filepath.Join(dir, "root.pub"), filepath.Join(dir, "revocations.json")}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			fmt.Fprintf(stderr, "shunya: keys init-root: %s exists; refusing to replace a root\n", p)
			return 1
		}
	}
	pass, err := passphrase(*passFile, true, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys init-root:", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(stderr, "shunya: keys init-root:", err)
		return 1
	}
	pub, err := keys.CreateRoot(paths[0], pass)
	if err == nil {
		err = keys.WritePublic(paths[1], pub)
	}
	if err == nil {
		var priv ed25519.PrivateKey
		if priv, err = keys.LoadRoot(paths[0], pass); err == nil {
			var l keys.RevocationList
			if l, err = keys.NewRevocationList(priv, now()); err == nil {
				err = writeJSONFile(paths[2], l, false)
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys init-root:", err)
		return 1
	}
	fmt.Fprintf(stdout, "root key id: %s\nwrote %s (encrypted), %s, %s\n", keys.KeyID(pub), paths[0], paths[1], paths[2])
	fmt.Fprintln(stdout, "Keep root.key offline and backed up; distribute root.pub to verifiers.")
	return 0
}

// loadRoot asks for the passphrase and decrypts the root key.
func loadRoot(path, passFile string, stderr io.Writer) (ed25519.PrivateKey, error) {
	pass, err := passphrase(passFile, false, stderr)
	if err != nil {
		return nil, err
	}
	return keys.LoadRoot(path, pass)
}

func keysIssueStation(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("keys issue-station", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", "", "root key file (root.key)")
	stationKey := fl.String("station-key", "", "station key file (to read its public key)")
	pubHex := fl.String("pub", "", "station public key (hex), instead of --station-key")
	name := fl.String("name", "", "station name, printed on its certificates")
	days := fl.Int("days", 365, "validity in days")
	notBefore := fl.String("not-before", "", "start of validity (RFC 3339 UTC; default now)")
	out := fl.String("out", "", "write the station certificate here (default: stdout)")
	passFile := fl.String("passphrase-file", "", "read the passphrase from FILE")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *root == "" || *name == "" || (*stationKey == "") == (*pubHex == "") || fl.NArg() != 0 || *days < 1 {
		fmt.Fprint(stderr, "usage: shunya keys issue-station --root ROOT.key (--station-key FILE | --pub HEX) --name NAME [--days N] [--out FILE]\n")
		return 2
	}
	var pub ed25519.PublicKey
	if *stationKey != "" {
		k, err := journal.LoadKeyFile(*stationKey)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: keys issue-station:", err)
			return 1
		}
		pub = k.Public().(ed25519.PublicKey)
	} else {
		p, err := keys.ParsePublic(*pubHex)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: keys issue-station:", err)
			return 1
		}
		pub = p
	}
	nb := now()
	if *notBefore != "" {
		t, err := keys.ParseTime(*notBefore)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: keys issue-station:", err)
			return 2
		}
		nb = t
	}
	priv, err := loadRoot(*root, *passFile, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys issue-station:", err)
		return 1
	}
	sc, err := keys.IssueStation(priv, *name, pub, nb, nb.AddDate(0, 0, *days), now())
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys issue-station:", err)
		return 1
	}
	if *out == "" {
		return writeJSON(stdout, stderr, sc)
	}
	if err := writeJSONFile(*out, sc, false); err != nil {
		fmt.Fprintln(stderr, "shunya: keys issue-station:", err)
		return 1
	}
	fmt.Fprintf(stdout, "certified station %q, key %s, valid %s to %s\nwrote %s\n", sc.Station, sc.KeyID, sc.NotBefore, sc.NotAfter, *out)
	return 0
}

func keysRevoke(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("keys revoke", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", "", "root key file (root.key)")
	listPath := fl.String("revocations", "", "the current revocation list (replaced with the next one)")
	keyID := fl.String("key-id", "", "station key id to revoke (ed25519:…)")
	reason := fl.String("reason", "", "retired (certificates issued before --at stay valid) or compromised (none do)")
	at := fl.String("at", "", "revocation time (RFC 3339 UTC; default now)")
	note := fl.String("note", "", "free-text note recorded in the list")
	passFile := fl.String("passphrase-file", "", "read the passphrase from FILE")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *root == "" || *listPath == "" || *keyID == "" || *reason == "" || fl.NArg() != 0 {
		fmt.Fprint(stderr, "usage: shunya keys revoke --root ROOT.key --revocations FILE --key-id ID --reason retired|compromised [--at TIME] [--note TEXT]\n")
		return 2
	}
	when := now()
	if *at != "" {
		t, err := keys.ParseTime(*at)
		if err != nil {
			fmt.Fprintln(stderr, "shunya: keys revoke:", err)
			return 2
		}
		when = t
	}
	priv, err := loadRoot(*root, *passFile, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys revoke:", err)
		return 1
	}
	raw, err := os.ReadFile(*listPath)
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys revoke:", err)
		return 1
	}
	l, err := keys.ParseRevocationList(raw, priv.Public().(ed25519.PublicKey))
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys revoke:", err)
		return 1
	}
	n, err := l.Revoke(priv, *keyID, *reason, when, now())
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys revoke:", err)
		return 1
	}
	if *note != "" {
		for i := range n.Revoked {
			if n.Revoked[i].KeyID == *keyID {
				n.Revoked[i].Note = *note
			}
		}
		if n, err = resign(priv, n); err != nil {
			fmt.Fprintln(stderr, "shunya: keys revoke:", err)
			return 1
		}
	}
	if err := writeJSONFile(*listPath, n, true); err != nil {
		fmt.Fprintln(stderr, "shunya: keys revoke:", err)
		return 1
	}
	fmt.Fprintf(stdout, "revoked %s (%s from %s); revocation list %d written to %s\nDistribute the new list to every verifier.\n",
		*keyID, *reason, keys.FormatTime(when), n.Number, *listPath)
	return 0
}

// resign signs l again after a note was added (Revoke signs before the note exists).
func resign(priv ed25519.PrivateKey, l keys.RevocationList) (keys.RevocationList, error) {
	l.Signature = ""
	sig, err := keys.SignJSON(priv, keys.CtxRevocations, l)
	l.Signature = sig
	return l, err
}

func keysShow(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("keys show", flag.ContinueOnError)
	fl.SetOutput(stderr)
	rootPub := fl.String("root", "", "root public key (file or hex): verify the document against it")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fmt.Fprint(stderr, "usage: shunya keys show [--root ROOT.pub] FILE\n")
		return 2
	}
	raw, err := os.ReadFile(fl.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "shunya: keys show:", err)
		return 1
	}
	if pub, err := keys.ParsePublic(string(raw)); err == nil {
		fmt.Fprintf(stdout, "root public key %s\n  %x\n", keys.KeyID(pub), []byte(pub))
		return 0
	}
	var root ed25519.PublicKey
	if *rootPub != "" {
		text := *rootPub
		if b, err := os.ReadFile(text); err == nil {
			text = string(b)
		}
		if root, err = keys.ParsePublic(text); err != nil {
			fmt.Fprintln(stderr, "shunya: keys show:", err)
			return 1
		}
	}
	var probe struct {
		Format string `json:"format"`
	}
	json.Unmarshal(raw, &probe)
	verified := "NOT verified (give --root ROOT.pub)"
	switch probe.Format {
	case "shunya-station-certificate":
		var sc keys.StationCert
		if root != nil {
			if sc, err = keys.ParseStationCert(raw, root); err != nil {
				fmt.Fprintln(stderr, "shunya: keys show: INVALID:", err)
				return 1
			}
			verified = "verified against root " + keys.KeyID(root)
		} else if err := json.Unmarshal(raw, &sc); err != nil {
			fmt.Fprintln(stderr, "shunya: keys show:", err)
			return 1
		}
		fmt.Fprintf(stdout, "station certificate (%s)\n  station   %s\n  key       %s\n  valid     %s to %s\n  issuer    %s, issued %s\n",
			verified, sc.Station, sc.KeyID, sc.NotBefore, sc.NotAfter, sc.Issuer, sc.Issued)
	case "shunya-revocation-list":
		var l keys.RevocationList
		if root != nil {
			if l, err = keys.ParseRevocationList(raw, root); err != nil {
				fmt.Fprintln(stderr, "shunya: keys show: INVALID:", err)
				return 1
			}
			verified = "verified against root " + keys.KeyID(root)
		} else if err := json.Unmarshal(raw, &l); err != nil {
			fmt.Fprintln(stderr, "shunya: keys show:", err)
			return 1
		}
		fmt.Fprintf(stdout, "revocation list %d (%s), issued %s by %s\n", l.Number, verified, l.Issued, l.Issuer)
		if len(l.Revoked) == 0 {
			fmt.Fprintln(stdout, "  no station keys revoked")
		}
		for _, r := range l.Revoked {
			fmt.Fprintf(stdout, "  %s  %-11s from %s  %s\n", r.KeyID, r.Reason, r.At, r.Note)
		}
	default:
		fmt.Fprintf(stderr, "shunya: keys show: %s is not a root public key, station certificate or revocation list\n", fl.Arg(0))
		return 1
	}
	return 0
}

// writeJSONFile writes v as indented JSON. replace swaps an existing file atomically
// (temporary file, fsync, rename); otherwise an existing file is refused.
func writeJSONFile(path string, v any, replace bool) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'), replace)
}

func writeFile(path string, b []byte, replace bool) error {
	target := path
	if replace {
		path += ".tmp"
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if replace {
		return os.Rename(path, target)
	}
	return nil
}
