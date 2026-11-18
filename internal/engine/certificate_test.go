package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shunya/internal/ata"
	"shunya/internal/cert"
	"shunya/internal/certpdf"
	"shunya/internal/journal"
	"shunya/internal/keys"
	"shunya/internal/sanitize"
)

var certNow = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func certInput(t *testing.T) (CertInput, ed25519.PublicKey, keys.RevocationList) {
	t.Helper()
	rpub, rpriv, _ := ed25519.GenerateKey(rand.Reader)
	sc, err := keys.IssueStation(rpriv, "lab-bay", jkey.Public().(ed25519.PublicKey), certNow.AddDate(0, -1, 0), certNow.AddDate(1, 0, 0), certNow)
	if err != nil {
		t.Fatal(err)
	}
	crl, _ := keys.NewRevocationList(rpriv, certNow)
	return CertInput{Issuer: "shunya test", IssuerBuildHash: strings.Repeat("ee", 32), Build: "dev",
		StationPub: jkey.Public().(ed25519.PublicKey), StationCert: &sc, Now: certNow}, rpub, crl
}

func loadJournal(t *testing.T, path string) (*journal.Log, []byte, State) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	log := readLog(t, path)
	st, err := Replay(log)
	if err != nil {
		t.Fatal(err)
	}
	return log, b, st
}

// overwriteJournal wipes an image for real, with one interruption, and verifies it.
func overwriteJournal(t *testing.T, verify ...VerifiedData) (string, Plan) {
	t.Helper()
	file := image(t, "", 64*kib*8, 512)
	p := planFor(t, file, 64*kib, 128*kib)
	jpath := filepath.Join(t.TempDir(), "wipe.journal")
	w, err := journal.Create(jpath, jkey)
	if err != nil {
		t.Fatal(err)
	}
	rec := JournalRecorder{W: w, BuildHash: strings.Repeat("ab", 32)}
	if err := rec.Start(NewWipeID(), "shunya test", p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	tg := &hookTarget{Target: file, onWrite: func(n int, _ int64) error {
		if n == 3 {
			cancel(errors.New("operator"))
		}
		return nil
	}}
	if _, err := Run(ctx, tg, p, rec, RunOptions{}); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	w.Close()
	st, _ := Replay(readLog(t, jpath))
	w, log, err := journal.OpenAppend(jpath, jkey)
	if err != nil {
		t.Fatal(err)
	}
	rec.W = w
	rec.Resumed(st, log.TornBytes)
	if _, err := Run(context.Background(), file, p, rec, RunOptions{StartPass: st.Pass, StartOffset: st.Offset}); err != nil {
		t.Fatal(err)
	}
	if len(verify) == 0 {
		verify = []VerifiedData{{Mode: "full", Pattern: PatternRandom, OK: true, BytesRead: p.SizeBytes}}
	}
	for _, v := range verify {
		rec.Verified(v)
	}
	w.Close()
	return jpath, p
}

func TestCertificateFromOverwriteJournal(t *testing.T) {
	jpath, p := overwriteJournal(t)
	log, raw, st := loadJournal(t, jpath)
	in, rpub, crl := certInput(t)
	c, err := BuildCertificate(log, raw, st, in)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cert.Sign(c, jkey)
	if err != nil {
		t.Fatal(err)
	}
	r, err := cert.Verify(signed, cert.Policy{Root: rpub, Revocations: &crl})
	if err != nil {
		t.Fatal(err)
	}
	got := r.Certificate
	if got.Erasure.Method != MethodOverwrite || got.Erasure.NISTLevel != "clear" || got.Tool.WipeBuildHash != strings.Repeat("ab", 32) ||
		len(got.Interruptions) != 1 || got.Interruptions[0].Reason != "operator" || got.Station.Name != "lab-bay" ||
		got.Journal.Records != len(log.Records) || got.Erasure.Passes[0] != PatternRandom || got.Hidden.Checked {
		t.Fatalf("%+v", got)
	}
	// Secrets stay in the journal: the random pass key must not be in the certificate.
	if bytes.Contains(signed, []byte(p.Passes[0].Key)) || bytes.Contains(signed, []byte(st.Plan.Passes[0].Key)) {
		t.Error("pattern key copied into the certificate")
	}
	if _, err := certpdf.Render(got, r.ID); err != nil {
		t.Fatal(err)
	}
	// A journal changed after the certificate no longer matches its hash.
	if got.Journal.SHA256 == "" || bytes.Contains(raw, []byte(got.Journal.SHA256)) {
		t.Error("journal hash")
	}
}

func TestCertificateFromSecurityEraseJournal(t *testing.T) {
	jpath := filepath.Join(t.TempDir(), "j")
	w, _ := journal.Create(jpath, jkey)
	rec := JournalRecorder{W: w}
	rec.Start(NewWipeID(), "t", erasePlan(t))
	removed := hiddenHPA().Before
	removed.ReportedSectors, removed.HPA = 2112, false
	rec.Hidden(HiddenEvent{Event: HiddenRemoved, State: removed})
	rec.Firmware(sanitize.Event{Event: EvMarkersPlanted, Note: "1024 sectors"})
	for _, s := range []ata.Step{{Step: ata.StepSetPassword, Password: "shunya-secret-pw"}, {Step: ata.StepErasePrepare},
		{Step: ata.StepEraseUnit, Mode: "normal"}, {Step: ata.StepEraseDone, Seconds: 3}, {Step: ata.StepChecked}} {
		rec.Security(s)
	}
	rec.Done(0)
	rec.Verified(VerifiedData{Mode: "markers", OK: true, BytesRead: 1024 * 512})
	in, rpub, crl := certInput(t)

	// The HPA is still removed: no certificate until it is restored. (Append fsyncs.)
	log, raw, st := loadJournal(t, jpath)
	if _, err := BuildCertificate(log, raw, st, in); !errors.Is(err, ErrNotCertifiable) {
		t.Errorf("HPA pending: %v", err)
	}
	rec.Hidden(HiddenEvent{Event: HiddenRestored, State: hiddenHPA().Before})
	w.Close()
	log, raw, st = loadJournal(t, jpath)
	c, err := BuildCertificate(log, raw, st, in)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := cert.Sign(c, jkey)
	if bytes.Contains(signed, []byte("shunya-secret-pw")) {
		t.Fatal("ATA password copied into the certificate")
	}
	r, err := cert.Verify(signed, cert.Policy{Root: rpub, Revocations: &crl})
	if err != nil {
		t.Fatal(err)
	}
	h := r.Certificate.Hidden
	if !h.Checked || !h.HPA || h.HPASectors == 0 || !h.Wiped || h.Final != HiddenRestored || r.Certificate.Erasure.NISTLevel != "purge" {
		t.Errorf("%+v level %s", h, r.Certificate.Erasure.NISTLevel)
	}
	names := []string{}
	for _, s := range r.Certificate.Erasure.Steps {
		names = append(names, s.Step+"="+s.Detail)
	}
	if strings.Join(names, ",") != "set-password=,erase-prepare=,erase-unit=normal,erase-done=3 s,security-checked=,markers-planted=1024 sectors" {
		t.Errorf("steps %v", names)
	}
}

func TestCertificateRefusals(t *testing.T) {
	in, _, _ := certInput(t)
	// A failed verification, even followed by a passing one.
	jpath, _ := overwriteJournal(t, VerifiedData{Mode: "full", OK: false, BadSectors: 3}, VerifiedData{Mode: "full", OK: true})
	log, raw, st := loadJournal(t, jpath)
	if _, err := BuildCertificate(log, raw, st, in); !errors.Is(err, ErrNotCertifiable) {
		t.Errorf("failed check: %v", err)
	}
	jpath, _ = overwriteJournal(t)
	log, raw, st = loadJournal(t, jpath)
	for name, mod := range map[string]func(*State, *CertInput){
		"not done":        func(s *State, _ *CertInput) { s.Done = false },
		"no verification": func(s *State, _ *CertInput) { s.Verifications = nil },
		"other station": func(_ *State, c *CertInput) {
			p, _, _ := ed25519.GenerateKey(rand.Reader)
			c.StationPub = p
		},
		"expired station cert": func(_ *State, c *CertInput) { c.Now = certNow.AddDate(2, 0, 0) },
		"station cert for another key": func(_ *State, c *CertInput) {
			sc := *c.StationCert
			sc.PublicKey = strings.Repeat("00", 32)
			c.StationCert = &sc
		},
	} {
		s, c := st, in
		mod(&s, &c)
		if _, err := BuildCertificate(log, raw, s, c); !errors.Is(err, ErrNotCertifiable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Dev key: a certificate is built, marked, and refused by default.
	dev := in
	dev.StationCert = nil
	c, err := BuildCertificate(log, raw, st, dev)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := cert.Sign(c, jkey)
	if _, err := cert.Verify(signed, cert.Policy{SkipRevocation: true}); !errors.Is(err, cert.ErrDevKey) {
		t.Errorf("dev key: %v", err)
	}
}

func TestCertificateKnowsEveryMethod(t *testing.T) {
	for _, m := range []string{MethodOverwrite, MethodATAErase, MethodATAEnhancedErase, MethodATASanitizeCrypto,
		MethodATASanitizeBlock, MethodATASanitizeOverwrite, MethodNVMeSanitizeCrypto, MethodNVMeSanitizeBlock,
		MethodNVMeSanitizeOverwrite, MethodNVMeFormatCrypto, MethodNVMeFormatUserData} {
		if !cert.KnownMethod(m) {
			t.Errorf("certificate does not accept method %q", m)
		}
	}
}
