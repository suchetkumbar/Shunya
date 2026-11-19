package engine

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"shunya/internal/cert"
	"shunya/internal/journal"
	"shunya/internal/keys"
	"shunya/internal/sanitize"
)

// CertInput is what a certificate needs besides the journal.
type CertInput struct {
	Issuer          string // "shunya 0.7.0-dev"
	IssuerBuildHash string
	Build           string // dev or release
	StationPub      ed25519.PublicKey
	StationCert     *keys.StationCert // nil: dev key (certificate marked, verifiers refuse by default)
	Now             time.Time
	VerifyURL       string // default cert.DefaultVerifyURL
}

// ErrNotCertifiable: the journal does not show a finished, verified wipe.
var ErrNotCertifiable = errors.New("no certificate: the wipe is not finished and verified")

// BuildCertificate summarises a verified journal as a certificate body. journalBytes
// is the journal file as read (the certificate binds the SHA-256 of its verified
// prefix). Secrets in the journal — pattern keys, marker keys, the temporary ATA
// password — are never copied.
func BuildCertificate(log *journal.Log, journalBytes []byte, st State, in CertInput) (cert.Certificate, error) {
	fail := func(f string, a ...any) (cert.Certificate, error) {
		return cert.Certificate{}, fmt.Errorf("%w: %s", ErrNotCertifiable, fmt.Sprintf(f, a...))
	}
	if log.KeyID != keys.KeyID(in.StationPub) {
		return fail("journal signed by %s, station key is %s", log.KeyID, keys.KeyID(in.StationPub))
	}
	if int64(len(journalBytes)) < log.GoodBytes {
		return fail("journal bytes shorter than the verified journal")
	}
	switch {
	case !st.Done:
		return fail("the journal shows the wipe still %s; resume it first", st.Pending())
	case len(st.Verifications) == 0:
		return fail("no verification recorded; run shunya verify first")
	}
	for i, v := range st.Verifications {
		if !v.OK {
			return fail("verification %d (%s) failed: the data may not be erased", i+1, v.Mode)
		}
	}
	if pendingHPA(st) {
		return fail("the HPA is still removed (restore pending); resume the wipe to restore it")
	}
	if sc := in.StationCert; sc != nil {
		if sc.PublicKey != hex.EncodeToString(in.StationPub) {
			return fail("station certificate is for key %s", sc.KeyID)
		}
		if !sc.ValidAt(in.Now) {
			return fail("station certificate valid %s to %s, now is %s", sc.NotBefore, sc.NotAfter, keys.FormatTime(in.Now))
		}
	}
	url := in.VerifyURL
	if url == "" {
		url = cert.DefaultVerifyURL
	}
	h := sha256.Sum256(journalBytes[:log.GoodBytes])
	p := st.Plan
	c := cert.Certificate{
		Format: cert.Format, Version: cert.Version, WipeID: st.WipeID, Issued: keys.FormatTime(in.Now),
		Result: cert.ResultErasedVerified,
		Tool: cert.Tool{Wipe: st.Tool, WipeBuildHash: st.ToolBuildHash, Issuer: in.Issuer,
			IssuerBuildHash: in.IssuerBuildHash, Build: in.Build},
		Device: cert.Device{Path: p.Target.Path, Model: p.Target.Model, Serial: p.Target.Serial, WWID: p.Target.WWID,
			SizeBytes: int64(p.Target.SizeBytes), Fingerprint: p.Target.Fingerprint, Media: string(p.Media), Virtual: p.Virtual},
		Erasure: cert.Erasure{Method: p.Method, NISTLevel: string(p.Level), Passes: []string{}, SizeBytes: p.SizeBytes,
			SectorSize: p.SectorSize, Started: stamp(st.Started), Finished: stamp(st.Finished),
			Steps: steps(st), Notes: append([]string{}, p.Notes...)},
		Hidden:        hidden(st),
		Verification:  []cert.Verification{},
		Interruptions: []cert.Interruption{},
		Journal:       cert.Journal{SHA256: hex.EncodeToString(h[:]), Records: len(log.Records), KeyID: log.KeyID},
		Station:       cert.StationFor(in.StationPub, in.StationCert),
		VerifyURL:     url,
	}
	if p.Hidden != nil {
		c.Device.NativeFingerprint = p.Hidden.NativeFingerprint
	}
	for _, ps := range p.Passes {
		c.Erasure.Passes = append(c.Erasure.Passes, ps.Pattern)
	}
	for _, v := range st.Verifications {
		c.Verification = append(c.Verification, cert.Verification{Mode: v.Mode, Pattern: v.Pattern, OK: v.OK,
			BytesRead: v.BytesRead, BadSectors: v.BadSectors, Samples: v.Samples, SeedSource: v.SeedSource,
			Seed: v.Seed, Bound95: v.Bound95, Scope: v.Scope, SeedRequest: v.SeedRequest, SeedLog: v.SeedLog})
	}
	for _, i := range st.Interruptions {
		c.Interruptions = append(c.Interruptions, cert.Interruption{Kind: i.Kind, Reason: i.Reason, Pass: i.Pass,
			Offset: i.Offset, StoppedAt: stamp(i.StoppedAt), ResumedAt: stamp(i.ResumedAt), TornBytes: i.TornBytes})
	}
	return c, nil
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// pendingHPA: the last hidden-area event left the HPA removed although the policy
// restores it.
func pendingHPA(st State) bool {
	if st.Plan.Hidden == nil || !st.Plan.Hidden.RemoveHPA || st.Plan.Hidden.Policy == HPALeaveRemoved || len(st.HiddenEvents) == 0 {
		return false
	}
	switch st.HiddenEvents[len(st.HiddenEvents)-1].Event {
	case HiddenRemoved, HiddenAlreadyGone:
		return true
	}
	return false
}

// steps lists the Security Erase and firmware steps without secrets or progress noise.
func steps(st State) []cert.Step {
	out := []cert.Step{}
	for _, s := range st.SecuritySteps {
		var d []string // never s.Password
		if s.Mode != "" {
			d = append(d, s.Mode)
		}
		if s.Seconds > 0 {
			d = append(d, fmt.Sprintf("%.0f s", s.Seconds))
		}
		out = append(out, cert.Step{Step: s.Step, Detail: strings.Join(d, ", ")})
	}
	for _, e := range st.FirmwareEvents {
		if e.Event == sanitize.EvProgress {
			continue
		}
		d := e.Action
		if e.Note != "" {
			d = strings.TrimPrefix(d+"; "+e.Note, "; ")
		}
		out = append(out, cert.Step{Step: e.Event, Detail: d})
	}
	return out
}

func hidden(st State) cert.Hidden {
	h := st.Plan.Hidden
	if h == nil {
		return cert.Hidden{Reason: "not an ATA drive: HPA/DCO do not apply"}
	}
	b := h.Before
	out := cert.Hidden{Checked: b.Checked, Reason: b.Reason, HPA: b.HPA, HPASectors: b.HPASectors(), DCO: b.DCO,
		DCOSectors: b.DCOSectors, Policy: h.Policy, Wiped: h.RemoveHPA, KeepReason: h.KeepReason}
	if n := len(st.HiddenEvents); n > 0 {
		out.Final = st.HiddenEvents[n-1].Event
	}
	return out
}
