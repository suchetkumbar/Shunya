// Package audit checks a transparency log the way an independent monitor would:
//
//  1. the checkpoint is signed by the log's key;
//  2. every entry is fetched from the entry bundles and the tree rebuilt; its root
//     must be the checkpoint's, and every tile the log serves must match it;
//  3. against the checkpoint the auditor saw last time (its saved state), the log must
//     prove consistency: the old tree must be a prefix of the new one. A log that
//     deleted, edited or reordered an entry it had already published cannot do that,
//     even if it re-signs everything;
//  4. entries are well formed, and stations that asked for more than one sampling seed
//     for the same wipe and device (possible seed grinding) are listed.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"shunya/internal/checkpoint"
	"shunya/internal/logentry"
	"shunya/internal/note"
	"shunya/internal/tilestore"
	"shunya/internal/tlog"
)

var (
	// ErrInconsistent: the log is not an extension of what it published before.
	ErrInconsistent = errors.New("the log is not consistent with the checkpoint seen before: it rewrote, removed or reordered published entries")
	// ErrContent: the log's files do not match its own checkpoint.
	ErrContent = errors.New("the log's entries and tiles do not match its checkpoint")
)

// Result is a passed audit.
type Result struct {
	Checkpoint   checkpoint.Checkpoint
	Signed       []byte // the checkpoint to save as the new state
	Previous     *checkpoint.Checkpoint
	Entries      uint64
	Certificates int
	SeedRequests int
	Beacons      int
	// Repeated lists station/wipe/device triples with more than one seed request.
	Repeated []string
}

// Run audits the log in fsys. prev is the signed checkpoint saved by the last audit,
// or nil for the first one.
func Run(fsys fs.FS, key *note.Verifier, prev []byte) (*Result, error) {
	signed, err := fs.ReadFile(fsys, "checkpoint")
	if err != nil {
		return nil, err
	}
	cp, err := checkpoint.Open(signed, key)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	r := &Result{Checkpoint: cp, Signed: signed, Entries: cp.Size}
	var old checkpoint.Checkpoint
	if prev != nil {
		if old, err = checkpoint.Open(prev, key); err != nil {
			return nil, fmt.Errorf("saved checkpoint: %w", err)
		}
		r.Previous = &old
		if old.Size > cp.Size {
			return nil, fmt.Errorf("%w (it shrank from %d to %d entries)", ErrInconsistent, old.Size, cp.Size)
		}
	}
	entries, err := tilestore.ReadEntries(fsys, cp.Size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrContent, err)
	}
	tree := &tlog.Tree{}
	for _, e := range entries {
		tree.Append(e)
	}
	// The files must match the log's own checkpoint (catches tampering behind the
	// log's back) ...
	if err := tilestore.CheckTiles(fsys, tree, cp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrContent, err)
	}
	// ... and the checkpoint must extend the one seen before (catches a log that
	// rewrote its history and re-signed it: that passes the check above).
	if prev != nil && old.Size > 0 {
		proof, err := tree.ConsistencyProof(old.Size, cp.Size)
		if err != nil {
			return nil, err
		}
		if err := tlog.VerifyConsistency(old.Size, cp.Size, proof, old.Root, cp.Root); err != nil {
			return nil, fmt.Errorf("%w (%v)", ErrInconsistent, err)
		}
	}
	seeds := map[string]int{}
	for i, e := range entries {
		typ, payload, err := logentry.Split(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		switch typ {
		case logentry.TypeCertificate:
			r.Certificates++
		case logentry.TypeBeacon:
			r.Beacons++
		case logentry.TypeSeedRequest:
			r.SeedRequests++
			var q logentry.SeedRequest
			if err := json.Unmarshal(payload, &q); err != nil {
				return nil, fmt.Errorf("entry %d: seed request: %v", i, err)
			}
			if err := q.Verify(); err != nil {
				return nil, fmt.Errorf("entry %d: %w", i, err)
			}
			seeds[fmt.Sprintf("station %s, wipe %s, device %s", q.StationKeyID, q.WipeID, q.Fingerprint)]++
		}
	}
	for k, n := range seeds {
		if n > 1 {
			r.Repeated = append(r.Repeated, fmt.Sprintf("%s: %d seed requests", k, n))
		}
	}
	sort.Strings(r.Repeated)
	return r, nil
}
