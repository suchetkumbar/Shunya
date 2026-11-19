// Package checkpoint is the C2SP tlog-checkpoint format (c2sp.org/tlog-checkpoint):
// a signed note whose text is the log's origin, tree size and root hash, one per line.
//
//	shunya.example/log
//	20852163
//	CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=
//
//	— shunya.example/log <base64 signature>
//
// Shunya writes no extension lines and refuses checkpoints that have them: they are
// not auditable, and nothing here needs them.
package checkpoint

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"shunya/internal/note"
	"shunya/internal/tlog"
)

var ErrMalformed = errors.New("checkpoint: malformed")

// Checkpoint is a log's signed tree head.
type Checkpoint struct {
	Origin string
	Size   uint64
	Root   tlog.Hash
}

// Text is the note text.
func (c Checkpoint) Text() []byte {
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Root[:])))
}

// Sign returns the signed checkpoint. The log's key name must be its origin.
func Sign(c Checkpoint, s *note.Signer) ([]byte, error) {
	if s.Name != c.Origin {
		return nil, fmt.Errorf("%w: key %q is not the log origin %q", ErrMalformed, s.Name, c.Origin)
	}
	if _, err := ParseText(c.Text()); err != nil {
		return nil, err
	}
	return note.Sign(c.Text(), s)
}

// ParseText parses checkpoint text strictly: exactly three lines, a valid key-name
// origin, a decimal size without leading zeros, and a canonical base64 32-byte root.
func ParseText(text []byte) (Checkpoint, error) {
	lines := strings.Split(string(text), "\n")
	if len(lines) != 4 || lines[3] != "" {
		return Checkpoint{}, fmt.Errorf("%w: want exactly origin, size and root lines", ErrMalformed)
	}
	var c Checkpoint
	c.Origin = lines[0]
	if !note.ValidName(c.Origin) {
		return Checkpoint{}, fmt.Errorf("%w: origin %q", ErrMalformed, c.Origin)
	}
	n, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != lines[1] || n > 1<<62 {
		return Checkpoint{}, fmt.Errorf("%w: size %q", ErrMalformed, lines[1])
	}
	c.Size = n
	r, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil || len(r) != tlog.HashSize {
		return Checkpoint{}, fmt.Errorf("%w: root hash %q", ErrMalformed, lines[2])
	}
	c.Root = tlog.Hash(r)
	return c, nil
}

// Open verifies a signed checkpoint against the log's key, whose name must be the
// checkpoint's origin, and parses it.
func Open(signed []byte, log *note.Verifier) (Checkpoint, error) {
	n, err := note.Open(signed, log)
	if err != nil {
		return Checkpoint{}, err
	}
	c, err := ParseText(n.Text)
	if err != nil {
		return Checkpoint{}, err
	}
	if c.Origin != log.Name {
		return Checkpoint{}, fmt.Errorf("%w: origin %q signed by key %q", ErrMalformed, c.Origin, log.Name)
	}
	return c, nil
}
