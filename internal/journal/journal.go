// Package journal is Shunya's crash-safe progress journal: an append-only file of
// JSON lines, each record hash-chained to the previous one and signed with the
// station's Ed25519 key (brief §3.7).
//
// Properties:
//   - Append-only: Writer only appends; every record is fsynced before Append returns,
//     so a record that exists describes something that has already happened.
//   - Tamper-evident: record n carries the SHA-256 of line n-1 and a signature over its
//     own fields, and every line must be in canonical form. Editing, dropping, reordering
//     or inserting a record is detected (ErrTampered).
//   - Crash-tolerant: a power loss or kill -9 during an append can leave a final line
//     without its newline. Read reports it as a torn tail (TornBytes) instead of failing;
//     OpenAppend cuts it off before appending again. Damage anywhere else is tampering.
//
// The journal lives on the tool's own medium, never on the target (the engine checks).
// Canonical JSON (RFC 8785) and the station key hierarchy arrive in Milestone 7; until
// then the signing input is a fixed text encoding (see signingInput) and the key is a
// temporary development station key (GenerateKeyFile).
package journal

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// MaxLine bounds one record (the start record holds the whole plan).
const MaxLine = 1 << 20

var (
	// ErrTampered: the journal is not a valid, unmodified journal.
	ErrTampered = errors.New("journal tampered or corrupt")
	// ErrWrongKey: the journal was signed by a different key.
	ErrWrongKey = errors.New("journal signed by a different key")
)

// Record is one journal entry. Field order is the on-disk order.
type Record struct {
	Seq  uint64          `json:"seq"`
	Time string          `json:"time"` // RFC 3339, UTC, nanoseconds
	Type string          `json:"type"`
	Prev string          `json:"prev"` // hex SHA-256 of the previous line; "" for the first
	Key  string          `json:"key"`  // KeyID of the signing key
	Data json.RawMessage `json:"data"`
	Sig  string          `json:"sig"` // base64 Ed25519 signature over signingInput

	raw []byte // the line as read or written, without the newline
}

// Decode unmarshals the record's data.
func (r Record) Decode(v any) error { return json.Unmarshal(r.Data, v) }

// At parses the record time.
func (r Record) At() time.Time {
	t, _ := time.Parse(time.RFC3339Nano, r.Time)
	return t
}

// signingInput is what the signature covers: every field except the signature, with
// the data reduced to its hash. Fixed field order, newline-separated, versioned.
func signingInput(r *Record) []byte {
	h := sha256.Sum256(r.Data)
	var b bytes.Buffer
	b.WriteString("shunya-journal-v1\n")
	b.WriteString(strconv.FormatUint(r.Seq, 10) + "\n")
	b.WriteString(r.Time + "\n")
	b.WriteString(r.Type + "\n")
	b.WriteString(r.Prev + "\n")
	b.WriteString(r.Key + "\n")
	b.WriteString(hex.EncodeToString(h[:]))
	return b.Bytes()
}

func lineHash(line []byte) string {
	h := sha256.Sum256(line)
	return hex.EncodeToString(h[:])
}

// KeyID names a public key: "ed25519:" and the first 16 hex digits of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:8])
}

// Log is a verified journal.
type Log struct {
	Records   []Record
	KeyID     string
	TornBytes int   // bytes of an incomplete final line (crash during append), ignored
	GoodBytes int64 // length of the verified prefix
}

// Read verifies a journal against pub. A missing trailing newline on the final line is
// a torn tail, not an error; anything else wrong is ErrTampered (or ErrWrongKey).
func Read(r io.Reader, pub ed25519.PublicKey) (*Log, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("journal: bad public key")
	}
	log := &Log{KeyID: KeyID(pub)}
	br := bufio.NewReaderSize(r, 64<<10)
	prev := ""
	for n := 1; ; n++ {
		line, err := readLine(br)
		if err == io.EOF {
			if len(line) > 0 {
				log.TornBytes = len(line)
			}
			return log, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrTampered, n, err)
		}
		rec, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrTampered, n, err)
		}
		switch {
		case rec.Key != log.KeyID:
			// Indistinguishable from an edited key field, so it is both.
			return nil, fmt.Errorf("%w or %w: line %d names key %s, expected %s", ErrWrongKey, ErrTampered, n, rec.Key, log.KeyID)
		case rec.Seq != uint64(n):
			return nil, fmt.Errorf("%w: line %d has seq %d", ErrTampered, n, rec.Seq)
		case rec.Prev != prev:
			return nil, fmt.Errorf("%w: line %d does not chain to line %d", ErrTampered, n, n-1)
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(rec.Sig)
		if err != nil || !ed25519.Verify(pub, signingInput(rec), sig) {
			return nil, fmt.Errorf("%w: line %d: bad signature", ErrTampered, n)
		}
		log.Records = append(log.Records, *rec)
		log.GoodBytes += int64(len(line)) + 1
		prev = lineHash(line)
	}
}

// readLine returns the next line without its newline. At end of input it returns
// io.EOF together with any bytes after the last newline (a torn tail).
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxLine+1 {
			return nil, fmt.Errorf("line longer than %d bytes", MaxLine)
		}
		switch err {
		case nil:
			return line[:len(line)-1], nil
		case bufio.ErrBufferFull:
			continue
		case io.EOF:
			return line, io.EOF
		default:
			return nil, err
		}
	}
}

// parseLine decodes one line and requires it to be in canonical form (exactly what
// encodeRecord would write), so no byte can change without changing a signed field.
func parseLine(line []byte) (*Record, error) {
	var rec Record
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	if rec.Type == "" || len(rec.Data) == 0 {
		return nil, errors.New("missing type or data")
	}
	if _, err := time.Parse(time.RFC3339Nano, rec.Time); err != nil {
		return nil, fmt.Errorf("bad time: %v", err)
	}
	canon, err := json.Marshal(&rec)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canon, line) {
		return nil, errors.New("not in canonical form")
	}
	rec.raw = bytes.Clone(line)
	return &rec, nil
}

// Writer appends signed records to a journal file.
type Writer struct {
	mu    sync.Mutex
	f     *os.File
	key   ed25519.PrivateKey
	keyID string
	seq   uint64
	prev  string
	now   func() time.Time
}

// Create starts a new journal at path. It refuses to overwrite an existing file.
func Create(path string, key ed25519.PrivateKey) (*Writer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("journal: bad signing key")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	if err := lock(f); err != nil {
		f.Close()
		return nil, err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		f.Close()
		return nil, err
	}
	return newWriter(f, key, 0, ""), nil
}

// OpenAppend verifies an existing journal with key's public half, cuts off a torn tail
// and returns a Writer positioned after the last good record, plus the verified log.
func OpenAppend(path string, key ed25519.PrivateKey) (*Writer, *Log, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("journal: bad signing key")
	}
	f, err := OpenRegular(path, os.O_RDWR)
	if err != nil {
		return nil, nil, err
	}
	if err := lock(f); err != nil {
		f.Close()
		return nil, nil, err
	}
	log, err := Read(f, key.Public().(ed25519.PublicKey))
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if log.TornBytes > 0 {
		if err := f.Truncate(log.GoodBytes); err != nil {
			f.Close()
			return nil, nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, nil, err
		}
	}
	if _, err := f.Seek(log.GoodBytes, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, err
	}
	prev := ""
	if n := len(log.Records); n > 0 {
		prev = lineHash(log.Records[n-1].raw)
	}
	return newWriter(f, key, uint64(len(log.Records)), prev), log, nil
}

func newWriter(f *os.File, key ed25519.PrivateKey, seq uint64, prev string) *Writer {
	return &Writer{f: f, key: key, keyID: KeyID(key.Public().(ed25519.PublicKey)), seq: seq, prev: prev,
		now: time.Now}
}

// Append signs and writes one record and fsyncs the file before returning.
func (w *Writer) Append(typ string, data any) (Record, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return Record{}, os.ErrClosed
	}
	d, err := json.Marshal(data)
	if err != nil {
		return Record{}, err
	}
	rec := Record{Seq: w.seq + 1, Time: w.now().UTC().Format(time.RFC3339Nano), Type: typ, Prev: w.prev,
		Key: w.keyID, Data: d}
	rec.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(w.key, signingInput(&rec)))
	line, err := json.Marshal(&rec)
	if err != nil {
		return Record{}, err
	}
	if len(line) > MaxLine {
		return Record{}, fmt.Errorf("journal: record of %d bytes exceeds %d", len(line), MaxLine)
	}
	// One write call per record: a crash leaves at most one torn final line.
	if _, err := w.f.Write(append(bytes.Clone(line), '\n')); err != nil {
		return Record{}, fmt.Errorf("journal: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		return Record{}, fmt.Errorf("journal: %w", err)
	}
	rec.raw = line
	w.seq++
	w.prev = lineHash(line)
	return rec, nil
}

// Path returns the journal's file name.
func (w *Writer) Path() string { return w.f.Name() }

// Close closes the journal file (releasing its lock).
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// ErrNotRegular: a journal path that is not a regular file (a device node, symlink,
// directory, FIFO, ...). It is refused before anything is opened: a journal path must
// never become a way to open a device around the backend guards.
var ErrNotRegular = errors.New("journal must be a regular file")

// OpenRegular opens an existing journal file, refusing anything but a regular file
// (checked with Lstat before opening, and again on the open descriptor).
func OpenRegular(path string, flag int) (*os.File, error) {
	pre, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	if !pre.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is %v", ErrNotRegular, path, pre.Mode().Type())
	}
	f, err := os.OpenFile(path, flag|noFollow, 0)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	post, err := f.Stat()
	if err != nil || !os.SameFile(pre, post) {
		f.Close()
		return nil, fmt.Errorf("%w: %s changed while opening", ErrNotRegular, path)
	}
	return f, nil
}

// syncDir fsyncs a directory so a newly created file's directory entry is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return syncDirErr(err)
	}
	return nil
}
