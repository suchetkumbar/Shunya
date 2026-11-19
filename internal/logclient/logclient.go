// Package logclient talks to a Shunya transparency log (logserver) and checks every
// answer against the log's key before using it: a log that answers with a proof that
// does not verify is treated as an error, never trusted.
package logclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"shunya/internal/cert"
	"shunya/internal/logentry"
	"shunya/internal/logserver"
	"shunya/internal/manifest"
	"shunya/internal/note"
)

// maxResponse bounds anything read from the log (a full entry bundle is at most
// 256 × 64 KiB).
const maxResponse = 17 << 20

// ErrUnreachable: the log could not be reached or failed (network error, timeout,
// 5xx). The offline fallback applies only to this, never to a refusal.
var ErrUnreachable = errors.New("transparency log unreachable")

// ErrRefused: the log answered and refused the request (4xx).
var ErrRefused = errors.New("transparency log refused the request")

// Client is one log.
type Client struct {
	Base string // URL prefix, no trailing slash
	Key  *note.Verifier
	HTTP *http.Client
}

// New makes a client with a 20-second timeout.
func New(base string, key *note.Verifier) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), Key: key, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func (c *Client) do(ctx context.Context, method, path, ctype string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	if len(b) > maxResponse {
		return nil, fmt.Errorf("%w: response too large", ErrUnreachable)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return b, nil
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("%w: %s %s: %s", ErrUnreachable, method, path, resp.Status)
	}
	var e struct {
		Error string `json:"error"`
	}
	json.Unmarshal(b, &e)
	if e.Error == "" {
		e.Error = resp.Status
	}
	return nil, fmt.Errorf("%w: %s", ErrRefused, e.Error)
}

// Seed sends a signed seed request and returns the verified inclusion proof of the
// request, the seed it gives, and how many requests the log now holds for this wipe.
func (c *Client) Seed(ctx context.Context, q logentry.SeedRequest) (*logentry.Inclusion, []byte, int, error) {
	body, err := json.Marshal(q)
	if err != nil {
		return nil, nil, 0, err
	}
	b, err := c.do(ctx, http.MethodPost, "/seed", "application/json", body)
	if err != nil {
		return nil, nil, 0, err
	}
	var r logserver.SeedResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, nil, 0, fmt.Errorf("log answer: %v", err)
	}
	entry, err := q.Entry()
	if err != nil {
		return nil, nil, 0, err
	}
	if _, err := r.Inclusion.Verify(entry, c.Key); err != nil {
		return nil, nil, 0, fmt.Errorf("the log's answer does not verify: %w", err)
	}
	text, err := r.Inclusion.CheckpointText()
	if err != nil {
		return nil, nil, 0, err
	}
	return &r.Inclusion, logentry.Seed(text, q.Fingerprint), r.Requests, nil
}

// Submit logs a certificate file and returns it with the verified proof attached.
func (c *Client) Submit(ctx context.Context, file []byte) ([]byte, *logserver.AddResponse, error) {
	entry, err := cert.LogEntry(file)
	if err != nil {
		return nil, nil, err
	}
	b, err := c.do(ctx, http.MethodPost, "/add", "application/json", file)
	if err != nil {
		return nil, nil, err
	}
	var r logserver.AddResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, nil, fmt.Errorf("log answer: %v", err)
	}
	if _, err := r.Inclusion.Verify(entry, c.Key); err != nil {
		return nil, nil, fmt.Errorf("the log's answer does not verify: %w", err)
	}
	out, err := cert.WithLog(file, r.Inclusion)
	return out, &r, err
}

// SubmitManifest logs a batch manifest and returns it with the verified proof attached.
func (c *Client) SubmitManifest(ctx context.Context, file []byte) ([]byte, *logserver.AddResponse, error) {
	entry, err := manifest.LogEntry(file)
	if err != nil {
		return nil, nil, err
	}
	b, err := c.do(ctx, http.MethodPost, "/manifest", "application/json", file)
	if err != nil {
		return nil, nil, err
	}
	var r logserver.AddResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, nil, fmt.Errorf("log answer: %v", err)
	}
	if _, err := r.Inclusion.Verify(entry, c.Key); err != nil {
		return nil, nil, fmt.Errorf("the log's answer does not verify: %w", err)
	}
	out, err := manifest.WithLog(file, r.Inclusion)
	return out, &r, err
}

// FS presents the log's static files (checkpoint, tiles, bundles) as a read-only
// file system, for the auditor.
func (c *Client) FS(ctx context.Context) fs.FS { return httpFS{c, ctx} }

type httpFS struct {
	c   *Client
	ctx context.Context
}

func (h httpFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: errors.ErrUnsupported}
}

// ReadFile fetches one file (fs.ReadFile uses it).
func (h httpFS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	b, err := h.c.do(h.ctx, http.MethodGet, "/"+name, "", nil)
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	return b, nil
}
