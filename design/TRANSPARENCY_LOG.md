# Transparency log and public verifier (Milestone 8)

Every certificate goes into an append-only Merkle-tree log. Anyone can check that a
certificate is in the log (inclusion proof) and that the log never rewrote its past
(consistency proof). The log also supplies the seed for sampled verification, so a
station cannot pick which sectors get read back.

## Formats (all standard, all implemented in-tree)

| Part | Standard | Package | Checked against |
|---|---|---|---|
| Merkle tree, proofs | RFC 6962 §2.1 hashing; RFC 9162 §2.1.3–2.1.4 verification | `internal/tlog` | transparency-dev/merkle vectors (196 inclusion/consistency cases, copied into `internal/tlog/testdata`, Apache-2.0); `golang.org/x/mod/sumdb/tlog` for every size up to 300 |
| Signed notes | C2SP `signed-note` (Ed25519, type 0x01) | `internal/note` | the spec's example key and note; x/mod's test keys and expected signature; x/mod signs byte-identically; fuzzing finds nothing that one accepts and the other rejects |
| Checkpoints | C2SP `tlog-checkpoint` (no extension lines) | `internal/checkpoint` | the spec's example; strict parsing (decimal, canonical base64) |
| Storage | C2SP `tlog-tiles` (256-hash tiles, `x001/x234/067` paths, partial `.p/W`, uint16-length entry bundles) | `internal/tilestore` | the spec's tile counts for sizes 70 000 and 256; x/mod tile paths and tile contents |

x/mod is used only by tests and is not linked into either binary (`go list -deps` shows it absent).

## Entries

One type byte, then the payload (`internal/logentry`):

| Type | Payload |
|---|---|
| `0x01` certificate | the certificate file's canonical envelope with `"log": null` (no newline) |
| `0x02` seed request | RFC 8785 JSON of a `SeedRequest`, signed by the station key (context `shunya/seed-request/v1`) |
| `0x03` beacon | 32 random bytes from the log |

## Unpredictable sampling (brief §3.3)

1. The wipe finishes and the journal records `done`.
2. The station signs a seed request with its key and sends it. The request holds the wipe ID, the fingerprint of the target being sampled, the SHA-256 of the journal so far, the time, and the station's key and certificate.
3. The log checks the request: the signature, a station certificate from the root, and that the station is not revoked. It then appends the request, appends a beacon of its own randomness, and signs a checkpoint covering both.
4. The station gets back the checkpoint and the request's inclusion proof, and checks both against the log key.
5. The seed is `SHA-256("shunya/sample-seed/v1" ‖ 0 ‖ checkpoint text ‖ 0 ‖ fingerprint)`. The sample positions come from the seed and the fingerprint, as in M4.
6. The `verified` journal record and the certificate (version 2) carry the request and the proof. A verifier then checks:
   - the request's signature;
   - that it names this wipe, this device and this station;
   - that it is dated no earlier than the erase's finish time;
   - that the seed is the one the checkpoint gives;
   - with the log key: that the checkpoint is the log's and includes the request.

**What this stops:** an operator choosing a seed whose positions avoid sectors they know are dirty. The beacon makes the checkpoint unknowable before the log answers.

**Seed grinding:** a station can ask again in the hope of better positions, but each request is a public log entry. The server counts them, and `audit` lists every station, wipe and device with more than one request.

**What it does not stop:**
- A station that lies about having finished: the tool is trusted to send the request only after `done`.
- A log that colludes with the station.

**Offline fallback (`--offline-seed`):**
- `full` (default): the whole target is read back instead.
- `local`: the tool draws a random seed itself. The certificate says `local-random`, and verifiers warn that nobody else can confirm the seed.

Only an unreachable log (network error, timeout, 5xx, 429) triggers the fallback. A refusal (4xx, such as a revoked station) is an error.

## Certificates in the log

`wipe --log URL --log-key K --station-cert S` or `shunya cert submit` sends the certificate to `POST /add`. The server verifies it fully, under the root and the revocation list, before logging it. A certificate already in the log is not added again.

The inclusion proof goes into the file's `"log"` member. It sits outside the station's signature and is covered by the log's checkpoint signature. Logging changes neither the certificate ID nor the PDF.

With `--log`, the QR URL defaults to the log's page, `URL/c/`. Plain `http` is accepted only for `127.0.0.1` or `localhost`, for demos and labs.

`shunya-verify --log-key K [--require-log]` checks the proof offline.

## Server (`shunya-verify serve`)

**Endpoints:**

| Endpoint | Returns |
|---|---|
| `GET /checkpoint` | the signed checkpoint |
| `GET /tile/…` | tiles and entry bundles (only canonical tile paths; never temporary files) |
| `GET /log.vkey` | the log's verifier key |
| `GET /revocations` | the root-signed revocation list the server checks against |
| `POST /add` | logs a certificate; returns its inclusion proof |
| `POST /seed` | logs a seed request; returns the checkpoint and proof |
| `GET /proof/{id}` | the inclusion proof of a logged certificate |
| `GET /consistency?from=N` | a consistency proof from size N to the current tree |
| `GET /cert/{id}` | the logged certificate, with its proof attached |
| `GET /c/{id}` | the recycler page: a VALID / INVALID / NOT FOUND verdict and the main fields |
| `GET /` | a form to look up a certificate by ID |

The recycler page has no JavaScript, and its content-security policy is `default-src 'none'`.

**Limits:**
- Rate limit: a token bucket per client address, 5 requests per second with bursts of 20 by default. A POST costs 5 tokens.
- Bodies: 64 KiB for `/add`, 16 KiB for `/seed`.
- Header and read/write timeouts.

**Logs:** one JSON line per request, holding the method, the path (no query string), the status, the size, the time taken and the client address. Bodies are never logged.

**Binding:** loopback only, unless `--allow-public` is given.

**Startup:** the server re-reads every entry and checks every tile against the checkpoint. It refuses to serve a log that fails this check.

**Revocation list:** updates take effect on restart.

## Storage and crash safety

`Append` writes the tiles and entry bundles first and syncs each file and directory. It writes the checkpoint last, atomically (temporary file, rename, directory sync). A crash therefore leaves the old checkpoint valid.

Files beyond the published checkpoint are leftovers from that crash and are overwritten on the next append. A file the published checkpoint covers is never changed; an attempt to change one is an error.

## Audit (`shunya-verify audit --log URL|DIR --log-key K --state FILE`)

The audit:
1. Checks the checkpoint signature.
2. Fetches every entry, rebuilds the tree, and checks it against the checkpoint's root and against every tile. This catches tampering behind the log's back.
3. Checks a consistency proof from the checkpoint saved by the last audit to the new one. This catches a log that deleted, edited or reordered published entries and re-signed everything; such a log passes step 2.
4. Checks every entry's form and every seed request's signature, and reports repeated seed requests.

The state file is replaced only after an audit passes.

## Known limits

- **Single log, no witnesses:** the log key alone vouches for each checkpoint. A split view (showing different trees to different clients) is detected only when auditors compare their saved checkpoints. C2SP cosignatures would remove this limit later.
- **No independent time:** checkpoints carry no timestamp. The log proves order (this entry came before that one), not wall-clock time, so `compromised` revocation still refuses every certificate of the key.
- **Personal data:** logged certificates are public and include device serials and station names.
- **Memory:** the whole tree is held in memory, about 64 bytes per entry plus the entries themselves. That is fine for a demo or one organisation, not for an Internet-scale log.
