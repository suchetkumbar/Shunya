# Certificates and the key hierarchy (Milestone 7)

A Shunya certificate is a signed statement about one wipe: which device, which method,
which NIST SP 800-88 level, how the result was checked, and who signed it. Anyone with the
organisation's root public key can verify it offline with `shunya-verify`.

## Key hierarchy

```
offline root key (root.key, passphrase-encrypted, never on a wiping station)
 ├─ signs ─▶ station certificate  "key ed25519:… may sign as station NAME from … to …"
 └─ signs ─▶ revocation list      numbered; each change makes a new, higher-numbered list
station key (station.key, 0600, on the wiping station)
 ├─ signs ─▶ progress journal records (Milestone 3)
 └─ signs ─▶ erasure certificates
```

| File | Where it lives | Format |
|---|---|---|
| `root.key` | offline machine only | JSON: PBKDF2-SHA256 (600 000 iterations, 16-byte salt) → AES-256-GCM over the Ed25519 seed. Every header field (format, KDF, iterations, salt, public key, key id) is the GCM additional data, so editing any of them fails like a wrong passphrase. |
| `root.pub` | every verifier | `shunya-root-public-key-v1 <64 hex digits>` |
| `revocations.json` | every verifier, republished on change | signed JSON (below) |
| `station.key` | the station | `shunya-station-key-v1 <base64 seed>` (M3–M6 files say `shunya-dev-station-key-v1` and still load) |
| `station.cert.json` | the station; embedded in each certificate | signed JSON (below) |

Commands (`shunya keys help`):

```
shunya keys init-root DIR                    # root.key, root.pub, revocations.json (list 1, empty)
shunya keys gen-station station.key          # on the station; prints the public key
shunya keys issue-station --root DIR/root.key --pub HEX --name bay-3 --days 365 --out station.cert.json
shunya keys revoke --root DIR/root.key --revocations DIR/revocations.json \
                   --key-id ed25519:… --reason retired|compromised [--at TIME]
shunya keys show [--root root.pub] FILE
```

The passphrase is read from the terminal without echo (`golang.org/x/term`), asked twice
at `init-root`, at least 12 characters. `--passphrase-file` is for scripts and the lab.

## Signatures

Every signature is Ed25519 over `context || 0x00 || JCS(document without "signature")`.
JCS is RFC 8785 canonical JSON (`internal/jcs`, tested against the RFC's vectors). The
contexts are:

| Document | Context |
|---|---|
| station certificate | `shunya/station-certificate/v1` |
| revocation list | `shunya/revocation-list/v1` |
| erasure certificate | `shunya/erasure-certificate/v1` |

The context makes a signature valid for exactly one kind of document. The signature covers
the members as they appear in the file, not a re-encoding. Parsers refuse unknown members,
missing members, duplicate members and misspelt member names. `encoding/json` matches
names case-insensitively, so a file saying `"Certificate"` would otherwise read as
`"certificate"`. The certificate tests found this.

## The certificate file

```
{"certificate":BODY,"log":null,"signature":"<base64>"}\n
```

The file must be exactly its own canonical form plus one newline. Anything else is refused,
even a change that keeps the JSON meaning. That is why changing any single byte fails
verification: `TestEverySingleByteChangeFails` flips every bit of every byte and deletes
every byte (21 862 variants of a 2.4 KB certificate), and `FuzzVerify` searches further.

- **Certificate ID:** hex SHA-256 of BODY's canonical bytes. The QR code holds
  `verify_url + ID`.
- **`log`:** `null`, or, once logged, the transparency-log inclusion proof
  `{"index":N,"checkpoint":"<signed checkpoint>","proof":["<base64>",…]}` (M8, see
  `TRANSPARENCY_LOG.md`). It sits outside the station's signature because it is added after
  signing; the log's signature on the checkpoint covers it. The logged entry is the file with
  `"log": null`, so logging changes neither the ID nor the PDF. `shunya-verify --log-key K`
  checks it; `--require-log` refuses certificates without one.

BODY (schema version 2 since M8; version 1 still verifies):

| Member | Content |
|---|---|
| `format`, `version` | `shunya-erasure-certificate`, 2 (1 for certificates issued before M8) |
| `wipe_id`, `issued` | the journal's wipe ID; issue time (RFC 3339 UTC, seconds) |
| `result` | always `erased-and-verified`: Shunya issues no certificate for less |
| `tool` | wiping and issuing tool versions, the SHA-256 of each executable (builds are reproducible, so anyone can rebuild and compare), build kind. `wipe_build_hash` is `""` for journals written before M7 |
| `device` | path, model, serial, WWID, size, fingerprint (fp2), native fingerprint (HPA), media type, virtual |
| `erasure` | method, NIST level, overwrite patterns (never their keys), bytes, sector size, start and finish, Security Erase and firmware steps (never the temporary password), the plan's caveats |
| `hidden_areas` | checked or why not, HPA size, whether it was wiped, DCO state, policy, final state |
| `verification` | every read-back: mode (full, sampled, markers), pattern, bytes, bad sectors, samples, seed and seed source (`operator`, `tlog-checkpoint`, `local-random`), 95 % bound, scope. Version 2, seed source `tlog-checkpoint` only: `seed_request` (the station's signed request) and `seed_log` (the log's checkpoint and the request's inclusion proof), from which any verifier recomputes the seed |
| `interruptions` | every stop and resume, with times |
| `journal` | SHA-256 of the signed journal, record count, signing key |
| `station` | key id, public key, name, and the root-signed station certificate (`null` for a dev key) |
| `verify_url` | `https://…`, or `http://127.0.0.1…`/`http://localhost…` for a local verifier; at most 100 characters. Default: the log's page (`LOG/c/`) when `--log` is given, else `https://verify.shunya.invalid/c/` (`.invalid` is reserved: a placeholder) |

The verifier also checks internal consistency:
- an overwrite is never Purge;
- a virtual disk is never Purge;
- every verification passed;
- the journal key is the certificate key;
- the method is a known one;
- the station certificate's key and name match;
- a log seed belongs to this wipe, device and station, was asked for no earlier than the
  erase finished, and is the seed its checkpoint gives (with the log key: the checkpoint is
  the log's and includes the request);
- an operator-chosen or locally drawn seed is reported as such.

## Issuing

`shunya wipe … --station-cert station.cert.json` issues `JOURNAL.cert.json` and
`JOURNAL.cert.pdf` when the wipe and its verification succeed. `shunya cert issue
--journal J --key K [--station-cert S]` issues later, including for journals from
Milestones 3–6. No certificate is issued, and the reason is printed, when:
- the wipe is not finished;
- no verification was recorded, or any verification failed (even if a later one passed);
- the HPA is still removed although the policy restores it;
- the journal was signed by another key;
- the station certificate is for another key or has expired.

Existing certificate files are never overwritten.

**Dev keys.** A certificate signed by a key the root never certified gets
`"station":{"certificate":null}`. Verifiers refuse it unless given `--allow-dev-key`, and
then report it. The PDF carries an "UNCERTIFIED DEVELOPMENT KEY" banner. This is how wipes
from M3–M6 can be certified, as agreed for M7.

## Revocation policy

| Reason | Certificates issued before `at` | Certificates issued from `at` on |
|---|---|---|
| `retired` | valid | refused |
| `compromised` | refused | refused |

A station asserts its own issue times. Someone holding a stolen key can therefore backdate a
certificate to before any revocation, so the only safe answer for a compromised key is to
distrust everything it signed. The M8 log orders certificates (an entry index can't be
backdated), but its checkpoints carry no time, and revocation lists don't yet refer to log
positions. So `compromised` still refuses every certificate of the key. Accepting those
logged before the compromise was reported ("compromised as of log size N") is a possible
later refinement.

A retired key can later be marked compromised; nothing can be downgraded or repeated. Lists
carry an increasing number. A verifier working offline cannot know whether a newer list
exists, so `shunya-verify` prints the number it checked. Verifying without a list needs
`--no-revocation-check` and is reported.

## The PDF

`internal/certpdf` renders the PDF from BODY and the ID only, and the PDF holds no data of
its own:
- **Determinism:** the same inputs give the same bytes, so `shunya-verify --pdf F` renders
  again and compares bytes.
- **Writer:** in-tree PDF 1.7 with the standard Helvetica and Courier fonts.
- **QR code:** an in-tree encoder (byte mode, level M, versions 1–10, all eight masks scored),
  drawn as vector rectangles.
- **Timestamp:** the CreationDate is the certificate's issue time.

Limits:
- **Characters:** the fonts are not embedded (not PDF/A), and characters outside
  WinAnsiEncoding print as `<U+XXXX>`. The JSON keeps the exact text.
- **Layout versions:** the layout is versioned (`certificate layout 1` in the Producer). A PDF
  made by another layout version cannot be compared, and the verifier says so. The JSON stays
  authoritative.

Independent checks, run in the lab (`TestLabCertificate`):
- `qpdf --check` (structure);
- `pdftotext` (the page shows the JSON's values);
- `pdftoppm` + `zbarimg` (the QR code decodes to exactly `verify_url + ID`).

## Verifying

```
shunya-verify --root root.pub --revocations revocations.json [--pdf cert.pdf] [--json] cert.json
```

- Works offline. It never opens a device.
- Exit codes: 0 valid, 1 invalid, 2 usage.
- `shunya cert show` runs the same check (`internal/certcheck`).

## Batch manifests (Milestone 9)

Fleet mode and the TUI sign one manifest per batch: `batch-<batch_id>.manifest.json` in the
journal directory (`internal/manifest`).

**Form:** the same as a certificate.
- The file is RFC 8785 canonical JSON plus a newline:
  `{"log": null | inclusion, "manifest": {...}, "signature": "..."}`.
- The signature is Ed25519, over the canonical body, with context
  `shunya/batch-manifest/v1`.
- It is signed by the station key that signed the batch's certificates.

**Body:**
- `format` "shunya-batch-manifest", `version` 1;
- `batch_id` (32 hex digits), `created`, `tool`;
- `station` (as in certificates);
- `items`, between 1 and 100.

**Each item:**
- the device's `path`, `model`, `serial` and `fingerprint`;
- the `method` and `nist_level`;
- its `outcome`: certified, not-certified, verify-failed, interrupted, failed or refused;
- the `wipe_id`;
- the `certificate_id`, present exactly when the outcome is certified;
- an `error` summary.

A device refused before it could be identified gets the fingerprint `unknown:<path>`.

**Verification** (`shunya-verify manifest`):
1. The canonical form and the signature.
2. Trust in the station under the same rules as certificates: root, validity, revocation,
   and dev keys only with `--allow-dev-key`.
3. The log proof, if one is attached.
4. With `--certs DIR`, every certified item needs a valid certificate with that ID, for
   the same fingerprint, wipe and station. Missing or mismatched ones make the batch
   **INCOMPLETE**, exit 1.

A manifest does not replace the certificates. Each certificate stands on its own.
