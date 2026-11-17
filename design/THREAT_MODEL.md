# Threat model

> Status: Milestone 0 — skeleton. Each milestone fills in the mitigations it delivers;
> Milestone 11 completes the review.

## Assets
- Data on the drive being wiped (must become unrecoverable).
- Data on every *other* drive, especially the machine running Shunya (must be untouched).
- Integrity of wipe certificates and the transparency log.
- Station signing keys and the organisation root key.

## Adversaries and threats

| # | Threat | Mitigation (planned milestone) | Status |
|---|---|---|---|
| T1 | Tool wipes the wrong disk (bug, operator error) | Lab lock, boot/root/mounted/holder refusals, dry-run default, typed confirmation (M2) | planned |
| T2 | Drive swapped between selection and write (TOCTOU) | Identity re-check (serial + size) just before first write (M2) | planned |
| T3 | Overwrite misses remapped or over-provisioned flash cells | Media-aware planner; overwrite on flash labelled **Clear** with disclosure; prefer Sanitize/crypto erase (M3, M6) | planned |
| T4 | Hidden areas (HPA/DCO) left unwiped | Detect, temporarily remove HPA, wipe, record before/after state (M5) | planned |
| T5 | Dishonest operator verifies only sectors known to be clean | Verification seed derived from the transparency log checkpoint fetched *after* the wipe + device fingerprint (M8) | planned |
| T6 | Forged or edited certificate | Ed25519 signature over RFC 8785 canonical JSON; single-byte tamper test (M7) | planned |
| T7 | Back-dated, deleted or rewritten certificate | Append-only Merkle log, inclusion + consistency proofs, `audit` command (M8) | planned |
| T8 | Stolen station key | Root-certified station keys, signed revocation list (M7) | planned |
| T9 | Interrupted wipe reported as complete | Signed append-only journal on the tool's own medium; interruptions recorded in the certificate (M3) | planned |
| T10 | Firmware lies about erase completion | Independent read-back verification; honest disclosure that firmware erase can't be fully verified from outside (M4, M6) | planned |
| T11 | Certificate bound to the wrong drive | Device fingerprint from model, serial, WWN/EUI-64, firmware, native capacity (M1) | planned |
| T12 | Abuse of the public verifier | Rate limiting, input-size limits, structured logging (M8) | planned |

## Out of scope
- Physical destruction (NIST "Destroy").
- Attackers with physical access to the drive *before* the wipe.
- Firmware implants that survive a sanitize.
