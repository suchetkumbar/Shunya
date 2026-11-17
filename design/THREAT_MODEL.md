# Threat model

> Status: Milestone 2. Each milestone fills in the mitigations it delivers;
> Milestone 11 completes the review.

## Assets
- Data on the drive being wiped (must become unrecoverable).
- Data on every *other* drive, especially the machine running Shunya (must be untouched).
- Integrity of wipe certificates and the transparency log.
- Station signing keys and the organisation root key.

## Adversaries and threats

| # | Threat | Mitigation (planned milestone) | Status |
|---|---|---|---|
| T1 | Tool wipes the wrong disk (bug, operator error) | M1: discovery marks root/boot/self-binary disks PROTECTED and mounted/swap/holder/btrfs disks IN-USE, failing closed. M2: `backend.Check` refuses all of them plus partitions, read-only, logical and weak-identity devices; lab lock in dev builds; typed confirmation in release builds; O_EXCL; dry-run default. All tested on fakes and in the lab VM | mitigated (M2) |
| T2 | Drive swapped between selection and write (TOCTOU) | M2: the open descriptor must match the selected major:minor, size and sector sizes; a fresh enumeration just before the first write must match device number, serial, WWID, size and fingerprint, and the device must still be unused; on mismatch the target is dead. M3: the same re-check runs before every pass and after every checkpoint (each sync interval, 64 MiB by default), and `--resume` refuses unless the fingerprint matches the journal. Residual: a swap is noticed at the next checkpoint, not the next write; the open descriptor stays bound to the original disk (expected kernel behaviour, not yet tested with a QEMU hot-swap) | mitigated (M3) |
| T3 | Overwrite misses remapped or over-provisioned flash cells | M3: every overwrite plan is labelled **Clear** (never Purge) and lists what it can't reach per media type (design/NIST_MAPPING.md). Purge via Sanitize/crypto erase in M5–M6 | partial (M3: disclosure) |
| T4 | Hidden areas (HPA/DCO) left unwiped | Detect, temporarily remove HPA, wipe, record before/after state (M5) | planned |
| T5 | Dishonest operator verifies only sectors known to be clean | Verification seed derived from the transparency log checkpoint fetched *after* the wipe + device fingerprint (M8) | planned |
| T6 | Forged or edited certificate | Ed25519 signature over RFC 8785 canonical JSON; single-byte tamper test (M7) | planned |
| T7 | Back-dated, deleted or rewritten certificate | Append-only Merkle log, inclusion + consistency proofs, `audit` command (M8) | planned |
| T8 | Stolen station key | Root-certified station keys, signed revocation list (M7) | planned |
| T9 | Interrupted wipe reported as complete | M3: signed, hash-chained, fsynced append-only journal on the tool's own medium; checkpoints only after Sync; Replay derives every interruption (clean, error, unclean stop) and refuses impossible histories; tested with SIGINT and kill -9 on images and on a lab block device. Certificates carry the list from M7 | mitigated (M3) |
| T10 | Firmware lies about erase completion | Independent read-back verification; honest disclosure that firmware erase can't be fully verified from outside (M4, M6) | planned |
| T11 | Certificate bound to the wrong drive | M1: `fp1` fingerprint from model, serial, WWID, firmware and sysfs capacity, marked `weak` with no serial or WWID (design/FINGERPRINT.md). M5: `fp2` with native capacity | partial (fp1) |
| T12 | Abuse of the public verifier | Rate limiting, input-size limits, structured logging (M8) | planned |
| T13 | Drive or USB bridge lies about its identity or media type | Classification records confidence and reasons, USB is never above medium, emulated devices are flagged `virtual`; a fingerprint detects swaps, not a forged identity (M1) | documented |
| T14 | Disk mounted in a namespace Shunya cannot see (container, other WSL distro, hypervisor) | M1: scans every mount namespace visible in /proc and always prints a warning. M2: exclusive open (O_EXCL) is refused by the kernel for any mounted or claimed device | mitigated (M2: lab test shows EBUSY for a mounted disk with the guard bypassed) |
| T15 | Journal edited to hide an interruption or claim progress that wasn't made | M3: every line signed; chained by SHA-256 to the previous line (catches records spliced in from another journal by the same key); canonical form required; seq checked. Tested: every single-byte flip, drop, reorder, duplicate, splice, wrong key. Residual: whoever holds the station key can write a whole new journal; M7 key custody and M8 log anchoring address that | mitigated (M3) |
| T16 | Journal path used to reach a device (`--journal /dev/sdX`) or the target itself | M3: journal paths must be regular files (lstat before open, O_NOFOLLOW, fstat SameFile); fresh journals use O_CREAT|O_EXCL; the journal's file system must not be the target or any of its partitions (st_dev), nor an image's loop mount. Lab test: all three commands refuse a device-node journal | mitigated (M3) |
| T17 | Random-pattern key exposure | The AES key only seeds the overwrite pattern; it protects nothing and is kept in the journal so resume and verification can regenerate the stream | accepted (by design) |

## Out of scope
- Physical destruction (NIST "Destroy").
- Attackers with physical access to the drive *before* the wipe.
- Firmware implants that survive a sanitize.

## Notes per milestone
- **M2: who the lab lock stops.** It stops accidents: a dev binary run on the host, or a lab
  binary copied elsewhere. It does not stop a determined local root user, who can set DMI
  strings in a VM or read the token out of the binary. Release builds rely on typed
  confirmation and the absolute refusals instead.
- **M3: what the journal proves.** It shows what this station's key holder recorded,
  in order, with no edits. It does not prove the writes happened; read-back
  verification (`--verify` now, sampled with an unpredictable seed from M8) does that.
