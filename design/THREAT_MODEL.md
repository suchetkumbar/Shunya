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
| T5 | Dishonest operator verifies only sectors known to be clean | M4: sampled verification derives positions from seed + device fingerprint with ChaCha8, always reads the first and last sector, and records the seed *and its source*; an `operator` seed is labelled as weak. M8: seed from a transparency-log checkpoint fetched *after* the wipe | partial (M4) |
| T6 | Forged or edited certificate | Ed25519 signature over RFC 8785 canonical JSON; single-byte tamper test (M7) | planned |
| T7 | Back-dated, deleted or rewritten certificate | Append-only Merkle log, inclusion + consistency proofs, `audit` command (M8) | planned |
| T8 | Stolen station key | Root-certified station keys, signed revocation list (M7) | planned |
| T9 | Interrupted wipe reported as complete | M3: signed, hash-chained, fsynced append-only journal on the tool's own medium; checkpoints only after Sync; Replay derives every interruption (clean, error, unclean stop) and refuses impossible histories; tested with SIGINT and kill -9 on images and on a lab block device. Certificates carry the list from M7 | mitigated (M3) |
| T10 | Firmware lies about erase completion | M4: independent read-back (full or sampled) of the expected pattern, recorded in the journal. A drive that remaps reads (returns the pattern from elsewhere) is outside what a host can check; disclosed. M6: firmware erase verification | partial (M4) |
| T11 | Certificate bound to the wrong drive | M1: `fp1` fingerprint from model, serial, WWID, firmware and sysfs capacity, marked `weak` with no serial or WWID (design/FINGERPRINT.md). M5: `fp2` with native capacity | partial (fp1) |
| T12 | Abuse of the public verifier | Rate limiting, input-size limits, structured logging (M8) | planned |
| T13 | Drive or USB bridge lies about its identity or media type | Classification records confidence and reasons, USB is never above medium, emulated devices are flagged `virtual`; a fingerprint detects swaps, not a forged identity (M1) | documented |
| T14 | Disk mounted in a namespace Shunya cannot see (container, other WSL distro, hypervisor) | M1: scans every mount namespace visible in /proc and always prints a warning. M2: exclusive open (O_EXCL) is refused by the kernel for any mounted or claimed device | mitigated (M2: lab test shows EBUSY for a mounted disk with the guard bypassed) |
| T15 | Journal edited to hide an interruption or claim progress that wasn't made | M3: every line signed; chained by SHA-256 to the previous line (catches records spliced in from another journal by the same key); canonical form required; seq checked. Tested: every single-byte flip, drop, reorder, duplicate, splice, wrong key. Residual: whoever holds the station key can write a whole new journal; M7 key custody and M8 log anchoring address that | mitigated (M3) |
| T16 | Journal path used to reach a device (`--journal /dev/sdX`) or the target itself | M3: journal paths must be regular files (lstat before open, O_NOFOLLOW, fstat SameFile); fresh journals use O_CREAT|O_EXCL; the journal's file system must not be the target or any of its partitions (st_dev), nor an image's loop mount. Lab test: all three commands refuse a device-node journal | mitigated (M3) |
| T17 | Random-pattern key exposure | The AES key only seeds the overwrite pattern; it protects nothing and is kept in the journal so resume and verification can regenerate the stream | accepted (by design) |
| T18 | Incomplete wipe (bug, skipped range) reported as complete | M4: full verify fails (exit 4) and is journalled; the lab canary harness proves the detection end to end with a deliberately broken build (`brokenwipe` tag, skips the last 1 %) — residue found only in the tail. The broken code exists only under that tag (constant 0 elsewhere) | mitigated (M4) |
| T19 | A "wiped" test that couldn't have failed (vacuous harness) | M4: each case first proves recovery works: canaries found, every marker on disk, photorec recovers every planted file intact (incl. deleted copies); otherwise the case FAILS as vacuous | mitigated (M4) |
| T20 | Data left in a Host Protected Area | M5: HPA detected (READ NATIVE MAX vs IDENTIFY), removed with a volatile SET MAX and wiped through ATA pass-through as part of the same plan, verification included; restored afterwards by default. `--hpa skip` is disclosed as "NOT wiped". Proven against the simulated drive only (QEMU has no HPA) | mitigated (M5, pending-real-hardware) |
| T21 | Data hidden by a DCO | M5: detected (DCO IDENTIFY) and disclosed with the uncovered range; never removed, because DCO changes are permanent. A DCO frozen by the BIOS is reported as "state unknown" | accepted, disclosed (M5) |
| T22 | Tool damages a drive permanently (DCO restore, permanent SET MAX, master password, firmware) | M5: those commands cannot be built in `internal/ata` and are refused again by `backend.CheckATA` on the raw CDB; tested for each | mitigated (M5) |
| T23 | Drive left locked by an interrupted Security Erase | M5: the password is journalled before SET PASSWORD; `shunya ata unlock` and `wipe --resume` use it; level High keeps the master password usable. The password is printable so hdparm can also be used | mitigated (M5) |
| T24 | An interrupted erase certified as complete | M5: resume never infers completion from the security state (a disabled password could be an operator's doing); it erases again. Normal erase can be read back for zeros | mitigated (M5) |
| T25 | Temporary password in the journal | It only unlocks this drive until the erase finishes, after which it is invalid; it is in the journal on purpose (T23). Protect the journal as you would the drive | accepted (by design) |
| T26 | ATA commands reach a different drive than the one selected (USB bridge, wrong path) | M5: IDENTIFY serial/model/WWN and size must match sysfs; behind USB, where they cannot be tied together, ATA is not used | mitigated (M5) |

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
- **M5: what a firmware erase proves.** A Security Erase is the drive's own claim. Shunya
  checks what it can: the security state before and after, and zeros after a normal erase.
  It cannot check a vendor pattern, spare-area coverage or a key change. That is why flash
  stays at Clear, and why everything ATA-specific beyond IDENTIFY is pending real hardware.
