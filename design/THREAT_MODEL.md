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
| T27 | Sanitize or Format erases other namespaces or another host's data | M6: refused unless the target is the only active namespace on a single-controller subsystem (CMIC bit 1, active NSID list, FNA bits 0–1) | mitigated (M6) |
| T28 | A drive claims an erase it can't do (QEMU completes crypto Format with FNA = 0) | M6: methods are offered and planned only from advertised capability bits; validation re-checks them | mitigated (M6) |
| T29 | An interrupted or earlier sanitize is certified | M6: resume waits for a sanitize still running; a completed one is accepted only when the NVMe controller attests Global Data Erased for the same action; otherwise (and always for ATA) it sanitizes again. Markers planted before the erase must all be gone | mitigated (M6, pending-real-hardware) |
| T30 | Firmware erase result can't be read back (crypto erase) | M6: 1024 HMAC markers at unpredictable positions must not survive; that shows the erase changed what the host reads, not that spare blocks were reached | partial (by design) |
| T31 | Emulated disk with a physical-looking identity earns Purge | M6: DMI hypervisor detection marks every disk of a VM virtual; found and fixed in the M6 lab run | mitigated (M6) |
| T32 | A certificate is edited (level, serial, result) | M7: Ed25519 over the canonical body; the file must be exactly canonical; every single-byte change fails (exhaustive test + fuzz) | mitigated (M7) |
| T33 | Two encodings of one certificate, or a member the verifier ignores (malleability) | M7: strict RFC 8785 parser (duplicates, surrogates, UTF-8); bodies must re-encode to their signed bytes. Found in testing: `encoding/json` accepted `"Certificate"` for `"certificate"` | mitigated (M7) |
| T34 | A signature for one document type is replayed as another | M7: domain-separated contexts per document type | mitigated (M7) |
| T35 | A stolen station key signs backdated certificates | M7: revocation `compromised` refuses every certificate of the key, whatever its date. M8: the log orders certificates, but revocation does not yet refer to log positions, so all of the key's certificates still fail | mitigated (M7) |
| T36 | Root key stolen from disk | M7: encrypted (PBKDF2-SHA256 600k + AES-256-GCM), kept offline; a stolen file still needs the passphrase. Hardware tokens later | partial (by design) |
| T37 | A verifier uses an old revocation list | Offline verification cannot know about newer lists; the list number is printed, lists only grow. M8: the server publishes its current list at `/revocations` (root-signed) | accepted (offline) |
| T38 | The PDF is edited and shown instead of the JSON | M7: the PDF is a pure rendering; `shunya-verify --pdf` re-renders and compares bytes; the QR code leads to the JSON's ID | mitigated (M7) |
| T39 | The operator picks a sampling seed that avoids dirty sectors | M8: the seed comes from a log checkpoint that covers the station's request and a random beacon of the log's, asked for after `done`; verifiers recompute it from the certificate | mitigated (M8) |
| T40 | Seed grinding: the station asks again until the positions suit it | M8: every request is a public log entry; the server counts them and `audit` lists repeats per station, wipe and device | detected (M8) |
| T41 | The log deletes, edits or reorders published entries and re-signs | M8: `audit` checks a consistency proof against the checkpoint it saved last time (the acceptance test rewrites and deletes leaves) | mitigated (M8) |
| T42 | Log files tampered behind the log's back | M8: startup and `audit` rebuild the tree from the entries and compare the root and every tile with the signed checkpoint | mitigated (M8) |
| T43 | A forged log answer (fake proof, other log's checkpoint) | M8: checkpoints must be signed by the configured log key and name its origin; inclusion proofs are verified before a seed or proof is used | mitigated (M8) |
| T44 | Split view: the log shows different trees to different clients | M8: only detected when auditors compare saved checkpoints; no witnesses/cosigners yet | open |
| T45 | Abuse of the public server (floods, huge bodies, path tricks, script injection on the page) | M8: per-client token bucket, 64 KiB/16 KiB body limits, timeouts, canonical tile paths only, html/template escaping, CSP `default-src 'none'`, loopback unless `--allow-public` | mitigated (M8) |
| T46 | Logged certificates expose device serials and station names | M8: the log is public by design; documented. Hashing or redacting serials would weaken what a recycler can check | accepted |
| T47 | Operator wipes the wrong disk in a busy session (wrong row, look-alike disks) | M9: protected disks unselectable; the plan screen names model, serial, size and method; the last 4 characters of each serial must be typed, in every build; the plan's method is pinned | mitigated (M9) |
| T48 | A fleet batch silently includes a disk nobody approved (a stray USB stick, a swapped drive) | M9: `--approved` fingerprint list required for `fleet --execute`; unlisted disks refused before opening and recorded as refused; the backend re-checks identity before the first write (M2) | mitigated (M9) |
| T49 | A batch hides its failures: the station shows only the certificates that succeeded | M9: the signed batch manifest lists every disk tried, with its outcome; it is logged (entry 0x04), and `shunya-verify manifest --certs` reports missing or mismatched certificates. A station can still skip writing a manifest at all | partly mitigated (M9) |
| T50 | Misleading or missing error guidance makes operators work around a guard (e.g. forcing a frozen drive) | M9: plain explanations for known refusals, with the safe remedy only; Shunya never applies a workaround itself (suspend/resume, hot-plug) | mitigated (M9) |
| T51 | One-click mode hides what is done | M9: the one-click screen still shows the method (in plain words and by name), its NIST level and the verification. The certificate is the same as in expert mode | mitigated (M9) |

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
- **M6: what markers prove.** After a firmware erase, markers show the sectors the host
  reads changed. They do not show that over-provisioned blocks were erased or that a key
  was destroyed. That rests on the drive's capability bits and SP 800-88's acceptance of
  the command. That is why Sanitize stays pending real hardware.
- **M7: what a certificate proves.** A valid certificate proves that a station the root
  certified signed this summary of its journal, and that nothing has changed since. It
  repeats what the journal and the read-back showed. It adds no evidence about the media
  itself. Its time is the station's own claim until the transparency log (M8) dates it.
- **M8: what the log proves.** An inclusion proof shows that the log, under its key,
  committed to this exact certificate at a position, and consistency proofs show that it
  never rewrote that past for any auditor who kept a checkpoint. A log seed shows the
  sample positions were fixed only after the station asked, once the wipe was recorded as
  done. Neither proves wall-clock time, and neither helps if the tool itself is modified
  to lie: that is what reproducible builds and the recorded build hash are for.
- **M9: what a batch manifest proves.** A valid manifest shows that this station signed
  this list of disks and outcomes at that time. With the log, it shows the list was never
  changed afterwards. It proves completeness only for the batches the station did
  manifest, and it adds no evidence about any one disk beyond that disk's certificate.
  The TUI and fleet mode change who selects and confirms; they add no new way to write.
