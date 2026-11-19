# Architecture

> Status: Milestone 8 — transparency log, unpredictable sampling and the public verifier implemented. Updated at every milestone.

Shunya is a verifiable secure data-wiping tool (SIH25070). It picks the strongest
NIST SP 800-88 method each medium supports, wipes it (including hidden areas), verifies
the result with samples the operator can't predict, and issues a signed certificate
recorded in a public append-only transparency log.

## Components

```
cmd/shunya           CLI + TUI: list (M1), guard (M2), wipe, journal show (M3), verify (M4), plan (M6),
                     keys, cert (M7), cert submit and log-seeded --sample (M8)
cmd/shunya-verify    offline certificate verifier (M7); log-key, serve, audit (M8)

internal/sysfs       sysfs/procfs readers over fs.FS (fakeable in tests)
internal/device      enumeration model, fingerprint, media classification (+ confidence)
internal/platform    OS layers: linux (SG_IO, NVMe admin ioctl), windows (DeviceIoControl)
internal/ata         ATA CDBs, IDENTIFY parsing, HPA/DCO, Security Erase
internal/nvme        Identify parsing, Format NVM, Sanitize
internal/backend     Target interface, FileBackend, BlockBackend, lab lock
internal/engine      NIST planner, overwrite pipeline, verification
internal/journal     signed, hash-chained append-only progress journal (crash-safe resume)
internal/testutil    leakcheck: goroutine-leak checker for tests (in place of goleak)
internal/jcs         RFC 8785 canonical JSON
internal/cert        certificate schema, signing, verification policy
internal/certpdf     the certificate's PDF rendering (internal/pdf + internal/qr)
internal/certcheck   offline verification shared by shunya-verify and shunya cert
internal/pdf         minimal deterministic PDF 1.7 writer
internal/qr          QR Code encoder (byte mode, level M, versions 1–10)
internal/buildinfo   SHA-256 of the running executable
internal/keys        root → station key hierarchy, revocation
internal/tlog        RFC 6962 Merkle tree, inclusion and consistency proofs (RFC 9162 verification)
internal/note        C2SP signed notes (Ed25519)
internal/checkpoint  C2SP tlog-checkpoint
internal/tilestore   C2SP tlog-tiles log storage (crash-safe, self-checking)
internal/logentry    log entry types, seed requests, inclusion proofs, the sampling seed
internal/logserver   HTTP API, rate limit, recycler page
internal/logclient   station/auditor side; verifies every answer
internal/audit       full-log audit: content, consistency with the saved checkpoint, grinding
internal/canary      HMAC sector canaries, Aho-Corasick residue scanner, planted files,
                     carve inspection, harness report (lab/test tooling; the engine never imports it)
lab/                 QEMU lab scripts, capability probe, lab/check (result assertions),
                     lab/tests (block-device tests, -tags labtest, run as root in the VM)
design/              committed project documentation
```

Changes from the brief's suggested layout: `internal/sysfs`, `internal/jcs`,
`internal/journal` and `internal/canary` are split out, because each is reused by more
than one package and is easier to fuzz on its own. Committed docs live in `design/`
(`docs/` holds working notes and is gitignored).

## Build and environments

- Linux is the primary target. Builds are static (`CGO_ENABLED=0`, `-trimpath`,
  `-buildvcs=false`, `-ldflags=-s -w -buildid=`) with a pinned toolchain (`go.mod`
  `toolchain go1.27.4`) so two builds give identical binaries.
- The dev host is Windows; all builds, tests and the lab run inside WSL2 Debian
  (`scripts/wsl.ps1 <target>` forwards to `make`).
- CI (GitHub Actions) runs gofmt, vet, staticcheck, race tests, govulncheck and
  cross-builds. It never runs lab or destructive tests.

## Lab

```
Windows ─ WSL2 (nested KVM) ─ Debian ─ QEMU/KVM ─ Alpine lab VM
                                                   ├─ vda   boot (refused)
                                                   ├─ vdb   virtio target
                                                   ├─ sda   AHCI "HDD" target
                                                   ├─ sdb   AHCI "SSD" target
                                                   ├─ nvme0n1 NVMe target
                                                   └─ sdc   USB mass-storage target
```

`make lab-up && make lab-test && make lab-down` boots the VM, pushes the lab binaries over
SSH, runs them (and with `PROBE=1` the capability probe), pulls results into `lab/results/`
and stops the VM.
See `LAB_CAPABILITIES.md` for which hardware features the lab can emulate.

## Device discovery (Milestone 1)

`device.Enumerate(fs.FS)` reads only sysfs and procfs. It never opens a device node or
issues an ioctl, and it runs no commands. The `fs.FS` is `os.DirFS("/")` in production
and a fake tree in tests.

1. **Graph.** Every entry of `/sys/class/block` (disks and partitions) is resolved to its
   `/sys/devices/...` path and indexed by name, `major:minor` and dm name, together with its
   `holders/` and `slaves/`.
2. **Transport.** The transport comes from the elements of the resolved path, not from the
   device name:

   | Path element | Transport |
   |---|---|
   | `nvme` | NVMe |
   | `usbN` | USB (checked before ATA, because USB-SATA bridges have no `ataN`) |
   | `ataN` | SATA |
   | `mmc_host` | MMC |
   | `virtioN` | virtio |
   | `MSFT1000`/`VMBUS` | Hyper-V |
   | `hostN` + `sas_address` | SAS, otherwise SCSI |

3. **Identity.** Each subsystem stores identity in a different place:

   | Transport | Model | Serial | Firmware | WWID |
   |---|---|---|---|---|
   | NVMe | controller `model` | controller `serial` | `firmware_rev` | namespace `wwid` |
   | SCSI, SATA, USB | `device/model` | `device/vpd_pg80` | `device/rev` | `device/wwid` |
   | USB, no VPD serial | | USB descriptor `serial`, found by walking up the tree | | |
   | virtio | | `serial` | | |
   | MMC | `name` | `serial` | `fwrev` | `cid` |

4. **Use.** Every mount is traced down through partitions, dm and md to the disks under it
   (`root filesystem / via dm-1 (vg0-root) → dm-0 (luks-…) → sda2`). Swaps and btrfs
   members (`/sys/fs/btrfs/*/devices`) are traced the same way, and so are holders.
   - Mounts are read from this process's namespace, pid 1's, and every other mount
     namespace visible in `/proc`.
   - Root and `/boot`, `/boot/efi` or `/efi` in the initial namespaces → **PROTECTED**.
   - Any other mount, a swap, a btrfs membership or a holder → **IN-USE**.
   - Optical drives, ram disks and logical devices → **IGNORED**.
   - Anything else → **AVAILABLE**.
   - If `mountinfo` can't be read, enumeration fails instead of guessing.
5. **Classification.** Media type comes with a confidence level and the reasons behind it.
   USB is never better than medium confidence, and emulated devices are flagged `virtual`.
6. **Fingerprint.** `fp-v1`, specified in `FINGERPRINT.md`.

Fake trees are text specs in `internal/device/testdata/sysfs/*.spec`, loaded by
`internal/sysfs/sysfstest`. The scenarios are a workstation, LVM-on-LUKS, a server with
RAID1 and btrfs, the lab VM, and WSL. `make lab-test` runs `shunya list` in the VM and
`lab/check` asserts the result. `PROBE=1 make lab-test` also reruns the M0 capability probe.

## Backends and guards (Milestone 2)

```
             shunya guard /dev/X                      OpenBlock(env, /dev/X, opts)
                    │                                          │
                    ▼                                          ▼
backend.Check ── device.EnumerateWith(sysfs, protect=self-exe) ─┤ refused → RefusalError
  absolute refusals (every build)                               │ (device never opened)
  labLock()  dev: QEMU/KVM DMI + token   release: none          ▼
                                       Confirmation (release: required)
                                                                ▼
                                       open O_EXCL|O_CLOEXEC[|O_DIRECT|O_SYNC]  (RDONLY if dry-run)
                                                                ▼
                                       fstat/BLKSSZGET/BLKPBSZGET == selection, else ErrIdentityChanged
                                                                ▼
                                       first WriteAt/Discard: Check again + identity compare (TOCTOU)
```

- **Build kinds:**

  | Build | Tag | Lab lock | Confirmation | Lab token |
  |---|---|---|---|---|
  | dev | (none) | yes | no | none, so it refuses every device |
  | release | `release` | no | required | none |
  | lab | (dev) | yes | no | yes (`make build-lab`, never shipped) |

- **Testing without devices:** `blockOps` (open, probe, discard) is a struct of functions
  that tests replace, so guard logic runs on the host with no device node opened.
- **`Target` rules:** I/O must be sector-aligned and in range, and targets never grow.
  `O_DIRECT` buffers must be aligned (`AlignedBuffer`).
- **Verification:** `make test` and `make lint` run every package under all three tag sets
  (dev, release, labtest) and for Linux and Windows.

## Overwrite engine and journal (Milestone 3)

```
shunya wipe [--execute] DEVICE|--image F
  │  inspect: backend.Check (devices, sysfs only) or read-only FileBackend open (images)
  ▼
engine.NewPlan ── media → notes (Clear only, what is not reached), estimate
  │  no --execute: print plan, exit (device never opened)
  ▼
CheckJournalPlacement (journal not on the target or its partitions, not a device node)
GenerateKeys (one AES-256 key per random pass) → open target (all M2 guards)
journal.Create → start record {wipe id, tool, plan incl. keys}
  ▼
engine.Run
  generator g (×G) ── own free list of aligned buffers ──► out[g] ─┐  chunk i from out[i mod G]
                                                                   ▼
                                     writer: WriteAt → (every SyncEvery or end of pass)
                                             Sync → checkpoint record → Recheck (Block)
  ctx cancelled: stop before next write → Sync → "interrupted" record → ErrInterrupted
  I/O error / identity change: "error" record with the last synced offset
```

- **Patterns:** zero, one and random. Random is the AES-256-CTR keystream with a zero
  starting counter, so byte *i* of the disk is byte *i* of the stream and any range can be
  regenerated (`Fill(buf, off)` is a pure function). Tested against the NIST SP 800-38A
  F.5.5 vector.
- **Pipeline:** G generators (default 2), each owning B buffers (default 2) of
  `chunk_bytes` (default 4 MiB, 4 KiB-aligned for O_DIRECT); one in-order writer.
  - Separate free lists prevent a deadlock. With a shared pool, one generator could hold
    every buffer while the writer waits on another.
  - Progress is sent without ever blocking the writer, and Run closes the channel.
- **Durability rule:** a checkpoint is written only after `Sync` returns, so the journal
  never claims unsynced bytes. On cancel the writer syncs before recording, so the
  recorded offset is exact. Before the offset is this pass's pattern; after it, the
  previous pass's pattern (or the original data).
- **Mid-wipe identity check:** `backend.Block.Recheck` runs before each pass and after
  every checkpoint. It re-enumerates sysfs and compares device number, serial, WWID, size
  and fingerprint. A mismatch kills the target, and the wipe stops with an "error" record.
- **Journal format:** JSON lines. Each record has seq, time, type, prev (SHA-256 of the
  previous line), key ID, data and an Ed25519 signature over a fixed text encoding.
  - Lines must be in canonical form, so no byte can change without breaking a signature
    or the chain.
  - Every append is fsynced, and the journal file is flocked.
  - A final line without its newline is a *torn tail*: a crash during an append. It is
    reported and cut off on resume. Damage anywhere else is `ErrTampered`.
- **Replay:** `engine.Replay` checks the history is one the engine could have written
  (positions move forward, passes complete in order, a stop is followed only by a resume)
  and derives the state and the list of interruptions:
  - **interrupted:** clean cancel, such as Ctrl-C or SIGTERM;
  - **error:** an I/O error;
  - **unclean-stop:** a crash, kill -9 or power loss, with no stop record.
- **Resume:** `shunya wipe --resume` verifies the journal and replays it.
  - It refuses unless the target's fingerprint equals the plan's, re-runs every guard and
    the placement check, then appends a "resumed" record.
  - It continues from the last synced offset, using the same keys.
- **Exit codes:**

  | Code | Meaning |
  |---|---|
  | 0 | done |
  | 1 | error |
  | 2 | usage |
  | 4 | verification failed |
  | 5 | interrupted, resumable |

- **Signing key:** station key (`shunya keys gen-station`; `gen-dev` is the M3 name), file
  mode 0600, refused if group- or world-readable. Certified by the root from M7.

## Verification and the forensic canary harness (Milestone 4)

- **Full read-back:** `engine.Verify` reads the whole target and compares it with the
  last pass's pattern, sector by sector.
- **Sampled verification:** `engine.VerifySampled` reads *n* sectors.
  - Positions come from ChaCha8 keyed with SHA-256("shunya-sample-v1" ‖ seed ‖
    fingerprint). The same seed gives different positions on different drives.
  - The first and last sectors are always read.
  - The result states its guarantee: with *n* samples, an unwiped share
    ≥ 1 − 0.05^(1/n) is caught with 95 % probability (n = 3000 → 0.1 %).
  - The seed source is recorded. `operator` (`--seed`) is weak, because the station
    picks it. `tlog-checkpoint` (M8) is a checkpoint fetched after the wipe.
- **Recording:** every verification appends a signed `verified` record. It is allowed
  only after `done` and may repeat. `shunya verify --journal J --key K [--sample N --seed HEX]`
  re-verifies later with a read-only open, after every guard and the fingerprint check.
  Exit code 4 means a mismatch.
- **Canary harness** (`internal/canary`):

  | Part | What it does |
  |---|---|
  | Canaries | 32-byte tokens: run magic (8) ‖ sector, index (8) ‖ HMAC-SHA256(key, sector)[:16] with the index folded in. Unique, name their sector, can't be forged; any fragment of 32+ bytes holds a whole token |
  | Scanner | Aho-Corasick over the canary magic plus every planted-file marker, streamed in chunks (the automaton state carries across chunk boundaries). Every byte offset is checked; each magic hit is HMAC-validated into *tokens*, *displaced* (found away from their sector) or *partial* |
  | Planted files | JPEG, PDF and DOCX generated in code. Each carries a unique marker, stored uncompressed. The DOCX zip has sizes and CRCs up front, without data descriptors, because photorec rejects stored entries with descriptors |
  | Carve inspection | Matches every carved file against the planted ones by marker and by SHA-256 |
  | Evaluate | Before the wipe, requires canaries, every marker and every planted file recovered intact (otherwise the test was *vacuous* and fails). After the wipe, requires nothing at all. The broken case requires residue, all in the skipped tail, plus a failing verify |
  | Report | `canary-report.json` + `.txt` |

- **Broken wipe (negative test):** in the `brokenwipe` build tag, `brokenTailPercent = 1`
  and the writer skips the last 1 % while journalling success. Everywhere else it is the
  constant 0 and the branch is compiled out. Only `bin/lab/shunya-broken` is built with it.
- **Lab flow** (`lab/tests/canary_lab_test.go`), for each disk × file system:
  1. Plant canaries over the whole disk.
  2. mkfs (`-E nodiscard`), store the planted files, delete one copy of each, umount.
  3. Scan, plus photorec ("before").
  4. `shunya wipe --execute`, then `shunya verify`.
  5. Drop caches, scan, plus photorec ("after").

## ATA layer: IDENTIFY, hidden areas, Security Erase (Milestone 5)

```
cmd/shunya (wipe --method, --hpa; ata identify|hidden|unlock)
   │  ata.Device{T: Transport}            ata.SecureErase / ProbeHidden / SetMaxVolatile
   ▼
internal/ata   Command → ATA PASS-THROUGH(16) CDB ─────► Transport.PassThrough(cdb, data)
   ▲              sense data ◄── ParseSense (descriptor 0x72 / fixed 0x70)        │
   │                                                                              ▼
   │                              backend.Block.PassThrough: CheckATA allowlist,
   │                              --execute + TOCTOU re-check for mutating commands,
   │                              SATA/USB transports only → SG_IO ioctl (Linux)
   └── internal/ata/atafake: simulated drive answering the same CDB bytes (tests)
```

- **Commands are built, never typed.** `internal/ata/commands.go` has one constructor per
  command Shunya uses: IDENTIFY, READ NATIVE MAX ADDRESS EXT, SET MAX ADDRESS EXT
  (volatile only), DCO IDENTIFY, READ/WRITE DMA EXT (≤ 256 sectors), FLUSH CACHE EXT and
  the user-password Security commands. CDBs follow SAT-4; IDENTIFY matches `sg_sat_identify`
  byte for byte. Non-data commands set CK_COND so the registers come back.
- **Defence in depth.** `backend.CheckATA` re-checks the raw CDB bytes and data buffer
  against its own allowlist. It refuses DCO SET/RESTORE/FREEZE, a non-volatile SET MAX,
  SECURITY FREEZE LOCK, master passwords, level Maximum, SANITIZE, DOWNLOAD MICROCODE and
  everything vendor-specific. Read-only commands work on a dry-run target; mutating ones
  need `--execute` and pass the same TOCTOU re-check as the first write.
- **IDENTIFY parser** (`identify.go`): strings (two characters per word, high byte first),
  28- and 48-bit capacity, validity signatures of words 83/84/86/87 (feature bits are
  trusted only when valid), WWN, logical/physical sector size (word 106/117–118), HPA, DCO,
  Security word 128 and erase times 89/90 (both formats), rotation rate, TRIM, Sanitize
  bits, the word-255 checksum. Also reads and writes the `hdparm --Istdout` text form.
  Tested on four public real-drive dumps against the hdparm output published with them
  (`internal/ata/testdata/identify/SOURCES.md`), on QEMU's drives in the lab, and fuzzed.
- **Hidden areas** (`hidden.go`): `ProbeHidden` compares IDENTIFY's size with READ NATIVE
  MAX (HPA) and DCO IDENTIFY's factory size (DCO). `HiddenArea` goes into the plan and
  into every `hidden-area` journal record.
- **HPA wipe:** with `--hpa restore` (the default) or `leave-removed`:
  1. A volatile SET MAX to the native size, always immediately after READ NATIVE MAX.
  2. `ata.Span` joins the kernel's block device (unchanged size: no rescan is
     triggered) with `ata.RangeTarget`, which reaches the hidden sectors through READ/WRITE
     DMA EXT.
  3. The engine wipes, checkpoints, resumes and verifies the whole native range as one
     target.
  4. The HPA policy runs after a completed wipe.

  A failed restore is journalled (`hpa-restore-failed`) and returns by itself at power-off.
  `--hpa skip` keeps the HPA and says "NOT wiped" in the plan.
- **DCO:** detected only. Removing one is permanent, so the plan states the uncovered range.
- **Security Erase** (`security.go`, `--method ata-secure-erase | ata-enhanced-secure-erase`):
  1. Check preconditions: supported; not frozen (the refusal explains the suspend/resume
     and hot-plug workarounds, which Shunya never applies itself); no foreign password;
     attempt counter not expired; enhanced mode supported if asked.
  2. Set a temporary random user password, level High.
  3. ERASE PREPARE, then ERASE UNIT with a timeout of twice the drive's estimate plus 30 min.
  4. IDENTIFY; DISABLE PASSWORD if the password is still set; check it is gone.

  Each step is journalled before it runs, including the password, so `shunya ata unlock`
  can recover a drive left locked. If an HPA exists it is removed first: some drives erase
  only up to the current max.
- **Resume never infers completion.** A drive without a password after ERASE UNIT was
  sent may have been erased, or an operator may have disabled the password on an
  interrupted erase. The resume therefore erases again: it costs time, but a false
  "erased" would certify live data. A drive power-cycled mid-erase comes up locked; resume
  unlocks it with the journalled password before touching the HPA (a locked drive aborts SET MAX).
- **NIST level:** ATA Security Erase on a real rotating disk is Purge. On flash, a virtual
  disk or behind a USB bridge it is Clear. A plan claiming Purge elsewhere fails validation.
  A normal erase writes zeros and can be verified; an enhanced erase leaves a vendor
  pattern, so `--verify` is refused for it.
- **Identity:** IDENTIFY's serial, model (INQUIRY truncates it to 16 characters) and WWN
  must match sysfs, and its size must match the kernel's (otherwise someone changed the
  max address in this power cycle). Behind USB the ATA identity can't be tied to the
  selected device, so ATA is not used there. Fingerprint v2 (`fp2:`) adds the native
  capacity to v1's fields and is recorded in the plan.
- **Simulated drive** (`internal/ata/atafake`): starts from a real IDENTIFY dump and
  decodes the CDB bytes. It keeps HPA, DCO and Security state (SEC0–SEC6: enabled, locked,
  frozen, attempt counter, power cycle) and sector contents. It can inject faults: no SAT,
  fixed sense, frozen at boot, one SET MAX per power cycle, power loss before any command.
  By default an erase covers only up to the current max, the worst case.

## NVMe layer, ATA SANITIZE and the planner (Milestone 6)

```
cmd/shunya: plan DEVICE · nvme identify|sanitize-log · wipe --method <firmware method>
   │ probeNVMe / probeHidden → engine.Recommend → engine.NewFirmwarePlan
   │ firmwareWipe: markers → erase → done → marker check → pattern verify → HPA policy
   ▼
internal/nvme  Command{AdminCmd = struct nvme_passthru_cmd} → Transport.AdminCommand
internal/ata   SANITIZE DEVICE (B4h) commands + SanitizeOp
internal/sanitize  Run(Operation): start, poll, journal, resume — shared by NVMe and ATA
   ▼
backend.Block.AdminCommand: CheckNVMe allowlist on the raw fields, --execute + TOCTOU
re-check for Format/Sanitize, NVMe transport only → NVME_IOCTL_ADMIN_CMD (Linux)
internal/nvme/nvmefake: simulated controller from the lab's recorded QEMU Identify data
```

- **NVMe commands** (`internal/nvme/cmd.go`):
  - Identify (CNS 0, 1, 2), Get Log Page 81h (Sanitize Status), Format NVM and Sanitize.
  - Format NVM uses SES 1 (user data) or 2 (crypto), one namespace only. It repeats the
    namespace's current LBA format, metadata and protection settings, so nothing changes
    but the data.
  - Sanitize does block erase, crypto erase or overwrite, never with auto-restart or
    no-deallocate.
  - `AdminCmd` is the kernel's 72-byte struct; a compile-time check pins the size.
  - Field offsets and bit layouts were cross-checked against libnvme's `types.h` and
    `ioctl.h` (consulted, not copied).
- **Parsers** (`identify.go`):
  - Identify Controller: VID, serial, model, firmware, OUI, CMIC, version, OACS, TNVMCAP,
    SANICAP, NN, FNA, SubNQN.
  - Identify Namespace: sizes, LBA formats including the 6-bit format index, metadata, PI,
    NMIC, DLFEAT (what deallocated blocks read as), EUI-64, NGUID.
  - Also the active NSID list and the Sanitize Status log (progress, status, Global Data
    Erased, last CDW10, time estimates).
  - Tested field by field against nvme-cli's decoded output of the same QEMU drive, and fuzzed.
- **Refusals** (`ops.go`):
  - Sanitize always acts on the whole subsystem. A Format whose FNA says it applies to all
    namespaces does too. Shunya refuses either when the controller has more than one active
    namespace, or when the subsystem has several controllers (CMIC bit 1).
  - Crypto Format needs FNA bit 2. QEMU completes SES=2 "successfully" with FNA = 0;
    Shunya trusts the capability bit, not the status.
- **ATA SANITIZE** (`internal/ata/sanitize.go`):
  - CRYPTO SCRAMBLE, BLOCK ERASE and OVERWRITE EXT, each with its ACS key in the LBA field.
  - SANITIZE STATUS EXT reports progress, completion, failure (ABRT) and the
    sanitize-frozen state, which Shunya explains and refuses.
  - FREEZE LOCK and ANTIFREEZE can't be built; `CheckATA` refuses them, wrong keys and
    the failure-mode bit.
- **Shared sanitize loop** (`internal/sanitize`):
  - Records `sanitize-started` before sending the start command, then polls (5 s) and
    records progress every 10 % or 5 minutes.
  - On resume:
    - **Still running:** wait, never start a second one.
    - **Completed and attested:** stop. Attested means the drive reports Global Data Erased
      (nothing written since a successful sanitize) and its last sanitize used this action.
    - **Anything else:** sanitize again. A "completed" status may be an earlier sanitize's;
      ATA has no attestation, so ATA always sanitizes again.
  - A sanitize this journal didn't start is refused. A failure is reported, with the
    drive's failure mode explained.
- **Markers** (`engine/markers.go`): before any firmware erase, 1024 sectors are
  overwritten with HMAC-SHA256(key, "shunya-marker-v1" ‖ LBA) blocks.
  - Positions come from `SamplePositions` with a random seed and the fingerprint; the
    first and last sector are always included.
  - Afterwards `CheckMarkers` requires that none still reads back. This is the only content
    check possible after a crypto erase.
  - The result is a `verified` record with mode `markers`.
- **Plans** (`engine/firmware.go`):
  - `NewFirmwarePlan` covers all ten firmware methods (the ATA Security Erase pair now
    goes through it too).
  - **Level:** virtual → Clear. ATA Security Erase → Purge only on a real rotating disk.
    Sanitize and NVMe Format with secure erase → Purge. A Purge claim elsewhere fails
    validation.
  - **Expected pattern:** zeros after a normal Security Erase or an overwrite sanitize.
    After a block erase or user-data Format, whatever DLFEAT says deallocated blocks read
    as. Crypto: none.
  - Validation re-checks support against the capabilities recorded in the plan.
- **Journal:** `firmware` records hold `markers-planted`, `format-started/-completed` and
  the sanitize events. Replay rejects:
  - an erase event before the markers are planted
  - an event of the wrong kind
  - `done` before the drive reported completion, or without the markers planted
- **Planner** (`engine/recommend.go`, `shunya plan`):
  - Lists every method in preference order, with level, availability and the reason.
  - NVMe: Sanitize crypto > block > Format crypto > Format user data > Sanitize overwrite
    > overwrite.
  - ATA: Sanitize crypto > block > overwrite > Security Erase enhanced > normal > overwrite.
  - Best is the first available Purge method, else the strongest Clear method.
  - It only recommends; `--method` stays explicit (the one-click mode, M9, may apply it).
- **Virtual machines** (`device.markHypervisor`, found in the M6 lab run): when DMI says
  the machine is a VM, every physical-looking disk is treated as emulated. The lab's SATA
  disks have custom model strings and looked physical before. A passed-through disk is
  under-claimed, never over-claimed.

## Certificates and the key hierarchy (Milestone 7)

Full design: `CERTIFICATES.md`. In short:

- `internal/jcs` is RFC 8785 with a strict parser. It refuses duplicate members, lone
  surrogates, invalid UTF-8, out-of-range numbers and depth over 64. `Marshal` also refuses
  integers beyond 2^53.
- `internal/keys` holds three things:
  - the root key file (PBKDF2-SHA256 → AES-256-GCM, header bound as AAD);
  - station certificates;
  - numbered revocation lists.

  Every signature is over context ‖ 0 ‖ JCS.
- `internal/cert` holds the schema, `Sign` and `Verify`. A file must be exactly its canonical
  form. The signature covers the body's bytes as they are, and the body must re-encode to
  those bytes (no unknown, missing, defaulted or case-mismatched members). The verifier
  checks the policy: station chain, validity, revocation, dev key, and consistency (no Purge
  for an overwrite or a virtual disk).
- `engine.BuildCertificate` summarises a replayed journal. It copies no secrets: pattern
  keys, marker keys and the ATA password stay in the journal. It refuses unfinished,
  unverified or failed wipes and a pending HPA restore. The journal's start record now holds
  the wiping executable's SHA-256 (`build_hash`).
- `internal/certpdf` is a pure function of the body and its ID. `shunya-verify --pdf`
  re-renders and compares bytes.
- `wipe --station-cert` issues `JOURNAL.cert.json` and `.cert.pdf` after a verified wipe.
  `cert issue` does it later.

Exit codes added: `cert issue` returns 4 when the journal is not certifiable;
`shunya-verify` returns 0 valid, 1 invalid, 2 usage.

## Transparency log and the public verifier (Milestone 8)

Full design: `TRANSPARENCY_LOG.md`. In short:

- `internal/tlog` keeps every complete subtree hash in memory and builds RFC 6962 inclusion
  and consistency proofs; verification follows RFC 9162. A consistency proof from the empty
  tree is refused (it proves nothing), as in transparency-dev/merkle.
- `internal/note` and `internal/checkpoint` are the C2SP formats; `internal/tilestore`
  writes C2SP tiles and entry bundles, the checkpoint last, and checks everything on load.
- `internal/logentry`: certificates, signed seed requests and random beacons. The seed is
  SHA-256 over a checkpoint that covers the request and a beacon.
- The station (`cmd/shunya/logseed.go`) asks for the seed after `done`. It falls back to a
  full read-back (or, if chosen, a local random seed) only when the log is unreachable, and
  submits the certificate after issuing it. The proof goes in the envelope's `log` member.
- `cert.Verify` checks log proofs and log seeds with `Policy.LogKey`; certificate version 2
  adds `seed_request`/`seed_log` to sampled verifications.
- `internal/logserver` is `shunya-verify serve`; `internal/audit` is `shunya-verify audit`,
  over HTTP (`logclient.FS`) or a directory.
