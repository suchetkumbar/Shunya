# Architecture

> Status: Milestone 3 — overwrite engine, progress journal and resume implemented. Updated at every milestone.

Shunya is a verifiable secure data-wiping tool (SIH25070). It picks the strongest
NIST SP 800-88 method each medium supports, wipes it (including hidden areas), verifies
the result with samples the operator can't predict, and issues a signed certificate
recorded in a public append-only transparency log.

## Components

```
cmd/shunya           CLI + TUI: list (M1), guard (M2), wipe, journal show, keys gen-dev (M3), plan
cmd/shunya-verify    offline certificate verifier + `serve` (HTTP API, transparency log, web page)

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
internal/cert        certificate schema, signing, PDF, QR
internal/keys        root → station key hierarchy, revocation
internal/tlog        RFC 6962 Merkle tree, C2SP checkpoints, proofs
internal/canary      HMAC sector canaries + residue scanner (lab harness)
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

- **Signing key:** temporary dev station key (`shunya keys gen-dev`, file mode 0600,
  refused if group- or world-readable) until the M7 key hierarchy.
