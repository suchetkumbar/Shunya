# Architecture

> Status: Milestone 1 — device discovery implemented. Updated at every milestone.

Shunya is a verifiable secure data-wiping tool (SIH25070). It picks the strongest
NIST SP 800-88 method each medium supports, wipes it (including hidden areas), verifies
the result with samples the operator can't predict, and issues a signed certificate
recorded in a public append-only transparency log.

## Components

```
cmd/shunya           CLI + TUI: list (M1), plan, wipe, keys
cmd/shunya-verify    offline certificate verifier + `serve` (HTTP API, transparency log, web page)

internal/sysfs       sysfs/procfs readers over fs.FS (fakeable in tests)
internal/device      enumeration model, fingerprint, media classification (+ confidence)
internal/platform    OS layers: linux (SG_IO, NVMe admin ioctl), windows (DeviceIoControl)
internal/ata         ATA CDBs, IDENTIFY parsing, HPA/DCO, Security Erase
internal/nvme        Identify parsing, Format NVM, Sanitize
internal/backend     Target interface, FileBackend, BlockBackend, lab lock
internal/engine      NIST planner, overwrite pipeline, verification
internal/journal     signed append-only progress journal (crash-safe resume)
internal/jcs         RFC 8785 canonical JSON
internal/cert        certificate schema, signing, PDF, QR
internal/keys        root → station key hierarchy, revocation
internal/tlog        RFC 6962 Merkle tree, C2SP checkpoints, proofs
internal/canary      HMAC sector canaries + residue scanner (lab harness)
lab/                 QEMU lab scripts, capability probe, lab/check (result assertions)
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

`make lab-up && make lab-test && make lab-down` boots the VM, pushes the binaries over
SSH, runs them plus the capability probe, pulls results into `lab/results/` and stops the VM.
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
