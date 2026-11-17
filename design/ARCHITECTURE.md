# Architecture

> Status: Milestone 0 — skeleton. Updated at every milestone.

Shunya is a verifiable secure data-wiping tool (SIH25070). It picks the strongest
NIST SP 800-88 method each medium supports, wipes it (including hidden areas), verifies
the result with samples the operator can't predict, and issues a signed certificate
recorded in a public append-only transparency log.

## Components

```
cmd/shunya           CLI + TUI: list, plan, wipe, keys
cmd/shunya-verify    offline certificate verifier + `serve` (HTTP API, transparency log, web page)
cmd/shunya-hello     M0 smoke test: lists disks from sysfs (read-only)

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
lab/                 QEMU lab scripts and capability probe
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
