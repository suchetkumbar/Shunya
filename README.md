# shunya (शून्य, "zero")

A verifiable secure data-wiping tool for trustworthy IT asset recycling. Built for Smart
India Hackathon 2025, problem SIH25070.

> **Status: Milestone 0 (foundations and lab).** Nothing wipes anything yet.

## Goals
- Media-aware NIST SP 800-88 wiping (Clear / Purge / crypto erase): never claims more than it delivers.
- Hidden-area handling (HPA/DCO) on ATA drives.
- Verification samples chosen so the operator can't predict them.
- Signed certificates (JSON + PDF + QR) recorded in an append-only transparency log.
- Offline bootable image; one-click mode; fleet mode.

## Layout
See `design/ARCHITECTURE.md`. Safety rules: `design/SAFETY.md`.

## Building (Linux / WSL)
```sh
make lint test build        # static, reproducible binaries in bin/
```
On Windows, run any target through WSL: `.\scripts\wsl.ps1 test`.

## Lab
Destructive tests run only inside a disposable QEMU/KVM VM whose disks are image files:
```sh
make lab-up && make lab-test && make lab-down
```
See `design/LAB_CAPABILITIES.md` for what the lab can and cannot emulate.

## License
MIT. See `LICENSE`.
