# shunya (शून्य, "zero")

A verifiable secure data-wiping tool for trustworthy IT asset recycling. Built for Smart
India Hackathon 2025, problem SIH25070.

> **Status: Milestone 3 (overwrite engine, NIST Clear).** `shunya wipe` overwrites a disk or image with a crash-safe, signed progress journal and can resume after Ctrl-C, kill -9 or power loss. It is a dry run unless `--execute` is given.

## Goals
- Media-aware NIST SP 800-88 wiping (Clear / Purge / crypto erase): never claims more than it delivers.
- Hidden-area handling (HPA/DCO) on ATA drives.
- Verification samples chosen so the operator can't predict them.
- Signed certificates (JSON + PDF + QR) recorded in an append-only transparency log.
- Offline bootable image; one-click mode; fleet mode.

## Layout
See `design/ARCHITECTURE.md`. Safety rules: `design/SAFETY.md`. Levels and what each
method can't reach: `design/NIST_MAPPING.md`.

## Building (Linux / WSL)
```sh
make lint test build        # static, reproducible binaries in bin/
./bin/linux-amd64/shunya list          # read-only: disks, media type, PROTECTED/IN-USE
./bin/linux-amd64/shunya list --json   # full detail: partitions, holders, mounts, fingerprint
./bin/linux-amd64/shunya guard /dev/sdb  # would the safety guards allow it? (never opens it)
```
On Windows, run any target through WSL: `.\scripts\wsl.ps1 test`.

## Wiping (Milestone 3)
Flags go before the device. Try it on an image file (dev builds refuse every block
device outside the lab VM). The station key must be mode 0600 and is refused otherwise,
so on WSL use a Linux directory: drives under `/mnt/` have no Unix permissions.
```sh
D=$(mktemp -d) && truncate -s 256M $D/disk.img
shunya keys gen-dev $D/station.key                   # temporary key until Milestone 7
shunya wipe --image $D/disk.img                      # dry run: prints the plan, writes nothing
shunya wipe --execute --verify --journal $D/wipe.journal --key $D/station.key --image $D/disk.img
#   Ctrl-C (or kill -9) part-way, then:
shunya wipe --resume --execute --verify --journal $D/wipe.journal --key $D/station.key
shunya journal show --key $D/station.key $D/wipe.journal   # verified history, interruptions
rm -r $D
```
- **Default:** one pass of an AES-256-CTR random stream, NIST SP 800-88 **Clear**.
- **Other patterns:** `--pattern zero,one,random` or `--passes N`. They are accepted but
  are not required by NIST.
- **Other tests:**
  - `make test-big` wipes and byte-checks a 1 GiB + 4095-sector image.
  - `make bench` runs the throughput benchmarks.

### Throughput
`make bench`, Go 1.27.4, i7-12700H, WSL2 (ext4 temp dir; the page cache absorbs most writes):

| Benchmark | MB/s |
|---|---|
| Pattern generation, zero (4 MiB buffers) | 10 038 |
| Pattern generation, random AES-256-CTR (AES-NI) | 6 263 |
| Wipe 256 MiB image, zero, 1 / 4 / 16 MiB chunks | 1 818 / 1 896 / 1 757 |
| Wipe 256 MiB image, random, 1 / 4 / 16 MiB chunks | 1 808 / 1 622 / 1 444 |

On real disks the device is the bottleneck. In the lab VM (emulated SATA HDD,
O_DIRECT, 1 MiB chunks) the wipe ran at about 125 MB/s. The 1 GiB acceptance test on
the Windows-mounted repo drive (`/mnt/d`, 9p) ran at 184 MB/s.

## Lab
Destructive tests run only inside a disposable QEMU/KVM VM whose disks are image files:
```sh
make lab-up && make lab-test && make lab-down
```
See `design/LAB_CAPABILITIES.md` for what the lab can and cannot emulate.

## License
MIT. See `LICENSE`.
