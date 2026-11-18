# shunya (शून्य, "zero")

A verifiable secure data-wiping tool for trustworthy IT asset recycling. Built for Smart
India Hackathon 2025, problem SIH25070.

> **Status: Milestone 7 (certificates).** A verified wipe gets a signed certificate (JSON + printable PDF with a QR code), checked fully offline by `shunya-verify` against the organisation's root key. `shunya plan` lists every erase method a drive supports with its NIST level; `shunya wipe` overwrites (Clear, HPA included) or runs the drive's own erase — ATA Security Erase, ATA SANITIZE, NVMe Sanitize or Format NVM (Purge where the medium allows) with a crash-safe, signed journal and resume; `shunya verify` re-checks a finished wipe by full read-back or by sampling. In the lab, a forensic harness shows that photorec recovers planted files before a wipe and nothing after it. Everything is a dry run unless `--execute` is given.

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
shunya keys gen-station $D/station.key               # station signing key (certify it: Milestone 7 below)
shunya wipe --image $D/disk.img                      # dry run: prints the plan, writes nothing
shunya wipe --execute --verify --journal $D/wipe.journal --key $D/station.key --image $D/disk.img
#   Ctrl-C (or kill -9) part-way, then:
shunya wipe --resume --execute --verify --journal $D/wipe.journal --key $D/station.key
shunya journal show --key $D/station.key $D/wipe.journal   # verified history, interruptions
shunya verify --sample 3000 --seed $(openssl rand -hex 16) --journal $D/wipe.journal --key $D/station.key
rm -r $D
```
- **Default:** one pass of an AES-256-CTR random stream, NIST SP 800-88 **Clear**.
- **Other patterns:** `--pattern zero,one,random` or `--passes N`. They are accepted but
  are not required by NIST.
- **Other tests:**
  - `make test-big` wipes and byte-checks a 1 GiB + 4095-sector image.
  - `make bench` runs the throughput benchmarks.

### Verification and the canary harness (Milestone 4)
- **Full read-back:** `--verify` (on `wipe`), or later with `shunya verify`.
- **Sampled:** `--sample N --seed HEX`. The output states the unwiped share it catches with 95 % probability; 3000 samples catch 0.1 %. The seed is labelled operator-chosen until Milestone 8 derives it from the transparency log.
- **Results are journalled:** every verification is a signed `verified` record, and `journal show` lists them.
- **Canary harness:** `make lab-test` runs it in the lab VM. The report goes to `lab/results/latest/canary-report.{json,txt}`.
- **Broken-wipe check:** `make test-broken` shows the harness catching a wipe that skips the last 1 %.

### ATA drives: IDENTIFY, hidden areas, Security Erase (Milestone 5)
```sh
shunya ata identify --dump internal/ata/testdata/identify/intel-ssdsa2ct040g3.txt   # decode a saved dump (no device)
shunya ata identify /dev/sdX --save sdX-identify.txt   # read-only; the file is hdparm --Istdout format
shunya ata hidden /dev/sdX                             # HPA / DCO state (read-only commands only)
shunya wipe /dev/sdX                                   # plan includes the hidden area; an HPA is wiped and restored
shunya wipe --method ata-secure-erase /dev/sdX         # dry run: level, preconditions (frozen? password set?)
shunya ata unlock --execute --journal J --key K        # recover a drive left locked by an interrupted erase
```
- **HPA:** removed with a volatile SET MAX (lost at power-off), wiped as part of the same plan, and restored afterwards (`--hpa restore`, the default). `--hpa leave-removed` keeps the full size until power-off; `--hpa skip` doesn't wipe it, and the plan says so.
- **DCO:** detected and disclosed, never changed (that would be permanent).
- **Security Erase:** a temporary password is set (journalled first), then ERASE UNIT runs and Shunya checks the password is gone. It counts as Purge on a real rotating disk and as Clear on flash. A normal erase can be verified for zeros; an enhanced one can't.
- **Testing:** the lab's QEMU drives answer IDENTIFY but emulate no HPA, DCO or Security, so those are tested against a simulated drive built from real IDENTIFY dumps and stay *pending real hardware*.

### NVMe, ATA SANITIZE and the planner (Milestone 6)
```sh
shunya plan /dev/nvme0n1                     # every method, its level, availability and why; the recommendation
shunya nvme identify /dev/nvme0n1            # controller + namespace (read-only); --ctrl FILE parses saved data
shunya wipe --method nvme-sanitize-crypto-erase /dev/nvme0n1   # dry run; add --execute --journal J --key K
```
- **Methods:** `nvme-sanitize-{crypto-erase,block-erase,overwrite}`, `nvme-format-{crypto,user-data}-erase`, `ata-sanitize-{crypto-scramble,block-erase,overwrite}`, plus the M5 ATA Security Erase pair and `overwrite`.
- **Purge** for Sanitize and NVMe Format with secure erase on real media; Clear on virtual disks. Methods are offered only when the drive advertises them.
- **Markers:** before any firmware erase, 1024 HMAC-tagged sectors are planted; afterwards none may read back. That is the only content check possible after a crypto erase.
- **Sanitize** runs inside the drive: Shunya polls and journals it, and a resume after a crash waits for it rather than starting a second one.
- **Refusals:** if the erase would hit other namespaces or a multi-controller subsystem.
- **Testing:** the lab ran a real Format NVM on QEMU. QEMU has no Sanitize, so that is tested against a simulated controller and is *pending real hardware*.

### Certificates and keys (Milestone 7)
```sh
R=$D/root                                                  # on an offline machine in practice
shunya keys init-root $R                                   # root.key (passphrase), root.pub, revocations.json
shunya keys issue-station --root $R/root.key --station-key $D/station.key --name bay-1 --out $D/station.cert.json
shunya wipe --execute --verify --journal $D/w.journal --key $D/station.key --station-cert $D/station.cert.json --image $D/disk.img
#   -> $D/w.journal.cert.json and $D/w.journal.cert.pdf
shunya-verify --root $R/root.pub --revocations $R/revocations.json --pdf $D/w.journal.cert.pdf $D/w.journal.cert.json
shunya keys revoke --root $R/root.key --revocations $R/revocations.json --key-id ed25519:... --reason retired
shunya cert issue --journal OLD.journal --key K            # certificate for an earlier wipe
```
- **What it is:** a canonical JSON (RFC 8785) file signed with Ed25519 by a station key that
  the offline root certified. Changing any byte of it fails verification. The PDF is
  rendered from the JSON, and `--pdf` checks it byte for byte. The QR code holds the
  verification URL and the certificate's SHA-256 ID.
- **Revocation:** a retired station's earlier certificates stay valid. A compromised
  station's certificates all fail, because their dates are its own claim until Milestone 8
  logs them.
- **Dev keys:** journals from Milestones 3–6 (dev keys) can be certified. They are marked,
  and verifiers refuse them without `--allow-dev-key`.
- **Design:** `design/CERTIFICATES.md`.

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
