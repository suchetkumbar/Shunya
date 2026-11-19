# Dependencies

Shunya keeps third-party code to a minimum. Crypto protocols, the Merkle tree, canonical
JSON and all wipe logic are written in this repository. Every dependency is listed here
with its justification.

## Go modules

| Module | Used by | Why | Added |
|---|---|---|---|
| `golang.org/x/sys` v0.50.0 | `internal/backend` (Linux) | open(2) with O_EXCL/O_DIRECT, fstat, BLKSSZGET/BLKPBSZGET/BLKDISCARD ioctls, fallocate. Maintained by the Go team; the stdlib `syscall` package is frozen and lacks these. | M2 |
| `golang.org/x/mod` v0.42.0 | **tests only** (`internal/tlog`, `note`, `checkpoint`, `tilestore`) | An independent implementation of the same formats (sumdb `tlog` and `note`), used as a test oracle: roots, proofs, tile paths and contents, signed notes in both directions. Not linked into any binary (`go list -deps ./cmd/...` doesn't list it). Go team. v0.42.0 (2026-10-09) rather than v0.43.0 (ten days old). The note package was pre-approved; `sumdb/tlog` is in the same module. | M8 |
| `golang.org/x/term` v0.47.0 | `cmd/shunya` (keys) | Reads the root key passphrase without echo, on Linux and Windows. Go team. v0.47.0 (2026-10-09) rather than v0.48.0 (2026-11-09, nine days old when added); it needs only `x/sys`, already present. Approved by the user for M7. | M7 |

No module was added in M3. `golang.org/x/sys` also provides flock and `O_NOFOLLOW` for the journal and `st_dev` for the journal placement check. The random pattern uses the standard library's `crypto/aes` + `crypto/cipher` CTR; ChaCha20 would need `x/crypto`, which isn't pre-approved. Leak checks use the in-tree `internal/testutil/leakcheck` instead of `go.uber.org/goleak`.

No module was added in M4 either. The canary harness uses the standard library only: `crypto/hmac`, `image/jpeg`, `archive/zip`, `hash/crc32`, and `math/rand/v2` ChaCha8 for the sample positions. Aho-Corasick is written in-tree.

Pre-approved for later milestones: a TUI library
(`charmbracelet/bubbletea` + `lipgloss`, M9), a PDF library (`go-pdf/fpdf`, M7),
a QR library (M7), and `golang.org/x/mod/sumdb/note` (signed notes, M8, if useful).

## Development tools (not linked into binaries)

| Tool | Version | Purpose |
|---|---|---|
| Go | 1.27.4 | Toolchain (pinned in `go.mod`) |
| staticcheck | 2026.2.2 | Linting |
| govulncheck | 1.9.0 | Known-vulnerability scan |
| QEMU | 10.0.13 | Lab VM (WSL Debian package) |
| xorriso | Debian 13 | Builds the cloud-init seed ISO |
| gcc, libc6-dev | Debian 13 (gcc 14.2) | Only for `make race` (the race detector needs cgo); release binaries stay CGO_ENABLED=0 |

## Lab-only tools (inside the lab VM, never in the core engine)
`nvme-cli`, `hdparm`, `sg3_utils`, `util-linux`, `e2fsprogs`, `dosfstools`, used by
`lab/probe/probe.sh` to measure what QEMU emulates. From M4, also `testdisk` (photorec,
the file carver) and `exfatprogs`, used by the canary harness (`lab/tests`). Each is
installed from the Alpine repositories inside the VM by `lab.sh`. `foremost` is not packaged
for Alpine 3.24. Shunya itself issues these commands
from Go (brief §4).

## Milestones 5–6: no new modules
The ATA and NVMe layers use only the standard library and `golang.org/x/sys/unix`. For
reference only (not vendored, not linked), the specifications were cross-checked against:
- ATA: hdparm's and sg3_utils' published CDBs and IDENTIFY decoding.
- NVMe: libnvme (`linux-nvme/libnvme`, LGPL-2.1) `src/nvme/types.h` and `ioctl.h` (struct
  layouts, bit fields, status codes).

The test data are public IDENTIFY dumps (cited in `internal/ata/testdata/identify/SOURCES.md`)
and data recorded from the lab's QEMU drives (`internal/nvme/testdata/SOURCES.md`).

## Milestone 7: one new module, PDF and QR in-tree
`golang.org/x/term` (above). As agreed, the PDF and QR Code were written in-tree rather
than taking the pre-approved `go-pdf/fpdf` and a QR library. Both are small (about 300 and
400 lines), deterministic and fully tested, and the binaries stay reproducible with a
single external module family. Key derivation and encryption use the standard library
(`crypto/pbkdf2`, `crypto/aes`, `crypto/cipher`); `x/crypto` (Argon2id, scrypt) is not
needed.

Lab VM packages added in M7, used only by `TestLabCertificate` to check Shunya's PDF and
QR output independently: `qpdf`, `poppler-utils` (pdftotext, pdftoppm), `zbar` (zbarimg)
and `imagemagick`, whose image coders zbarimg needs (VM only, 46 MiB in all).

## Test data from other projects

| Data | Source | Licence | Where |
|---|---|---|---|
| RFC 6962 inclusion and consistency proof vectors (196 JSON files) | transparency-dev/merkle `testdata/` (tarball of `main`, SHA-256 `0ccc8608…`, 2026-11-19) | Apache-2.0 (copy in the directory) | `internal/tlog/testdata/transparency-dev/` |

No module was added for the log itself in M8: the Merkle tree, signed notes, checkpoints,
tiles, server and rate limiter are in-tree, on the standard library (`net/http`,
`log/slog`, `html/template`, `crypto/ed25519`).
