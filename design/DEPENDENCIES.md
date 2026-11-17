# Dependencies

Shunya keeps third-party code to a minimum. Crypto protocols, the Merkle tree, canonical
JSON and all wipe logic are written in this repository. Every dependency is listed here
with its justification.

## Go modules

| Module | Used by | Why | Added |
|---|---|---|---|
| `golang.org/x/sys` v0.50.0 | `internal/backend` (Linux) | open(2) with O_EXCL/O_DIRECT, fstat, BLKSSZGET/BLKPBSZGET/BLKDISCARD ioctls, fallocate. Maintained by the Go team; the stdlib `syscall` package is frozen and lacks these. | M2 |

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
`lab/probe/probe.sh` to measure what QEMU emulates. Shunya itself issues these commands
from Go (brief §4).
