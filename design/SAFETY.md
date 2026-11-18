# Safety

Shunya destroys data by design. These rules protect the development machine and any
machine Shunya runs on. They override every other requirement.

## 1. Where destruction is allowed

| Place | Destructive operations allowed? |
|---|---|
| Windows host | **Never.** No block/char device is opened, not even read-only (on Windows, enumeration means opening `\\.\PhysicalDriveN`, so the Windows code paths are compile-only and parser-tested on the dev machine). |
| WSL2 Debian distro | **Never.** Treated exactly like the host: only builds, unit tests on regular files, and running QEMU. No `wsl --mount` of physical disks. |
| Lab VM (QEMU, Alpine) | **Yes, on target disks only.** All its disks are image files in `lab/images/`. |
| Real hardware | Only at the very end, on a device the user names, after explicit confirmation each time, booted from the Shunya live image. |

## 2. Host rules
1. Never open, write to, or issue ioctls against any host device (`/dev/sd*`, `/dev/nvme*`, `/dev/mmcblk*`, `/dev/loop*`, `/dev/dm-*`, `\\.\PhysicalDrive*`, …). Reading `/sys/block`, `/proc/mounts`, `/proc/partitions` and `/sys/class` is allowed.
2. On the host, destructive code paths run only against regular files via `FileBackend`.
3. Never run `sudo`, `losetup`, `mkfs`, `dd`, `wipefs`, `blkdiscard`, `hdparm`, `nvme`, `sg_*`, `parted`, `fdisk` or `diskpart` on the host (these appear only in `lab/probe/`, which refuses to run outside the lab VM).
4. No host configuration changes, system packages or large downloads without the user's prior approval. Approved changes so far are listed in §6.
5. Everything stays inside the repository, except the Go toolchain/module/build caches inside WSL.

## 3. The lab
- `lab/lab.sh` refuses to hand QEMU anything that is not a regular file under `lab/images/` (`assert_image_file`), and refuses to run as root or outside Linux.
- No host disk passthrough, ever.
- The VM has a separate boot disk (`SHUNYA-BOOT-0`) that every tool must refuse.
- `lab/probe/probe.sh` additionally refuses to run unless DMI says QEMU/KVM and `/etc/shunya-lab` exists, refuses the root disk and mounted disks, and only touches disks whose serial is a lab target serial.

## 4. Built-in defences in the tool (implemented in Milestone 2, `internal/backend`)
1. **Two backends.** Every wipe method is written against the `Target` interface, so it is tested on files.
   - `FileBackend` takes regular image files only. Symlinks, devices and directories are refused before opening. The file is checked again on the open descriptor, and `O_NOFOLLOW` is used.
   - `BlockBackend` handles real devices (Linux).
2. **Lab lock (every build without `-tags release`).** `BlockBackend` refuses to open a device unless DMI `sys_vendor`/`product_name` contains QEMU or KVM, **and** `/etc/shunya-lab` matches the token compiled in.
   - The token is compared in constant time.
   - Only `make build-lab` compiles a token in (`-ldflags -X …labToken=`). Ordinary dev builds carry none, so they refuse every block device, even inside the VM.
3. **Release builds (`-tags release`)** drop only the lab lock and keep every other guard. Opening requires a `Confirmation`:
   - the last 4 characters of the serial, typed by the operator; or
   - `--yes-really` together with the device fingerprint in a pre-approved list (fleet mode).
4. **Absolute refusals in every build** (`backend.Check`, from a fresh enumeration):
   - the disk under `/`, `/boot`, `/boot/efi` or `/efi`, traced through partitions, dm and md;
   - the disk holding the running binary (`st_dev` of `/proc/self/exe`);
   - anything mounted (in any visible mount namespace), used as swap, held by dm/LVM/dm-crypt/md, or a btrfs member;
   - partitions, read-only devices and logical devices;
   - devices with no serial or WWID, because a swap of such a drive can't be detected.
5. **Kernel-level exclusivity.** `BlockBackend` opens with `O_EXCL`. The kernel refuses this for any device that is mounted or claimed anywhere, including mounts Shunya cannot see (other namespaces, ZFS). The lab test proves `EBUSY` for a mounted disk with the guard bypassed.
6. **TOCTOU.** After opening, the descriptor must be the selected device: `S_ISBLK`, the same `major:minor`, and the same size and sector sizes. Just before the first write, a fresh enumeration must still allow the device with the same device number, serial, WWID, size and fingerprint. Any mismatch closes the target for good.
7. **Dry-run by default.** Without `Options.Execute`, devices open read-only and every write or discard returns `ErrDryRun`.
8. **Tests.**
   - Host tests use fake sysfs trees and faked system calls. They prove a refused device is never opened.
   - Each guard has a test: boot disk, mounted, holders, swap, partition, read-only, weak fingerprint, the binary's own disk, identity swap, and dev build outside the VM, plus wrong, missing or absent token.
   - Mutation checks confirm the tests fail if the re-check, `O_EXCL` or the lab lock is removed.
   - `lab/tests` repeats the guard checks on real QEMU disks.
9. **`shunya guard /dev/X`** shows the verdict and every reason, without opening the device.

### Milestone 3 additions (`internal/engine`, `internal/journal`)
10. **`shunya wipe` uses the same path.** A dry run (no `--execute`) only runs `backend.Check` and never opens the device. `--execute` opens through `OpenBlock` with every guard; `--resume` re-runs them all and also requires the target's fingerprint to equal the journal's.
11. **Mid-wipe re-check.** `Block.Recheck` repeats the TOCTOU identity check before each pass and after every checkpoint; a mismatch kills the target.
12. **Journal placement.** The journal must be a regular file (lstat before open, `O_NOFOLLOW`); a path naming a device node is refused before anything is opened. Its file system must not be the target or any of its partitions (`st_dev`), nor a loop mount of the image being wiped.
13. **Durable progress only.** A checkpoint is journalled only after `Sync`; a journal that can't be written stops the wipe.
14. **Big test files** (`make test-big`) go in the repo's `tmp/` (gitignored). Other test files use the Go test temp directory, as before.

### Milestone 4 additions
15. **The broken wipe is test-only.** `brokenTailPercent` is 1 only under the `brokenwipe` build tag, which is used for exactly one binary, `bin/lab/shunya-broken`. The tag is linted but never part of `make build`, `make repro` or CI builds. In every other build it is the constant 0 and the branch is compiled out (`TestBrokenWipeOnlyInBrokenBuild` runs in every tag set).
16. **The canary harness runs only in the lab VM** (`lab/tests`, `-tags labtest`, root). It plants through the guarded `BlockBackend` and shells out to `mkfs.*`, `mount` and `photorec`, which the brief allows in lab harnesses only. Its host tests use image files.
17. **VM-only packages.** `testdisk` (photorec) and `exfatprogs` are installed inside the lab VM by `lab.sh`, never on the host. `foremost` is not packaged for Alpine 3.24, so photorec is the only carver.

### Milestone 5 additions (`internal/ata`, `backend.CheckATA`)
18. **ATA allowlist on the raw bytes.** `Block.PassThrough` accepts only ATA PASS-THROUGH(16) CDBs whose command, protocol, direction, transfer length and data buffer match `backend.CheckATA`. Never allowed: DCO SET/RESTORE/FREEZE LOCK, a non-volatile SET MAX, SECURITY FREEZE LOCK, a master password or security level Maximum, SANITIZE, DOWNLOAD MICROCODE, any vendor command. Nothing Shunya sends can change a drive permanently outside its user data and its own temporary password.
19. **Mutating ATA commands are writes.** SET MAX, WRITE DMA EXT and the Security commands need `--execute` and run the same TOCTOU re-check as the first write; a dry run may only read (IDENTIFY, READ NATIVE MAX, DCO IDENTIFY, READ DMA EXT). ATA is sent only to SATA and USB-attached drives, and only after IDENTIFY's serial, model, WWN and size match what was selected.
20. **HPA changes are volatile.** The only SET MAX Shunya sends clears the Value Volatile bit, so a drive always returns to its original size at power-off, whatever happens to Shunya.
21. **Security Erase recovery.** The temporary password is journalled before it is set. `shunya ata unlock` removes it from a drive left locked; the password is level High, so the drive's master password also still works.
22. **Frozen drives are refused, not worked around.** The suspend-to-RAM and hot-plug workarounds act on the whole machine; Shunya explains them and leaves them to the operator.
23. **Simulated drive only for HPA/DCO/Security.** QEMU emulates none of them; everything proven only against `atafake` is labelled pending-real-hardware (design/LAB_CAPABILITIES.md). No real drive was sent a Security or SET MAX command during development.

### Milestone 6 additions (`internal/nvme`, `internal/sanitize`, `backend.CheckNVMe`)
24. **NVMe allowlist on the raw fields.** `Block.AdminCommand` accepts only Identify (CNS 0/1/2), the Sanitize Status log, Format NVM with SES 1 or 2 on one namespace, and Sanitize (block/overwrite/crypto, no auto-restart, no no-deallocate). Firmware download/commit, namespace management/attachment, Set Features, Security Send, Exit Failure Mode and vendor commands are refused; caller-set addresses or metadata are refused. Format and Sanitize need `--execute` and pass the TOCTOU re-check; only NVMe devices are addressed.
25. **No collateral erase.** Sanitize, and a Format whose FNA says it reaches all namespaces, are refused unless the target is the controller's only active namespace on a single-controller subsystem.
26. **ATA SANITIZE: no freeze or antifreeze.** SANITIZE FREEZE LOCK and ANTIFREEZE LOCK cannot be built and are refused by `CheckATA`, as are wrong erase keys and the failure-mode bit. A sanitize-frozen drive is explained, not worked around.
27. **Capabilities, not command status.** A method is offered only when the drive advertises it (SANICAP, FNA, IDENTIFY word 59). QEMU accepts a crypto Format with FNA = 0; Shunya refuses it.
28. **Virtual machine → virtual disks.** If DMI says the machine is a VM, every disk is treated as emulated (never Purge), whatever its model string says.
29. **One real firmware erase in the lab, none on the host.** The lab ran Format NVM (user data erase) on the QEMU NVMe target only. Sanitize (NVMe and ATA) is proven against the simulated drives only (pending-real-hardware).

### Interpretation note
Rule 2.1 targets storage devices. `/dev/null` (shell redirects, `go build -o /dev/null`) is
treated as outside its intent. `/dev/urandom` is no longer read: the lab token comes
from `openssl rand`, which uses `getrandom(2)`. The user was told about this.

## 5. Honesty rules
- Never claim a NIST 800-88 level the method cannot justify (an overwrite of flash media is **Clear** with a residual-risk disclosure, never Purge).
- A test that cannot run in the lab is reported as **SKIPPED with a reason**, never as passing. See `LAB_CAPABILITIES.md`.

## 6. Approved environment changes (audit trail)

| Date | Change | Where |
|---|---|---|
| 2026-11-17 | Installed WSL distro `Debian` (`wsl --install -d Debian --no-launch`) | Windows (WSL) |
| 2026-11-17 | Created `%UserProfile%\.wslconfig`: `memory=4GB`, `nestedVirtualization=true` (also caps Docker Desktop) | Windows |
| 2026-11-17 | apt: `qemu-system-x86 qemu-utils make openssh-client xorriso ca-certificates curl git`; user `lab` in group `kvm`; `/etc/wsl.conf` (default user, `modprobe kvm_intel` at boot) | WSL Debian |
| 2026-11-17 | Go 1.27.4 in `~lab/go-sdk` (SHA-256 verified), staticcheck 2026.2.2, govulncheck 1.9.0 | WSL Debian |
| 2026-11-17 | Alpine 3.24.2 cloud image (149 MiB, SHA-512 verified) into `lab/images/` | repo (gitignored) |
| 2026-11-17 | apt: `gcc libc6-dev` (race detector only; binaries stay `CGO_ENABLED=0`) | WSL Debian |
| 2026-11-17 | Go module `golang.org/x/sys` v0.50.0 (pre-approved) | Go module cache |
