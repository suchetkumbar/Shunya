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

## 4. Built-in defences in the tool (implemented from Milestone 2)
1. **Two backends.** `FileBackend` (regular image files) and `BlockBackend` (real devices). Every wipe method is written against the `Target` interface, so it is tested on files.
2. **Lab lock (every build without `-tags release`).** `BlockBackend` refuses to open a device unless **all** hold:
   - DMI `sys_vendor`/`product_name` reports QEMU/KVM;
   - `/etc/shunya-lab` exists and matches the token compiled in at lab build time;
   - the device is not the boot disk, not mounted, not held by LVM / MD-RAID / dm-crypt / ZFS, and has no active swap.
3. **Release builds (`-tags release`)** drop only the VM check. They keep every other guard and require typed confirmation (last 4 characters of the serial), or `--yes-really` plus a pre-approved device list in fleet mode.
4. **Absolute refusals in every build:** the disk holding the running root filesystem, the disk Shunya booted from, any mounted filesystem, and any device whose identity (serial, size) changed between selection and the first write (TOCTOU re-check).
5. **Dry-run by default.** `shunya wipe` without `--execute` prints the plan and writes nothing.
6. Each guard has a unit test: boot disk refused, mounted device refused, identity swap detected, dev build outside a VM refused.

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
