# The Shunya live image (Milestone 10)

A small bootable system for a machine whose disks are to be wiped. It boots from a USB
stick (or a CD), runs entirely from RAM, protects the medium it booted from, and starts
`shunya tui`. Wipe journals and certificates are kept on the stick; the station key lives
on its own partition.

It is built inside the lab VM, never on the host, and two builds give byte-identical
output (see [Reproducible](#reproducible)).

## What is on it

The image is one hybrid ISO file (`shunya-live.iso`, about 95 MB). It can be written to a
USB stick or booted as a CD.

| Part | Partition | Contents |
|---|---|---|
| `SHUNYA-LIVE` | 1, ISO 9660, read-only | `isolinux/` (boot loader), `boot/vmlinuz`, `boot/initramfs.gz`, `BUILDINFO.TXT` (every input and the SHA-256 of every file in the initramfs) |
| `SHUNYA-KEYS` | 2, ext4, 8 MiB | Ships with only a README. You add `station.key` and `station.cert.json` (see [Provisioning](#provisioning)). Mounted read-only. |
| `SHUNYA-DATA` | 3, ext4, 64 MiB | `sessions/<UTC time>/`: one directory per boot session, holding the wipe journals, certificates (JSON and PDF) and batch manifests. Mounted read-write. |

The initramfs holds:
- `init`: a busybox shell script, `image/init`.
- busybox (static).
- `shunya` and `shunya-verify`: the release builds, static.
- The storage drivers from `image/modules.list`, loaded in dependency order: NVMe, virtio, SCSI disks, USB storage (xhci/ehci/ohci/uhci, UAS), USB keyboards, CD-ROM, ext4. AHCI/SATA is built into the kernel.

There is no network, no package manager, no SSH, and no shell for the operator.

| Input | Version | Licence |
|---|---|---|
| Kernel `linux-virt` (Alpine 3.24) | 6.18.64-r0 | GPL-2.0 |
| `busybox-static` | 1.37.0-r31 | GPL-2.0 |
| `syslinux` (isolinux, MBR) | 6.04_pre1-r19 | GPL-2.0 |

These are pinned by version and SHA-256 in `image/packages.lock`. Distributing the ISO
means distributing GPL binaries. Their corresponding source is Alpine's aports at the
same package versions; publish that pointer, or the sources, alongside any public ISO
(`DEPENDENCIES.md`).

## Boot sequence (`image/init`)

1. Mount `/proc`, `/sys`, `/dev` (devtmpfs), `/run` and `/tmp`, then load the drivers.
2. **Find the boot medium.** `blkid` lists every partition labelled `SHUNYA-LIVE`, `SHUNYA-KEYS` or `SHUNYA-DATA`. Their device numbers go to `/run/shunya/boot-device`.
   - Shunya's enumeration marks every disk named there **PROTECTED**, in every build, whether mounted or not (`device.BootDeviceFile`, SAFETY rule 44).
   - Init refuses to start the TUI if no `SHUNYA-LIVE` medium is found, or if more than one is attached.
3. **Keys and data.** On the boot disk only, it mounts `SHUNYA-KEYS` read-only on `/keys` and `SHUNYA-DATA` read-write on `/data`.
   - Booted as a CD, there are no such partitions. `/data` is then RAM, and the screen says that journals and certificates will be lost at power-off.
4. **The TUI.** It runs `shunya tui --journal-dir /data/sessions/<time> --key /keys/station.key [--station-cert /keys/station.cert.json]` on the console chosen by `shunya.console=`.
   - Without a station key, a one-boot key keeps the journals signed, but no certificates are issued; the screen says so.
5. **Menu.** When the TUI exits:
   - **Enter:** wipe more disks.
   - **c:** print this session's certificates and manifest as JSON on the screen (also how the lab test reads them).
   - **p:** sync, unmount, power off.

The boot loader offers two entries:
- `shunya` (the default after 5 s): the screen and keyboard, `tty1`.
- `serial`: the first serial port at 115200 baud. Type `serial` at the `boot:` prompt.

## Provisioning

A station key and its certificate turn wipes into signed certificates.
1. On the offline root machine, run `shunya keys gen-station station.key` and `shunya keys issue-station … --out station.cert.json` (see `CERTIFICATES.md`).
2. On a Linux machine, mount the stick's `SHUNYA-KEYS` partition and copy both files there (`station.key` mode 0600).

The partition is plain ext4, not encrypted (the decision for M10). Anyone holding the
stick holds the station key, so a lost stick means revoking that station
(`shunya keys revoke`). Generating the key and importing the certificate from inside the
live system is not offered yet.

## Building

```sh
make lab-up         # the lab VM builds the image
make image          # release binaries + mkinitramfs, then lab.sh image → lab/images/live/
make image-repro    # two builds from empty caches; compares binaries and the ISO
make image-lock     # newest package versions and their SHA-256, to review into packages.lock
make lab-iso-test   # builds the release and lab-test ISOs, stops the VM, boots them in QEMU
```

`lab.sh image` pushes the release binaries, `mkinitramfs` and `image/*` into the VM, then
runs `image/build.sh` there as the unprivileged VM user:
1. Download each pinned `.apk` by URL and check its SHA-256 against the lock. A mismatch stops the build.
   - `apk` 3 cannot fetch a pinned version, so the build fetches the file directly. The recorded SHA-256 came from an `apk fetch`, which checks Alpine's signature.
2. Unpack the packages with `tar`; nothing is installed.
3. `mkinitramfs` (`image/mkinitramfs`, a Go tool, run in the VM) writes the initramfs:
   - entries in sorted order, owner root, all times `SOURCE_DATE_EPOCH`;
   - `/dev/console` and `/dev/null` as header-only entries (no device is created);
   - modules decompressed and ordered from `modules.dep`;
   - gzip with no timestamp.
4. `mke2fs -d` builds the two ext4 partitions from directories, with a fixed UUID and hash seed, `E2FSPROGS_FAKE_TIME`, and every file time set to the epoch.
5. `xorriso` builds the hybrid ISO: isolinux El Torito plus the isohybrid MBR, with the two ext4 images appended as partitions 2 and 3. It honours `SOURCE_DATE_EPOCH` for every date in the ISO.

`SOURCE_DATE_EPOCH` is the time of the last git commit. The only package installed in the
VM is `xorriso`, the build tool (`lab.env`, `IMAGE_BUILD_PACKAGES`); `e2fsprogs` was
already there.

### Reproducible

Measured on 2026-11-19 with `make image-repro`: two builds, each from an empty Go build
cache and a fresh build directory, with the packages downloaded again.

| Output | SHA-256 (both builds) |
|---|---|
| `shunya` (release) | `d343d3f9a99b57157071837201d87cdd3747be3cd4a2820cebd35b873b79e403` |
| `shunya-verify` (release) | `963dc84da037d6d99051ba9fe94dcc66c6696cfecca65b9ed19699fb9cdebf47` |
| `shunya-live.iso` | `bfbe3fe63dbceefbe9c337d36c0919a8f328ea3251c7269ab6da848cd0cf533a` |

These hashes are for the working tree at that point. They change with any code change or
commit time. Every input is recorded in the ISO's `BUILDINFO.TXT`. A certificate's
`tool.wipe_build_hash` is the hash of the `shunya` binary inside the image, so a
certificate can be traced back to an image build.

## Testing (`lab/iso`, `make lab-iso-test`)

QEMU runs from WSL, not inside the lab VM. The test passes every disk as a regular file
under `lab/images/`, and checks this before use. It drives the serial console as an
operator would.

| Test | What it shows |
|---|---|
| `TestISOBootCD` | The release ISO boots as a CD, finds itself (`/dev/sr0`) and says data stays in RAM. It lists the target disk and does not offer the CD drive. It powers off from the menu, and the target is untouched. |
| `TestISOBootUSBWipe` | The lab-test ISO boots as a USB stick on xhci. Its own disk is listed but PROTECTED as "boot medium of this Shunya live system", and cannot be selected. The test selects three disks of different kinds (virtio-blk, NVMe, SATA HDD) and types each confirmation. The plan, made after confirmation in this release build, uses the NVMe drive's own Format. After the wipes it prints the certificates and the manifest on the console. `shunya-verify` reports all 3 VALID, and the manifest BATCH COMPLETE. Every canary is gone from the target files. The stick is unchanged outside `SHUNYA-DATA`. Measured: boot plus three 256 MiB wipes with full verification in 19 s. |

The **lab-test ISO** is built in the same run as the release ISO. It is identical to the
release ISO except partition 2: a throwaway root certifies a station key, and both go on
`SHUNYA-KEYS`. The test checks this byte for byte before booting it. The throwaway root
key never leaves the VM. The lab-test ISO and its station key stay in `lab/images/`
(gitignored) and must never be published.

## Limitations

- **Boot method:** BIOS (legacy) boot only, through isolinux. A UEFI-only machine cannot boot it yet; that needs GRUB-EFI or systemd-boot packages and an EFI system partition.
- **Kernel drivers:** `linux-virt` is Alpine's kernel for virtual machines. Real machines may need drivers it lacks (some RAID/HBA controllers, Thunderbolt, MMC readers). `linux-lts` (about 40 MB more) would cover more hardware; not done yet.
- **Real hardware:** tested in QEMU only, never on a real machine.
- **Unencrypted key partition:** the station key partition is not encrypted (see Provisioning).
- **Shared UUIDs:** every stick made from the same ISO carries the same partition UUIDs (fixed for reproducibility). Shunya finds partitions by label on its own boot disk, never by UUID.
- **Other Shunya sticks:** a second Shunya stick attached at boot stops the live system, because it cannot tell which one it booted from. A Shunya stick plugged in after boot is not recorded in `boot-device`. It is treated like any other disk: listed, and wipeable after the typed confirmation. Labels are read only at boot, because enumeration reads sysfs and never opens a disk.
- **No in-image provisioning:** key generation and certificate import from inside the live system are not offered.
- **No transparency log:** the image has no network, so certificates are issued offline (`log: null`). They can be submitted later with `shunya cert submit`.
