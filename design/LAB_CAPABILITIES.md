# Lab capabilities

What the Shunya lab can and cannot exercise, measured by `make lab-test`
(`lab/probe/probe.sh`) on 2026-11-17. Re-run the probe after any QEMU or guest change
and update this file.

## Lab setup

| Item | Value |
|---|---|
| Host | Windows 11 → WSL2 (kernel 6.18.33, `kvm_intel nested=Y`) → Debian 13 |
| Hypervisor | QEMU 10.0.13 (Debian package), KVM-accelerated, `-machine q35` |
| Guest | Alpine Linux 3.24.2 cloud image (`linux-virt` 6.18.54), 1 GiB RAM, 2 vCPU |
| DMI seen by guest | `sys_vendor=QEMU`, `product_name=Standard PC (Q35 + ICH9, 2009)` |
| Lab marker | `/etc/shunya-lab` (64-hex token from `lab/secrets/lab-token`) |
| Boot disk | virtio-blk, serial `SHUNYA-BOOT-0`, 2 GiB qcow2 overlay |

## Target disks

| Serial | Bus / QEMU device | Guest node | ROTA | Notes |
|---|---|---|---|---|
| `SHUNYA-VIRTIO-01` | `virtio-blk-pci` | `vdb` | 1 | Kernel reports rotational=1 by default (no media info) |
| `SHUNYA-SATA-SSD-01` | `ide-hd` on ICH9 AHCI, `rotation_rate=1` | `sdb` | 0 | WWN `5000c500a1b2c301` |
| `SHUNYA-SATA-HDD-01` | `ide-hd` on ICH9 AHCI, `rotation_rate=7200` | `sda` | 1 | WWN `5000c500a1b2c302` |
| `SHUNYA-NVME-01` | `nvme` + `nvme-ns` (nsid 1, EUI-64 set) | `nvme0n1` | 0 | NVMe 1.4 (`ver=0x10400`), 8 LBA formats |
| `SHUNYA-USB-01` | `usb-storage` on `qemu-xhci`, removable | `sdc` | 1 | Serial only in the USB descriptor (not VPD) |

Note: on Alpine (no udev) `lsblk` shows no serials. Serials must come from sysfs:
virtio `…/serial`, NVMe `…/device/serial`, SCSI/SATA `…/device/vpd_pg80` (binary,
4-byte header — and sysfs reports its size as 0), USB: walk up to the USB device's `serial`.

## Capability matrix

Legend: ✅ works in lab · ⚠️ works but misleading · ❌ not emulated → **must be tested against
a fake device built from recorded data, labelled `pending-real-hardware`**.

| Feature | virtio | AHCI SATA | NVMe | USB MSC | Consequence for Shunya |
|---|---|---|---|---|---|
| Plain read/write/O_DIRECT | ✅ | ✅ | ✅ | ✅ | Overwrite engine (M3) fully lab-testable |
| Discard / TRIM | ✅ | ✅ (blkdiscard OK) | ✅ (DSM deallocate) | ❌ (`discard_max=0`) | |
| Write Zeroes | ✅ | — | ✅ | — | |
| ATA pass-through via SG_IO (IDENTIFY) | n/a | ✅ | n/a | ❌ (no SAT; all-zero IDENTIFY) | M5 IDENTIFY parser can be lab-tested on AHCI |
| ATA Security feature set (SET PASS / ERASE UNIT) | n/a | ❌ not advertised; commands ignored | n/a | ❌ | M5 Secure Erase: fake device only |
| HPA (READ NATIVE MAX / SET MAX) | n/a | ❌ not advertised (word 82 bit 10 clear) | n/a | ❌ | M5 HPA: fake device only |
| DCO IDENTIFY | n/a | ❌ (aborted with sense error) | n/a | ❌ | M5 DCO: fake device only |
| NVMe Identify Controller / Namespace | n/a | n/a | ✅ | n/a | M6 parsers lab-testable |
| NVMe Format NVM SES=0/1 | n/a | n/a | ✅ data verified zeroed | n/a | |
| NVMe Format NVM SES=2 (crypto) | n/a | n/a | ⚠️ returns success and zeroes data, **but `FNA=0` says crypto erase unsupported** | n/a | Planner must trust FNA bit 2, not command success. Lab can't show a real crypto erase. |
| NVMe Sanitize (block/overwrite/crypto) | n/a | n/a | ❌ `SANICAP=0`, Invalid Opcode | n/a | M6 Sanitize: fake controller only | Confirmed M6: QEMU 10.0.13 still SANICAP 0; the Sanitize Status log is refused with status 0x4002. |
| NVMe Sanitize Status log | n/a | n/a | ❌ | n/a | |
| Removable flag | 0 | 0 | 0 | ✅ 1 | |
| WWN / EUI-64 | — | ✅ | ✅ | — | Fingerprint fields lab-testable |

## Pending real hardware (Milestone 5)
Proven only against the simulated drive (`internal/ata/atafake`, built from real IDENTIFY dumps): HPA removal (volatile SET MAX), hidden-range writes through READ/WRITE DMA EXT, HPA restore, DCO detection, the whole Security Erase state machine (set password, erase prepare/unit, disable, unlock, frozen, attempt counter, power loss at each step, resume). No real drive has received a SET MAX or a Security command from Shunya yet.

## Pending real hardware (Milestone 6)
Proven only against the simulated controller (`internal/nvme/nvmefake`, built from the recorded QEMU Identify data) and the simulated ATA drive: NVMe Sanitize (block, crypto, overwrite) with status polling, failure mode, resume while running, Global Data Erased attestation; crypto Format on a controller that advertises it; ATA SANITIZE (crypto scramble, block erase, overwrite), its frozen state and failure. A real Format NVM (user data erase) ran in the lab on the QEMU NVMe target.

## Not testable in this lab at all
- Real flash behaviour (remapped/over-provisioned cells, wear levelling): why overwrite on SSD/flash is labelled **Clear**, never Purge.
- Frozen-security-state handling (no Security feature set to freeze).
- Vendor firmware that lies about erase completion.
- eMMC sanitize / secure trim (QEMU has no eMMC device on q35).

These stay `pending-real-hardware` until the final real-hardware step (see design/SAFETY.md).

## Lab facts worth knowing
- `/mnt/d` (drvfs) does not keep files sparse: the five targets occupy ~4.5 GiB on D:.
- The WSL kernel builds KVM as a module. The Debian distro's `/etc/wsl.conf` `[boot]` loads `kvm_intel` and fixes `/dev/kvm` group permissions.
- Alpine locks root: the lab logs in as `alpine` and uses `doas`.
- First boot takes ~20–90 s (package install with retries); `make lab-up` waits for `/etc/shunya-lab-ready`.
- The two AHCI disks do not keep their `sda`/`sdb` names across boots (in the M3 run the
  SSD was `sda`). Lab tests always find disks by serial, never by name.
- The lab VM's SATA disks have custom model strings, so before M6 they were not recognised as emulated; DMI (QEMU) now marks every disk of a VM virtual.
- This QEMU's kernel reports the NVMe WWID as `nvme.<vid>-<serial>-<model>-<nsid>`, not `eui.…`; the EUI-64 cross-check applies only when the WWID is `eui.`.
- The journal and station key live on the boot disk under `/var/lib/shunya/`. On WSL,
  files under `/mnt/` have no Unix permissions, so a station key there is refused as
  "too open". Host demos use a Linux temp directory.

## Tested in the lab, per milestone
| Milestone | Test (lab/tests, run as root in the VM) | Disks |
|---|---|---|
| M2 | 4 KiB O_DIRECT write + read-back; boot disk and partitions refused; mounted disk refused by the guard and by the kernel (EBUSY); second exclusive opener EBUSY; wrong token and spoofed DMI refused | all five targets |
| M3 | Full 1 GiB overwrite with O_DIRECT, `kill -9` mid-wipe, `--resume`, full read-back verify; the journal shows one unclean stop | SATA HDD |
| M3 | `wipe` of the boot disk refused before any journal exists; device-node journal refused by `wipe`, `wipe --resume` and `journal show` | boot, NVMe |
| M3 | Dry-run plan of the SATA SSD: Clear, flash disclosure, HPA/DCO note; device not opened | SATA SSD |
| M4 | Canary harness: whole-disk HMAC canaries → mkfs → planted JPEG/PDF/DOCX (one copy deleted) → raw scan + photorec **before** (all 6 files carved intact) → `shunya wipe` + `verify` → scan + photorec **after**: 0 tokens, 0 fragments, 0 markers, 0 carved files | virtio × ext4, FAT32, exFAT; NVMe × ext4 |
| M4 | Negative test: `shunya-broken` (skips the last 1 %) on ext4: harness finds 333 488 canary tokens, all in the unwritten tail; full verify exits 4 | SATA SSD |
| M5 | `shunya ata identify` over SG_IO on both AHCI disks: serial, model prefix, WWN, size and rotation rate match sysfs; dumps saved (now `internal/ata/testdata/identify/qemu-*.txt`) and parsed back | SATA SSD, SATA HDD |
| M5 | `shunya ata hidden`: HPA not supported, DCO not supported, native size = reported, fp-v2 computed | SATA SSD, SATA HDD |
| M5 | Refusals: Secure Erase (normal and enhanced) refused at planning and at `--execute` ("does not support the ATA Security feature set"), no journal created; `ata identify` refused on NVMe and virtio with the reason; plans for NVMe/virtio say why HPA/DCO don't apply; USB disk: no ATA answer, disclosed, overwrite still offered | SATA HDD, NVMe, virtio, USB |
| M6 | `shunya nvme identify` over NVME_IOCTL_ADMIN_CMD: serial, model, size match sysfs; SANICAP 0, FNA 0, DLFEAT zeros as recorded; raw data saved and parsed back | NVMe |
| M6 | Real **Format NVM user data erase** through the guarded backend: 1024 markers planted, format, full read-back of zeros (DLFEAT), markers gone; level Clear (virtual) | NVMe |
| M6 | Refusals: crypto Format (FNA bit 2 clear, although QEMU would complete it), all three NVMe Sanitize actions (SANICAP 0), the Sanitize Status log (Invalid Field 0x4002), ATA SANITIZE on the SATA disks (not advertised); `shunya plan` on all five targets: every option Clear (virtual), recommendations NVMe → Format user data, others → overwrite | all five targets |

### Forensic tools in the lab VM (M4)
| Tool | Status |
|---|---|
| photorec (testdisk 7.2, Alpine community) | ✅ installed by `lab.sh`; carves JPEG, PDF and DOCX byte-identical from ext4, FAT32 and exFAT, including deleted files |
| foremost | ❌ not packaged for Alpine 3.24 (main/community); photorec is the only carver. Honest gap: a second, independent carver would strengthen the result |
| exFAT, FAT32, ext4 | ✅ `exfatprogs`, `dosfstools`, `e2fsprogs`; kernel `exfat` and `vfat` modules present |
