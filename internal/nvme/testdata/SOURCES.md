# NVMe Identify data

| File | What | Source |
|---|---|---|
| `qemu-id-ctrl.bin` | Identify Controller (4096 bytes) of the lab's QEMU NVMe drive (`nvme` device, serial SHUNYA-NVME-01, QEMU 10.0.13) | `nvme id-ctrl -b` in the lab VM, 2026-11-18 |
| `qemu-id-ns.bin` | Identify Namespace 1 (4096 bytes) of the same drive | `nvme id-ns -b` |
| `*.nvme-cli.txt` | nvme-cli 2.16 / libnvme 1.16.2's decoded text of the same data | `nvme id-ctrl`, `nvme id-ns` |

These are an **emulated** controller, not real hardware. The parser tests compare every
decoded field against nvme-cli's independent decoding (`nvme_test.go`). No public raw
Identify dumps of real drives were found; field offsets were also checked against
libnvme's `src/nvme/types.h` (struct nvme_id_ctrl, nvme_id_ns, nvme_sanitize_log_page).
Everything Sanitize-related is tested against the simulated controller built from these
files and is labelled pending-real-hardware.
