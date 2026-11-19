# Demo: three disks wiped in parallel from the TUI, certified, logged, verified

This reproduces the Milestone 9 demo in the lab VM in under 10 minutes. Nothing runs on
the host's disks: the VM's target disks are image files under `lab/images/`, and every
destructive step happens inside the VM.

## Before you start (one-time, not counted in the 10 minutes)

The lab from Milestone 0 must exist: WSL2 Debian (or Linux) with KVM and QEMU, Go 1.27.4,
and the lab images (`make lab-images`, which downloads the 149 MiB Alpine cloud image and
creates the target images). See `SAFETY.md` §6 for exactly what was installed.

## The demo

```sh
make lab-up      # boots the disposable VM (about 15–40 s)
make lab-demo    # builds the lab binaries, pushes them, and starts the demo in the VM
```

`make lab-demo` runs `lab/demo.sh` inside the VM as root.

**Step 1: keys and the log (automatic, a few seconds)**
- an offline organisation root (`keys init-root`);
- a station key, certified by the root (`keys issue-station`, station `demo-bay`);
- a transparency log on `127.0.0.1:8080` inside the VM (`shunya-verify serve`).

**Step 2: the TUI (you)**

Press Enter and the TUI opens on three disks of different kinds: virtio-blk, emulated SATA HDD and emulated NVMe.

1. **Pick:** Space selects a disk, ↓ moves; select all three, then Enter.
2. **Confirm:** for each disk, type the last 4 characters of the serial shown on screen
   (`E-01`, `D-01`, `O-01`), then Enter. A wrong entry is refused and nothing starts.
3. **Plan:** the screen shows each disk's method, NIST SP 800-88 level, estimate and
   verification. The NVMe disk gets `nvme-format-user-data-erase` (the drive's own erase),
   the other two an overwrite. Nothing has been written yet. Enter starts the wipes; Esc
   goes back to the list. (Since Milestone 10 the plan comes after the confirmations, so
   a release build may identify the drive before planning.)
4. **Progress:** all three wipe at the same time, each with its own bar and phase:
   wiping → verifying → certificate issued → logged. Ctrl+C twice would stop them; the
   journals allow a resume.
5. **Result:** each disk shows "erased and verified", its certificate ID, the JSON and PDF
   paths, its log entry and its QR address. Then the batch manifest. Enter exits.

**Step 3: independent checks (automatic)**
- every certificate, with `shunya-verify --require-log`;
- the batch manifest and all its certificates, with `shunya-verify manifest --certs`;
- the whole log, with `shunya-verify audit`.

```sh
make lab-down
```

## What you should see

```
VALID certificate 6cff6eea…   nvme-format-user-data-erase, NIST SP 800-88 CLEAR
VALID certificate 0fcddcf0…   overwrite, NIST SP 800-88 CLEAR
VALID certificate 2abbd0d1…   overwrite, NIST SP 800-88 CLEAR
BATCH COMPLETE  manifest 65364fb2…  3 device(s): 3 certified, 0 not
  log: entry 3, proof verified against checkpoint 127.0.0.1:8080/log size 4
AUDIT PASSED: log 127.0.0.1:8080/log, 4 entries (3 certificates, 1 batch manifest(s), …)
```

Every level is **Clear**, because the lab's disks are virtual. A Format NVM on a real NVMe
SSD can reach Purge (see `NIST_MAPPING.md`); the lab cannot show that.

## Timing (measured 2026-11-19, i7-12700H, WSL2)

| Step | Time |
|---|---|
| `make build-lab` (warm cache) | 4 s |
| `make lab-up` | 37 s |
| keys, log, three 1 GiB wipes in parallel, verification and audit | 32 s (script run end to end with `DEMO_WIPE=fleet`, which runs the same wipes without the keyboard) |
| the same wipes from the TUI, by keystrokes on a terminal | 40–42 s, in `TestLabTUIFleet` |
| a person reading the screens and typing three confirmations | about 1–2 min |
| **Total** | **about 3–4 minutes** |

## Variants

- **Non-interactive:** `DEMO_WIPE=fleet bash lab/lab.sh demo`. The wipe step runs
  `shunya fleet --execute --approved … --yes-really`, the same code path without the
  TUI. This is how the script itself was checked.
- **One-click mode:** in the VM (`make lab-shell`, then `doas -s`), run
  `~/demo/shunya tui --simple --journal-dir DIR --key KEY /dev/sdc`. You get one disk,
  the recommended method, one confirmation, and large status text (READY → WIPING 43 %
  → CHECKING → DONE). `TestLabTUISimple` runs exactly this.
- **Without the VM, on image files:** `shunya tui --image a.img --image b.img
  --journal-dir DIR --key KEY` works on any Linux or WSL machine. Image files need no lab
  lock. `TestTUILiveImages` runs it with three images.
- **Lab tests:** `LAB_RUN='^TestLabTUI' make lab-test` runs both TUI acceptance tests on a
  real pseudo-terminal inside the VM.
- **The live image (Milestone 10):** `make lab-up && make lab-iso-test` builds the ISO in
  the VM and boots it in QEMU as a USB stick. The stick appears as PROTECTED ("boot medium
  of this Shunya live system"). Three disks are wiped from its TUI over the serial console,
  and the certificates it prints verify. This takes about 20 s once built. To watch it,
  boot `lab/images/live/shunya-live.iso` with any QEMU command line that uses only image
  files (see `lab/iso/iso_test.go`), and type `serial` at the `boot:` prompt.
