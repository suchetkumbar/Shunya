# NIST SP 800-88 mapping

How Shunya's methods map to NIST SP 800-88 Rev. 1, *Guidelines for Media Sanitization*,
and what each one can't reach. The rule (design/SAFETY.md §5): never claim a level the
method can't justify.

This mapping follows Rev. 1 (2014). Rev. 2 moves the per-media technique details to
IEEE 2883 but keeps Clear, Purge and Destroy; re-check this table against the current
revision before relying on it.

## The three levels

| Level | Meaning (800-88) | How it is reached |
|---|---|---|
| **Clear** | Protects against simple, non-invasive recovery (reading through the normal block interface, with ordinary tools) | Overwriting every user-addressable location |
| **Purge** | Protects against laboratory recovery | Commands inside the device: ATA Sanitize / Security Erase, NVMe Format with secure erase, NVMe Sanitize, crypto erase |
| **Destroy** | Media can't be used again | Shredding, disintegration, incineration; outside Shunya's scope |

## What Shunya does per media type

| Media | Methods (M5) | Level claimed | Not reached by an overwrite | Purge method |
|---|---|---|---|---|
| HDD (SATA) | Overwrite, 1 pass (+ HPA); ATA Security Erase, normal or enhanced (+ HPA) | Overwrite: Clear. Security Erase: **Purge** (SP 800-88 Rev. 1 App. A, ATA hard disk drives) | Reallocated (grown-defect) sectors; DCO-hidden sectors (disclosed, never removed) | ATA Security Erase (M5); ATA SANITIZE not implemented yet |
| SATA SSD | Overwrite (+ HPA); ATA Security Erase (+ HPA) | Clear for both: a Security Erase's effect on flash is vendor-defined and can't be checked from the host | Over-provisioned, retired and remapped flash blocks; DCO-hidden sectors | ATA SANITIZE block erase / crypto scramble: IDENTIFY reports support (word 59); the commands are not implemented yet |
| NVMe SSD | Overwrite, 1 pass | Clear | Over-provisioned and remapped flash | NVMe Sanitize / Format NVM with crypto or user-data erase (M6) |
| USB flash, SD card | Overwrite, 1 pass | Clear | Controller-managed spare blocks; bridges usually block firmware commands | None reachable through most USB bridges; Destroy for high-sensitivity data |
| USB HDD/SSD (bridge) | Overwrite, 1 pass | Clear | As the underlying media; HPA/DCO (ATA identity can't be tied to the selected device through a bridge, so ATA is not used) | None through bridges yet |
| eMMC | Overwrite, 1 pass | Clear | Spare blocks | eMMC Secure Erase / Sanitize (stretch goal) |
| Virtual disk | Overwrite, 1 pass | Clear (of the virtual disk) | Host-side copies, snapshots, thin provisioning | Sanitize on the host storage |
| Image file | Overwrite, 1 pass | Clear (of the file's current contents) | Earlier copies kept by the host file system (copy-on-write, snapshots, its journal) | — |

Every plan prints these disclosures (`shunya wipe` dry run) and the journal stores the
plan. From Milestone 7 the certificate will carry them.

## Why one pass

800-88 Rev. 1 (Appendix A, ATA hard disk drives) gives Clear as overwriting with a fixed
pattern such as zeros, with one pass as the minimum: one pass is enough on modern drives. For flash, no number of passes
reaches the blocks the controller has hidden, so more passes never turn Clear into
Purge.

Multi-pass schemes come from older guidance written for older drives:
- DoD 5220.22-M: 3 passes.
- Gutmann: 35 passes, tuned to MFM/RLL encodings of the 1980s–90s.

Their reasoning (recovering an overwritten bit from track-edge residue with a magnetic
force microscope) does not carry over to today's recording densities. Experiments on
modern drives (Wright, Kleiman and Sundhar, "Overwriting Hard Drive Data: The Great Wiping
Controversy", ICISS 2008) found single overwritten bits unrecoverable in practice. Later
editions of the DoD manual dropped the overwrite matrix and point to NIST guidance.

**Shunya's default is one random pass.** `--pattern zero,one,random` or `--passes N`
are available for policies that demand them. The plan then says "N passes requested…
extra passes add time, not assurance". Extra passes never raise the claimed level.

## Why a random pattern by default

- **Firmware can't fake it.** Some SSD controllers deduplicate, compress or "trim" runs
  of zeros instead of writing them. An AES-256-CTR keystream is incompressible and
  can't be predicted without the key.
- **It can be verified.** CTR mode is seekable (block *k* = AES(key, *k*)), so a read-back
  regenerates exactly what should be at any offset. A zero pattern can't tell
  "overwritten" apart from "the drive returns zeros for unmapped blocks".

The key is a pattern seed, not a secret. It is stored in the journal, so resume and
verification can regenerate the stream.

## Verification

- **Full read-back** (`--verify`, `shunya verify`): every sector compared with the
  last pass's pattern.
- **Sampled** (`--sample N --seed HEX`): N sectors from a seed. If a share *f* of the
  disk still held old data, all N samples miss it with probability (1−f)^N. The
  result records N, the seed, its source, and the share caught with 95 % probability.
  An operator-chosen seed is labelled as such.
- **Forensic canary harness** (lab): proves end to end, with a carver, that the wipe
  leaves nothing recoverable, and that the harness itself catches a wipe that misses 1 %.
  See design/LAB_CAPABILITIES.md.
- **M8:** sampling with a seed the wiping station can't choose in advance.

800-88 treats verification as part of sanitisation. A certificate without it will
say so.

## ATA Security Erase (Milestone 5)

- **Normal mode** writes binary zeros to all user data (ACS-3 §7.45). `--verify` and
  `--sample` check for zeros.
- **Enhanced mode** writes a vendor pattern, or replaces the media key on self-encrypting
  drives. There is nothing to compare, so verification is refused; the journal records the
  security state before and after instead.
- **Level:** Purge only for a real (not virtual) rotating disk whose IDENTIFY does not say
  "non-rotating". Plan validation rejects a Purge claim for any other media.
  Re-check this against the SP 800-88 revision in force before relying on it.
- **Hidden areas first:** an HPA is removed (volatile) before the erase command, because
  some drives erase only up to the current max. A DCO-hidden range is disclosed as possibly
  not erased.
