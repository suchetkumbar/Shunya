# Device fingerprint

A fingerprint binds a certificate to one physical drive (brief §3.8).

## v1 (`fp1:`), Milestone 1

```
fp1 = "fp1:" || hex( SHA-256(
        "shunya-fingerprint-v1\n" ||
        F("model", model) || F("serial", serial) || F("wwid", wwid) ||
        F("firmware", firmware) || F("capacity_bytes", decimal(capacity)) ) )

F(name, value) = name || 0x00 || uint32_be(len(value)) || value
```

- **Tag:** the leading tag separates this hash from every other SHA-256 Shunya computes
  (domain separation).
- **Length prefixes:** these make field boundaries unambiguous. Without them,
  model "AB" with serial "C" would hash the same as "A" with "BC".
- **Inputs:** the values are the strings sysfs reports, with surrounding whitespace and NULs
  trimmed. On SATA, sysfs gets the model and firmware from libata's INQUIRY emulation,
  which truncates them to 16 and 4 characters.
- **Capacity:** this is the capacity sysfs reports (`capacity_source: "sysfs"`). It is the
  capacity the host can see, not the drive's native capacity.
- **Weak fingerprints:** if neither a serial nor a WWID is known, the fingerprint is
  marked `weak`. Two drives of the same model and size would then share it, so a
  certificate must not claim to bind a single drive.
- **Test vector:** `internal/device/fingerprint_test.go`, checked independently with
  `printf … | sha256sum`.

## v2 (planned, Milestone 5)

v2 will hash the full ATA IDENTIFY and NVMe Identify strings and the **native** max capacity
(READ NATIVE MAX and DCO), so a drive with an HPA keeps the same fingerprint before and
after the HPA is removed. Certificates record the fingerprint version.

## What a fingerprint does not prove

The identity strings come from the drive's firmware or from a USB bridge, so a malicious
drive or enclosure can report any values. A fingerprint detects accidental mix-ups and
drive swaps, not a drive that lies about its identity (THREAT_MODEL T11 and T13).
