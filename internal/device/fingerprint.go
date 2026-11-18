package device

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// FingerprintInput holds the identity fields a fingerprint binds (brief §3.8).
type FingerprintInput struct {
	Model         string
	Serial        string
	WWID          string
	Firmware      string
	CapacityBytes uint64
}

// Fingerprint is a stable identity hash for one physical drive.
type Fingerprint struct {
	Version int    `json:"version"`
	Value   string `json:"value"` // "fp1:" + hex SHA-256
	// Weak: neither serial nor WWID is known, so two identical models of the same size
	// share a fingerprint. A certificate must not claim to bind one physical drive then.
	Weak bool `json:"weak"`
	// CapacitySource: "sysfs" in v1 (user-visible capacity). Native max capacity, which
	// includes HPA/DCO-hidden sectors, needs ATA commands and arrives with v2 (Milestone 5).
	CapacitySource string `json:"capacity_source"`
}

const fingerprintTagV1 = "shunya-fingerprint-v1\n"

// ComputeFingerprint returns the v1 fingerprint:
//
//	SHA-256( "shunya-fingerprint-v1\n" ||
//	         for each field in order model, serial, wwid, firmware, capacity_bytes:
//	             name || 0x00 || uint32_be(len(value)) || value )
//
// Length prefixes make field boundaries unambiguous ("AB"+"C" ≠ "A"+"BC"); the tag
// separates this hash from every other SHA-256 Shunya computes (domain separation).
func ComputeFingerprint(in FingerprintInput) Fingerprint {
	h := sha256.New()
	h.Write([]byte(fingerprintTagV1))
	field := func(name, value string) {
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value))))
		h.Write([]byte(value))
	}
	field("model", in.Model)
	field("serial", in.Serial)
	field("wwid", in.WWID)
	field("firmware", in.Firmware)
	field("capacity_bytes", strconv.FormatUint(in.CapacityBytes, 10))
	return Fingerprint{
		Version:        1,
		Value:          "fp1:" + hex.EncodeToString(h.Sum(nil)),
		Weak:           strings.TrimSpace(in.Serial) == "" && strings.TrimSpace(in.WWID) == "",
		CapacitySource: "sysfs",
	}
}

const fingerprintTagV2 = "shunya-fingerprint-v2\n"

// ComputeFingerprintV2 is v1 plus the drive's native capacity (READ NATIVE MAX
// ADDRESS: user-visible sectors and any HPA), which only ATA commands can read:
//
//	SHA-256( "shunya-fingerprint-v2\n" || the v1 fields ||
//	         "native_capacity_bytes" || 0x00 || uint32_be(len) || decimal )
//
// Two drives that differ only in a hidden area get different v2 fingerprints. A DCO
// can still hide sectors beyond the native maximum; the plan reports that separately.
func ComputeFingerprintV2(in FingerprintInput, nativeBytes uint64) Fingerprint {
	h := sha256.New()
	h.Write([]byte(fingerprintTagV2))
	field := func(name, value string) {
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value))))
		h.Write([]byte(value))
	}
	field("model", in.Model)
	field("serial", in.Serial)
	field("wwid", in.WWID)
	field("firmware", in.Firmware)
	field("capacity_bytes", strconv.FormatUint(in.CapacityBytes, 10))
	field("native_capacity_bytes", strconv.FormatUint(nativeBytes, 10))
	return Fingerprint{
		Version:        2,
		Value:          "fp2:" + hex.EncodeToString(h.Sum(nil)),
		Weak:           strings.TrimSpace(in.Serial) == "" && strings.TrimSpace(in.WWID) == "",
		CapacitySource: "ata-native-max",
	}
}
