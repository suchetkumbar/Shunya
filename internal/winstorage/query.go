package winstorage

import (
	"fmt"
)

// STORAGE_PROPERTY_ID values used here.
const (
	PropDevice                  = 0
	PropAccessAlignment         = 6
	PropSeekPenalty             = 7
	PropAdapterProtocolSpecific = 49
	PropDeviceProtocolSpecific  = 50
)

// PropertyQuery encodes STORAGE_PROPERTY_QUERY {PropertyId, QueryType =
// PropertyStandardQuery, AdditionalParameters[1]} (12 bytes with padding).
func PropertyQuery(id uint32) []byte {
	b := make([]byte, 12)
	le.PutUint32(b, id)
	return b
}

// NVMe protocol-specific queries (STORAGE_PROTOCOL_SPECIFIC_DATA, ntddstor.h).
const (
	protocolTypeNVMe     = 3
	nvmeDataTypeIdentify = 1

	protoSpecificSize = 40 // STORAGE_PROTOCOL_SPECIFIC_DATA: ten ULONGs
	protoQueryHeader  = 8  // STORAGE_PROPERTY_QUERY up to AdditionalParameters
	protoDescHeader   = 8  // STORAGE_PROTOCOL_DATA_DESCRIPTOR: Version, Size

	// NVMeIdentifyBytes is the Identify data size.
	NVMeIdentifyBytes = 4096
)

// NVMeIdentifyQuery builds the IOCTL_STORAGE_QUERY_PROPERTY input that asks StorNVMe for
// an Identify data structure: StorageAdapterProtocolSpecificProperty for the controller
// (CNS 01h), StorageDeviceProtocolSpecificProperty for a namespace (CNS 00h, nsid). The
// same buffer receives the answer (see ParseNVMeIdentify). Windows passes only Identify,
// Get Log Page and Get Features this way; Format NVM and Sanitize are not available to
// applications through StorNVMe, which is why Shunya does not offer them on Windows.
func NVMeIdentifyQuery(cns uint8, nsid uint32) ([]byte, error) {
	prop := uint32(PropAdapterProtocolSpecific)
	switch cns {
	case 0x01:
		if nsid != 0 {
			return nil, fmt.Errorf("winstorage: Identify Controller takes no namespace (got %d)", nsid)
		}
	case 0x00:
		if nsid == 0 || nsid == 0xffffffff {
			return nil, fmt.Errorf("winstorage: Identify Namespace needs one namespace (got %#x)", nsid)
		}
		prop = PropDeviceProtocolSpecific
	default:
		return nil, fmt.Errorf("winstorage: Identify CNS %#02x is not supported on Windows", cns)
	}
	b := make([]byte, protoQueryHeader+protoSpecificSize+NVMeIdentifyBytes)
	le.PutUint32(b, prop)
	p := b[protoQueryHeader:]
	le.PutUint32(p[0:], protocolTypeNVMe)
	le.PutUint32(p[4:], nvmeDataTypeIdentify)
	le.PutUint32(p[8:], uint32(cns))
	le.PutUint32(p[12:], nsid)
	le.PutUint32(p[16:], protoSpecificSize) // data follows the structure
	le.PutUint32(p[20:], NVMeIdentifyBytes)
	return b, nil
}

// ParseNVMeIdentify extracts the 4096 Identify bytes from the answer to
// NVMeIdentifyQuery: STORAGE_PROTOCOL_DATA_DESCRIPTOR {Version, Size,
// STORAGE_PROTOCOL_SPECIFIC_DATA}, with the data at ProtocolDataOffset from the start of
// the protocol-specific structure. The checks are those of Microsoft's sample code.
func ParseNVMeIdentify(b []byte) ([]byte, error) {
	const descSize = protoDescHeader + protoSpecificSize
	if len(b) < descSize {
		return nil, fmt.Errorf("%w: STORAGE_PROTOCOL_DATA_DESCRIPTOR is %d bytes", ErrShort, len(b))
	}
	if v, s := le.Uint32(b), le.Uint32(b[4:]); v != descSize || s != descSize {
		return nil, fmt.Errorf("winstorage: protocol data descriptor version %d size %d, want %d", v, s, descSize)
	}
	p := b[protoDescHeader:]
	if t := le.Uint32(p); t != protocolTypeNVMe {
		return nil, fmt.Errorf("winstorage: protocol type %d, not NVMe", t)
	}
	off, n := uint64(le.Uint32(p[16:])), uint64(le.Uint32(p[20:]))
	if off < protoSpecificSize || n < NVMeIdentifyBytes || protoDescHeader+off+NVMeIdentifyBytes > uint64(len(b)) {
		return nil, fmt.Errorf("%w: identify data at offset %d, %d bytes, in a %d-byte buffer", ErrShort, off, n, len(b))
	}
	start := protoDescHeader + off
	out := make([]byte, NVMeIdentifyBytes)
	copy(out, b[start:start+NVMeIdentifyBytes])
	return out, nil
}
