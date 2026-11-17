package backend

import "unsafe"

// AlignedBuffer returns a zeroed n-byte slice whose first byte sits at an address that is
// a multiple of align (a power of two). O_DIRECT I/O requires this: the kernel DMAs
// straight into the buffer, so it must meet the device's alignment.
//
// Go has no aligned allocator; the idiom is to over-allocate by align bytes and slice
// from the first aligned address. The garbage collector keeps the whole backing array
// alive as long as the returned slice is.
func AlignedBuffer(n, align int) []byte {
	if align <= 0 || align&(align-1) != 0 {
		panic("backend: alignment must be a positive power of two")
	}
	raw := make([]byte, n+align)
	off := 0
	if r := int(uintptr(unsafe.Pointer(&raw[0])) & uintptr(align-1)); r != 0 {
		off = align - r
	}
	return raw[off : off+n : off+n]
}

// IsAligned reports whether b's first byte is align-aligned. An empty slice is not.
func IsAligned(b []byte, align int) bool {
	if len(b) == 0 || align <= 0 {
		return false
	}
	return uintptr(unsafe.Pointer(&b[0]))&uintptr(align-1) == 0
}
