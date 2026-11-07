package secure

import (
	"crypto/subtle"
	"strings"
)

func constantTimeEqualString(a, b string) bool {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	aa := make([]byte, maxLen)
	bb := make([]byte, maxLen)
	copy(aa, a)
	copy(bb, b)

	return subtle.ConstantTimeCompare(aa, bb) == 1 && len(a) == len(b)
}

// constantTimeEqualHex compares two hex strings in constant time (case-insensitive).
// Both are normalized to lowercase and padded to the longer input length before
// comparison. Normalization and allocation are not fixed-cost operations across
// different inputs. Used by SHA and MD5 Verify/Check.
func constantTimeEqualHex(a, b string) bool {
	return constantTimeEqualString(strings.ToLower(a), strings.ToLower(b))
}

// ConstantTimeEqual compares two strings in constant time to prevent timing attacks.
// This should be used when comparing sensitive values like API keys, tokens, or hashes.
//
// For fixed input lengths, comparison work does not depend on the matching
// prefix. Both strings are copied into buffers sized to the longer input;
// allocation and copying costs therefore vary with input length.
func ConstantTimeEqual(a, b string) bool {
	return constantTimeEqualString(a, b)
}

// ConstantTimeEqualBytes compares two byte slices in constant time.
// Comparison work does not depend on the matching prefix for fixed input lengths;
// allocation and copying costs vary with the longer input length.
func ConstantTimeEqualBytes(a, b []byte) bool {
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}

	aa := make([]byte, maxLen)
	bb := make([]byte, maxLen)
	copy(aa, a)
	copy(bb, b)

	return subtle.ConstantTimeCompare(aa, bb) == 1 && len(a) == len(b)
}

// SecureCompare compares two strings and returns true if they are equal.
// This is an alias for ConstantTimeEqual for API compatibility.
func SecureCompare(a, b string) bool {
	return ConstantTimeEqual(a, b)
}

// TimingSafeEqual is another alias for ConstantTimeEqual.
// Named to match Python's hmac.compare_digest and Ruby's ActiveSupport::SecurityUtils.
func TimingSafeEqual(a, b string) bool {
	return ConstantTimeEqual(a, b)
}
