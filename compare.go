package secure

import (
	"crypto/subtle"
)

// ConstantTimeEqual compares two strings in constant time to prevent timing attacks.
// This should be used when comparing sensitive values like API keys, tokens, or hashes.
//
// Unlike simple == comparison, this function takes the same amount of time
// regardless of how many characters match, preventing attackers from learning
// information about the secret value through timing analysis.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ConstantTimeEqualBytes compares two byte slices in constant time.
func ConstantTimeEqualBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
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
