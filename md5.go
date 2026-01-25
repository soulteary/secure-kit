package secure

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

// MD5Hasher implements the Hasher interface using MD5 algorithm.
//
// WARNING: MD5 is cryptographically broken and should NOT be used for:
//   - Password hashing
//   - Security-critical applications
//   - New implementations
//
// This is provided ONLY for backward compatibility with legacy systems.
// For new implementations, use Argon2 or bcrypt instead.
type MD5Hasher struct{}

// NewMD5Hasher creates a new MD5 hasher.
// Consider using NewArgon2Hasher or NewBcryptHasher for new implementations.
func NewMD5Hasher() *MD5Hasher {
	return &MD5Hasher{}
}

// Hash generates an MD5 hash from the given plaintext.
// Returns the hash as a lowercase hex string.
func (h *MD5Hasher) Hash(plaintext string) (string, error) {
	hash := md5.Sum([]byte(plaintext))
	return hex.EncodeToString(hash[:]), nil
}

// Verify checks if the plaintext matches the given hash.
// Comparison is case-insensitive for hex strings.
func (h *MD5Hasher) Verify(hash, plaintext string) bool {
	// MD5 Hash() never returns an error, so we can safely ignore it
	expected, _ := h.Hash(plaintext)
	return strings.EqualFold(hash, expected)
}

// Check implements the HashResolver interface.
func (h *MD5Hasher) Check(hash, plaintext string) bool {
	return h.Verify(hash, plaintext)
}

// Algorithm returns the name of the hash algorithm.
func (h *MD5Hasher) Algorithm() string {
	return "md5"
}

// MD5Resolver is a zero-allocation implementation of HashResolver for MD5.
// This is a drop-in replacement for existing Stargate code.
//
// WARNING: MD5 is cryptographically broken. Use only for legacy compatibility.
type MD5Resolver struct{}

// Check verifies if the plaintext matches the given MD5 hash.
func (m *MD5Resolver) Check(hash, plaintext string) bool {
	return strings.EqualFold(hash, GetMD5Hash(plaintext))
}

// GetMD5Hash computes the MD5 hash of the given text.
// Returns the hash as a lowercase hex string.
// This is a helper function for backward compatibility with existing code.
//
// WARNING: MD5 is cryptographically broken. Use only for legacy compatibility.
func GetMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}
