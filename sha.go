package secure

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// SHA256Hasher implements the Hasher interface using SHA-256 algorithm.
// Note: SHA-256 is a fast hash and should NOT be used for password hashing.
// Use it for checksums, message authentication, or other non-password use cases.
type SHA256Hasher struct{}

// NewSHA256Hasher creates a new SHA-256 hasher.
func NewSHA256Hasher() *SHA256Hasher {
	return &SHA256Hasher{}
}

// Hash generates a SHA-256 hash from the given plaintext.
// Returns the hash as a lowercase hex string.
func (h *SHA256Hasher) Hash(plaintext string) (string, error) {
	hash := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(hash[:]), nil
}

// Verify checks if the plaintext matches the given hash.
// Uses constant-time comparison and is case-insensitive for hex strings.
func (h *SHA256Hasher) Verify(hash, plaintext string) bool {
	expected, _ := h.Hash(plaintext)
	return constantTimeEqualHex(hash, expected)
}

// Check implements the HashResolver interface.
func (h *SHA256Hasher) Check(hash, plaintext string) bool {
	return h.Verify(hash, plaintext)
}

// Algorithm returns the name of the hash algorithm.
func (h *SHA256Hasher) Algorithm() string {
	return "sha256"
}

// SHA512Hasher implements the Hasher interface using SHA-512 algorithm.
// Note: SHA-512 is a fast hash and should NOT be used for password hashing.
// Use it for checksums, message authentication, or other non-password use cases.
type SHA512Hasher struct{}

// NewSHA512Hasher creates a new SHA-512 hasher.
func NewSHA512Hasher() *SHA512Hasher {
	return &SHA512Hasher{}
}

// Hash generates a SHA-512 hash from the given plaintext.
// Returns the hash as a lowercase hex string.
func (h *SHA512Hasher) Hash(plaintext string) (string, error) {
	hasher := sha512.New()
	hasher.Write([]byte(plaintext))
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Verify checks if the plaintext matches the given hash.
// Uses constant-time comparison and is case-insensitive for hex strings.
func (h *SHA512Hasher) Verify(hash, plaintext string) bool {
	expected, _ := h.Hash(plaintext)
	return constantTimeEqualHex(hash, expected)
}

// Check implements the HashResolver interface.
func (h *SHA512Hasher) Check(hash, plaintext string) bool {
	return h.Verify(hash, plaintext)
}

// Algorithm returns the name of the hash algorithm.
func (h *SHA512Hasher) Algorithm() string {
	return "sha512"
}

// SHA512Resolver is a zero-allocation implementation of HashResolver for SHA-512.
// This is a drop-in replacement for existing Stargate code.
type SHA512Resolver struct{}

// Check verifies if the plaintext matches the given SHA-512 hash.
func (s *SHA512Resolver) Check(hash, plaintext string) bool {
	return constantTimeEqualHex(hash, GetSHA512Hash(plaintext))
}

// GetSHA512Hash computes the SHA-512 hash of the given text.
// Returns the hash as a lowercase hex string.
// This is a helper function for backward compatibility with existing code.
func GetSHA512Hash(text string) string {
	hasher := sha512.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// GetSHA256Hash computes the SHA-256 hash of the given text.
// Returns the hash as a lowercase hex string.
func GetSHA256Hash(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}
