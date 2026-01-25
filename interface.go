// Package secure provides unified cryptographic hash functions, secure random
// number generation, and sensitive data masking utilities for Go services.
//
// This package supports multiple hash algorithms with a unified interface:
//   - Argon2id: Recommended for password hashing and OTP codes (memory-hard)
//   - bcrypt: Industry standard for password hashing
//   - SHA-256/SHA-512: Fast hashing for checksums and message authentication
//   - MD5: Legacy support only (NOT recommended for new implementations)
//
// All hash functions implement the Hasher interface, enabling consistent usage
// across different algorithms and easy algorithm switching.
package secure

// Hasher defines a unified interface for hash operations.
// All hash implementations in this package implement this interface.
type Hasher interface {
	// Hash generates a hash from the given plaintext.
	// Returns the hash string and any error encountered.
	// The returned hash format is algorithm-specific and includes any
	// necessary metadata (salt, parameters) for verification.
	Hash(plaintext string) (string, error)

	// Verify checks if the plaintext matches the given hash.
	// Returns true if the plaintext produces the same hash.
	// This method uses constant-time comparison to prevent timing attacks.
	Verify(hash, plaintext string) bool

	// Algorithm returns the name of the hash algorithm.
	Algorithm() string
}

// HashResolver is a simplified interface for hash verification only.
// This is useful when you only need to verify hashes and don't need
// to generate new ones. Compatible with existing Stargate implementations.
type HashResolver interface {
	// Check verifies if the plaintext matches the given hash.
	Check(hash, plaintext string) bool
}
