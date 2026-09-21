// Package secure provides unified cryptographic hash functions, secure random
// number generation, constant-time comparison, HMAC verification, and sensitive
// data masking utilities for Go services.
//
// It depends on nothing outside the standard library. The password hashers are
// the exception that proves the rule: Argon2id and bcrypt need
// golang.org/x/crypto, so since v2 they live in the passwd subpackage and a
// service importing this package for RandomHex or ConstantTimeEqual no longer
// links, ships or audits a cryptographic library it never calls.
//
// Hash algorithms, with a unified interface:
//   - Argon2id: recommended for password hashing and OTP codes (memory-hard) -- passwd subpackage
//   - bcrypt: industry standard for password hashing -- passwd subpackage
//   - SHA-256/SHA-512: fast hashing for checksums and message authentication
//   - MD5: legacy support only (NOT recommended for new implementations)
//
// All of them implement the Hasher interface, wherever they live, so switching
// algorithms is a constructor change and the subpackage boundary costs a caller
// nothing beyond one import.
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
