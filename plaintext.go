package secure

import (
	"crypto/subtle"
)

// PlaintextHasher implements the Hasher interface for plaintext comparison.
//
// WARNING: This does NOT actually hash anything. It is provided ONLY for:
//   - Testing and development environments
//   - Migration from legacy systems
//
// NEVER use this in production for security-sensitive applications.
type PlaintextHasher struct{}

// NewPlaintextHasher creates a new plaintext "hasher".
// Consider using NewArgon2Hasher or NewBcryptHasher for any real use case.
func NewPlaintextHasher() *PlaintextHasher {
	return &PlaintextHasher{}
}

// Hash returns the plaintext unchanged.
// This does NOT provide any security.
func (h *PlaintextHasher) Hash(plaintext string) (string, error) {
	return plaintext, nil
}

// Verify checks if the plaintext matches the given "hash".
// Uses constant-time comparison to prevent timing attacks.
func (h *PlaintextHasher) Verify(hash, plaintext string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(plaintext)) == 1
}

// Check implements the HashResolver interface.
func (h *PlaintextHasher) Check(hash, plaintext string) bool {
	return h.Verify(hash, plaintext)
}

// Algorithm returns the name of the hash algorithm.
func (h *PlaintextHasher) Algorithm() string {
	return "plaintext"
}

// PlaintextResolver is a zero-allocation implementation of HashResolver for plaintext.
// This is a drop-in replacement for existing Stargate code.
//
// WARNING: This provides NO security. Use only for testing.
type PlaintextResolver struct{}

// Check verifies if the plaintext matches the given "hash".
func (p *PlaintextResolver) Check(hash, plaintext string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(plaintext)) == 1
}
