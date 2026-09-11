package secure

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// Default bcrypt cost factor
// The cost factor determines the computational cost of hashing.
// A value of 10 is a reasonable default; increase for higher security.
const DefaultBcryptCost = bcrypt.DefaultCost // 10

// BcryptHasher implements the Hasher interface using bcrypt algorithm.
// bcrypt is an industry-standard password hashing algorithm that automatically
// handles salt generation and includes the salt in the hash output.
type BcryptHasher struct {
	cost int

	// optErrs collects rejected option values.
	optErrs []error
}

// BcryptOption is a function that configures a BcryptHasher.
//
// An option given an out-of-range value records an error rather than silently
// keeping the default: WithBcryptCost(14) quietly leaving the cost at 10 gives
// the caller hashes weaker than the ones they asked for.
type BcryptOption func(*BcryptHasher)

// WithBcryptCost sets the bcrypt cost factor.
// Valid range is bcrypt.MinCost (4) to bcrypt.MaxCost (31).
// Higher values increase security but also computation time.
func WithBcryptCost(cost int) BcryptOption {
	return func(h *BcryptHasher) {
		if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
			h.optErrs = append(h.optErrs, fmt.Errorf("WithBcryptCost: %d out of range (%d..%d)", cost, bcrypt.MinCost, bcrypt.MaxCost))
			return
		}
		h.cost = cost
	}
}

// NewBcryptHasher creates a new bcrypt hasher with default or custom
// parameters. It panics if an option was given an out-of-range value; use
// NewBcryptHasherStrict to handle that as an error.
func NewBcryptHasher(opts ...BcryptOption) *BcryptHasher {
	h, err := NewBcryptHasherStrict(opts...)
	if err != nil {
		panic("secure: " + err.Error())
	}
	return h
}

// NewBcryptHasherStrict is NewBcryptHasher, reporting invalid option values
// instead of panicking.
func NewBcryptHasherStrict(opts ...BcryptOption) (*BcryptHasher, error) {
	h := &BcryptHasher{
		cost: DefaultBcryptCost,
	}

	for _, opt := range opts {
		opt(h)
	}

	if len(h.optErrs) > 0 {
		return nil, errors.Join(h.optErrs...)
	}
	return h, nil
}

// Hash generates a bcrypt hash from the given plaintext.
// The returned hash includes the salt and cost factor.
func (h *BcryptHasher) Hash(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), h.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Verify checks if the plaintext matches the given hash.
// Returns true if the plaintext produces the same hash.
func (h *BcryptHasher) Verify(hash, plaintext string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
	return err == nil
}

// Check implements the HashResolver interface.
// Compatible with existing Stargate implementations.
func (h *BcryptHasher) Check(hash, plaintext string) bool {
	return h.Verify(hash, plaintext)
}

// Algorithm returns the name of the hash algorithm.
func (h *BcryptHasher) Algorithm() string {
	return "bcrypt"
}

// BcryptResolver is a zero-allocation implementation of HashResolver for bcrypt.
// This is a drop-in replacement for existing Stargate code.
type BcryptResolver struct{}

// Check verifies if the plaintext matches the given bcrypt hash.
func (b *BcryptResolver) Check(hash, plaintext string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
	return err == nil
}
