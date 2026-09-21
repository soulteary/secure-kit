package passwd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secure "github.com/soulteary/secure-kit/v2"
)

// The hashers here moved out of the root package in v2 so that importing it
// stops linking golang.org/x/crypto. These tests are what keeps that move
// honest: they run the root package's own Hasher and HashResolver contracts
// against Argon2 and bcrypt from the outside, so a signature that drifts away
// from secure.Hasher fails here rather than in a caller.

// TestHashersSatisfyTheRootInterfaces is a compile-time and behavioural check
// in one: the slice literal will not build unless both hashers still implement
// secure.Hasher.
func TestHashersSatisfyTheRootInterfaces(t *testing.T) {
	hashers := []secure.Hasher{
		NewArgon2Hasher(),
		NewBcryptHasher(),
	}

	for _, h := range hashers {
		t.Run(h.Algorithm(), func(t *testing.T) {
			password := "testPassword123!"

			hash, err := h.Hash(password)
			require.NoError(t, err)
			assert.NotEmpty(t, hash)

			assert.True(t, h.Verify(hash, password))
			assert.False(t, h.Verify(hash, "wrongPassword"))
			assert.NotEmpty(t, h.Algorithm())
		})
	}
}

// TestResolversSatisfyTheRootInterface does the same for secure.HashResolver.
func TestResolversSatisfyTheRootInterface(t *testing.T) {
	resolvers := []struct {
		name     string
		resolver secure.HashResolver
		hasher   secure.Hasher
	}{
		{"Argon2", NewArgon2Hasher(), NewArgon2Hasher()},
		{"Bcrypt", NewBcryptHasher(), NewBcryptHasher()},
		{"BcryptResolver", &BcryptResolver{}, NewBcryptHasher()},
	}

	for _, tt := range resolvers {
		t.Run(tt.name, func(t *testing.T) {
			password := "testPassword123!"

			hash, err := tt.hasher.Hash(password)
			require.NoError(t, err)

			assert.True(t, tt.resolver.Check(hash, password))
			assert.False(t, tt.resolver.Check(hash, "wrongPassword"))
		})
	}
}

// TestSaltedHashes tests that salted hashes are non-deterministic
func TestSaltedHashes(t *testing.T) {
	saltedHashers := []secure.Hasher{
		NewArgon2Hasher(),
		NewBcryptHasher(),
	}

	password := "testPassword"

	for _, h := range saltedHashers {
		t.Run(h.Algorithm(), func(t *testing.T) {
			hash1, err := h.Hash(password)
			require.NoError(t, err)

			hash2, err := h.Hash(password)
			require.NoError(t, err)

			assert.NotEqual(t, hash1, hash2, "%s should produce different hashes due to salt", h.Algorithm())

			// But both should verify correctly
			assert.True(t, h.Verify(hash1, password))
			assert.True(t, h.Verify(hash2, password))
		})
	}
}
