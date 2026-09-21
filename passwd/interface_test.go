package passwd

import (
	"testing"

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
			mustNoError(t, err)
			wantNotEmpty(t, hash)

			wantTrue(t, h.Verify(hash, password))
			wantFalse(t, h.Verify(hash, "wrongPassword"))
			wantNotEmpty(t, h.Algorithm())
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
			mustNoError(t, err)

			wantTrue(t, tt.resolver.Check(hash, password))
			wantFalse(t, tt.resolver.Check(hash, "wrongPassword"))
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
			mustNoError(t, err)

			hash2, err := h.Hash(password)
			mustNoError(t, err)

			if hash1 == hash2 {
				t.Errorf("%s hashed the same password to %q twice; the salt is not random", h.Algorithm(), hash1)
			}

			// But both should verify correctly
			wantTrue(t, h.Verify(hash1, password))
			wantTrue(t, h.Verify(hash2, password))
		})
	}
}
