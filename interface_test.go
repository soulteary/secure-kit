package secure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHasherInterface verifies that all hashers implement the Hasher interface correctly
func TestHasherInterface(t *testing.T) {
	hashers := []Hasher{
		NewArgon2Hasher(),
		NewBcryptHasher(),
		NewSHA256Hasher(),
		NewSHA512Hasher(),
		NewMD5Hasher(),
		NewPlaintextHasher(),
	}

	for _, h := range hashers {
		t.Run(h.Algorithm(), func(t *testing.T) {
			password := "testPassword123!"

			// Test Hash
			hash, err := h.Hash(password)
			require.NoError(t, err)
			assert.NotEmpty(t, hash)

			// Test Verify with correct password
			assert.True(t, h.Verify(hash, password))

			// Test Verify with incorrect password
			assert.False(t, h.Verify(hash, "wrongPassword"))

			// Test Algorithm returns non-empty string
			assert.NotEmpty(t, h.Algorithm())
		})
	}
}

// TestHashResolverInterface verifies that all resolvers implement the HashResolver interface
func TestHashResolverInterface(t *testing.T) {
	resolvers := []struct {
		name     string
		resolver HashResolver
		hasher   Hasher
	}{
		{"Argon2", NewArgon2Hasher(), NewArgon2Hasher()},
		{"Bcrypt", NewBcryptHasher(), NewBcryptHasher()},
		{"SHA256", NewSHA256Hasher(), NewSHA256Hasher()},
		{"SHA512", NewSHA512Hasher(), NewSHA512Hasher()},
		{"MD5", NewMD5Hasher(), NewMD5Hasher()},
		{"Plaintext", NewPlaintextHasher(), NewPlaintextHasher()},
		{"BcryptResolver", &BcryptResolver{}, NewBcryptHasher()},
		{"SHA512Resolver", &SHA512Resolver{}, NewSHA512Hasher()},
		{"MD5Resolver", &MD5Resolver{}, NewMD5Hasher()},
		{"PlaintextResolver", &PlaintextResolver{}, NewPlaintextHasher()},
	}

	for _, tt := range resolvers {
		t.Run(tt.name, func(t *testing.T) {
			password := "testPassword123!"

			hash, err := tt.hasher.Hash(password)
			require.NoError(t, err)

			// Test Check with correct password
			assert.True(t, tt.resolver.Check(hash, password))

			// Test Check with incorrect password
			assert.False(t, tt.resolver.Check(hash, "wrongPassword"))
		})
	}
}

// TestHasherConsistency tests that hashers produce consistent verification results
func TestHasherConsistency(t *testing.T) {
	hashers := []Hasher{
		NewArgon2Hasher(),
		NewBcryptHasher(),
		NewSHA256Hasher(),
		NewSHA512Hasher(),
		NewMD5Hasher(),
		NewPlaintextHasher(),
	}

	passwords := []string{
		"simple",
		"Complex!Password123",
		"测试密码",
		"emoji🔐password",
		"",
	}

	for _, h := range hashers {
		for _, password := range passwords {
			t.Run(h.Algorithm()+"/"+password, func(t *testing.T) {
				hash, err := h.Hash(password)
				require.NoError(t, err)

				// Verify should always return true for correct password
				for i := 0; i < 10; i++ {
					assert.True(t, h.Verify(hash, password))
				}
			})
		}
	}
}

// TestDeterministicHashes tests that non-salted hashes are deterministic
func TestDeterministicHashes(t *testing.T) {
	deterministicHashers := []Hasher{
		NewSHA256Hasher(),
		NewSHA512Hasher(),
		NewMD5Hasher(),
		NewPlaintextHasher(),
	}

	password := "testPassword"

	for _, h := range deterministicHashers {
		t.Run(h.Algorithm(), func(t *testing.T) {
			hash1, err := h.Hash(password)
			require.NoError(t, err)

			hash2, err := h.Hash(password)
			require.NoError(t, err)

			assert.Equal(t, hash1, hash2, "%s should produce deterministic hashes", h.Algorithm())
		})
	}
}

// TestSaltedHashes tests that salted hashes are non-deterministic
func TestSaltedHashes(t *testing.T) {
	saltedHashers := []Hasher{
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
