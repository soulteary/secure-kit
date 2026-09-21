package secure

import (
	"testing"
)

// The Argon2 and bcrypt hashers are exercised against these same interfaces
// from the passwd subpackage, where they live -- see passwd/interface_test.go.
// They are the reason that subpackage exists: they are the only thing here
// that needs golang.org/x/crypto.

// TestHasherInterface verifies that all hashers implement the Hasher interface correctly
func TestHasherInterface(t *testing.T) {
	hashers := []Hasher{
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
			mustNoError(t, err)
			wantNotEmpty(t, hash)

			// Test Verify with correct password
			wantTrue(t, h.Verify(hash, password))

			// Test Verify with incorrect password
			wantFalse(t, h.Verify(hash, "wrongPassword"))

			// Test Algorithm returns non-empty string
			wantNotEmpty(t, h.Algorithm())
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
		{"SHA256", NewSHA256Hasher(), NewSHA256Hasher()},
		{"SHA512", NewSHA512Hasher(), NewSHA512Hasher()},
		{"MD5", NewMD5Hasher(), NewMD5Hasher()},
		{"Plaintext", NewPlaintextHasher(), NewPlaintextHasher()},
		{"SHA512Resolver", &SHA512Resolver{}, NewSHA512Hasher()},
		{"MD5Resolver", &MD5Resolver{}, NewMD5Hasher()},
		{"PlaintextResolver", &PlaintextResolver{}, NewPlaintextHasher()},
	}

	for _, tt := range resolvers {
		t.Run(tt.name, func(t *testing.T) {
			password := "testPassword123!"

			hash, err := tt.hasher.Hash(password)
			mustNoError(t, err)

			// Test Check with correct password
			wantTrue(t, tt.resolver.Check(hash, password))

			// Test Check with incorrect password
			wantFalse(t, tt.resolver.Check(hash, "wrongPassword"))
		})
	}
}

// TestHasherConsistency tests that hashers produce consistent verification results
func TestHasherConsistency(t *testing.T) {
	hashers := []Hasher{
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
				mustNoError(t, err)

				// Verify should always return true for correct password
				for i := 0; i < 10; i++ {
					wantTrue(t, h.Verify(hash, password))
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
			mustNoError(t, err)

			hash2, err := h.Hash(password)
			mustNoError(t, err)

			if hash1 != hash2 {
				t.Errorf("%s hashed the same password to %q and then %q", h.Algorithm(), hash1, hash2)
			}
		})
	}
}
