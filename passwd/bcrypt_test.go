package passwd

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHasher_Hash(t *testing.T) {
	h := NewBcryptHasher()

	t.Run("basic hash", func(t *testing.T) {
		hash, err := h.Hash("password123")
		mustNoError(t, err)
		wantNotEmpty(t, hash)
		wantTrue(t, len(hash) == 60) // bcrypt hash is always 60 chars
	})

	t.Run("different passwords produce different hashes", func(t *testing.T) {
		hash1, err := h.Hash("password1")
		mustNoError(t, err)

		hash2, err := h.Hash("password2")
		mustNoError(t, err)

		wantNotEqual(t, hash1, hash2)
	})

	t.Run("same password produces different hashes (due to salt)", func(t *testing.T) {
		hash1, err := h.Hash("password")
		mustNoError(t, err)

		hash2, err := h.Hash("password")
		mustNoError(t, err)

		wantNotEqual(t, hash1, hash2)
	})

	t.Run("empty password", func(t *testing.T) {
		hash, err := h.Hash("")
		mustNoError(t, err)
		wantNotEmpty(t, hash)
	})

	t.Run("password too long", func(t *testing.T) {
		// bcrypt has a 72 byte limit
		longPassword := string(make([]byte, 100))
		_, err := h.Hash(longPassword)
		// bcrypt returns an error for passwords exceeding 72 bytes
		wantError(t, err)
	})
}

func TestBcryptHasher_Verify(t *testing.T) {
	h := NewBcryptHasher()

	t.Run("correct password", func(t *testing.T) {
		password := "correctPassword123!"
		hash, err := h.Hash(password)
		mustNoError(t, err)

		wantTrue(t, h.Verify(hash, password))
	})

	t.Run("incorrect password", func(t *testing.T) {
		hash, err := h.Hash("password123")
		mustNoError(t, err)

		wantFalse(t, h.Verify(hash, "wrongpassword"))
	})

	t.Run("invalid hash format", func(t *testing.T) {
		wantFalse(t, h.Verify("invalid", "password"))
		wantFalse(t, h.Verify("", "password"))
	})

	t.Run("known hash value", func(t *testing.T) {
		// Pre-computed bcrypt hash for "Hello, World!"
		hash := "$2a$10$k8fBIpJInrE70BzYy5rO/OUSt1w2.IX0bWhiMdb2mJEhjheVHDhvK"
		wantTrue(t, h.Verify(hash, "Hello, World!"))
		wantFalse(t, h.Verify(hash, "Hello, World"))
	})
}

func TestBcryptHasher_CustomCost(t *testing.T) {
	t.Run("custom cost", func(t *testing.T) {
		h := NewBcryptHasher(WithBcryptCost(12))
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})

	t.Run("minimum cost", func(t *testing.T) {
		h := NewBcryptHasher(WithBcryptCost(bcrypt.MinCost))
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})

	// Silently keeping the default meant WithBcryptCost(14) produced cost-10
	// hashes: weaker than the caller asked for, with nothing to reveal it.
	t.Run("invalid cost is rejected", func(t *testing.T) {
		_, err := NewBcryptHasherStrict(WithBcryptCost(0))
		mustError(t, err)
		wantContains(t, err.Error(), "out of range")

		wantPanic(t, func() { NewBcryptHasher(WithBcryptCost(0)) })
	})

	t.Run("cost too high is rejected", func(t *testing.T) {
		_, err := NewBcryptHasherStrict(WithBcryptCost(100))
		mustError(t, err)
	})

	t.Run("valid cost applies", func(t *testing.T) {
		h, err := NewBcryptHasherStrict(WithBcryptCost(bcrypt.MinCost + 1))
		mustNoError(t, err)
		wantEqual(t, bcrypt.MinCost+1, h.cost)
	})
}

func TestBcryptHasher_Check(t *testing.T) {
	h := NewBcryptHasher()
	hash, err := h.Hash("password")
	mustNoError(t, err)

	wantTrue(t, h.Check(hash, "password"))
	wantFalse(t, h.Check(hash, "wrong"))
}

func TestBcryptHasher_Algorithm(t *testing.T) {
	h := NewBcryptHasher()
	wantEqual(t, "bcrypt", h.Algorithm())
}

func TestBcryptResolver(t *testing.T) {
	resolver := &BcryptResolver{}

	t.Run("correct password", func(t *testing.T) {
		hash := "$2a$10$k8fBIpJInrE70BzYy5rO/OUSt1w2.IX0bWhiMdb2mJEhjheVHDhvK"
		wantTrue(t, resolver.Check(hash, "Hello, World!"))
	})

	t.Run("incorrect password", func(t *testing.T) {
		hash := "$2a$10$k8fBIpJInrE70BzYy5rO/OUSt1w2.IX0bWhiMdb2mJEhjheVHDhvK"
		wantFalse(t, resolver.Check(hash, "Wrong Password"))
	})

	t.Run("invalid hash", func(t *testing.T) {
		wantFalse(t, resolver.Check("invalid", "password"))
		wantFalse(t, resolver.Check("", "password"))
	})
}

func BenchmarkBcryptHash(b *testing.B) {
	h := NewBcryptHasher(WithBcryptCost(bcrypt.MinCost))
	password := "benchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(password)
	}
}

func BenchmarkBcryptVerify(b *testing.B) {
	h := NewBcryptHasher(WithBcryptCost(bcrypt.MinCost))
	hash, _ := h.Hash("benchmarkPassword123!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Verify(hash, "benchmarkPassword123!")
	}
}
