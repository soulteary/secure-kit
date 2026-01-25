package secure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHasher_Hash(t *testing.T) {
	h := NewBcryptHasher()

	t.Run("basic hash", func(t *testing.T) {
		hash, err := h.Hash("password123")
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.True(t, len(hash) == 60) // bcrypt hash is always 60 chars
	})

	t.Run("different passwords produce different hashes", func(t *testing.T) {
		hash1, err := h.Hash("password1")
		require.NoError(t, err)

		hash2, err := h.Hash("password2")
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("same password produces different hashes (due to salt)", func(t *testing.T) {
		hash1, err := h.Hash("password")
		require.NoError(t, err)

		hash2, err := h.Hash("password")
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("empty password", func(t *testing.T) {
		hash, err := h.Hash("")
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
	})

	t.Run("password too long", func(t *testing.T) {
		// bcrypt has a 72 byte limit
		longPassword := string(make([]byte, 100))
		_, err := h.Hash(longPassword)
		// bcrypt returns an error for passwords exceeding 72 bytes
		assert.Error(t, err)
	})
}

func TestBcryptHasher_Verify(t *testing.T) {
	h := NewBcryptHasher()

	t.Run("correct password", func(t *testing.T) {
		password := "correctPassword123!"
		hash, err := h.Hash(password)
		require.NoError(t, err)

		assert.True(t, h.Verify(hash, password))
	})

	t.Run("incorrect password", func(t *testing.T) {
		hash, err := h.Hash("password123")
		require.NoError(t, err)

		assert.False(t, h.Verify(hash, "wrongpassword"))
	})

	t.Run("invalid hash format", func(t *testing.T) {
		assert.False(t, h.Verify("invalid", "password"))
		assert.False(t, h.Verify("", "password"))
	})

	t.Run("known hash value", func(t *testing.T) {
		// Pre-computed bcrypt hash for "Hello, World!"
		hash := "$2a$10$k8fBIpJInrE70BzYy5rO/OUSt1w2.IX0bWhiMdb2mJEhjheVHDhvK"
		assert.True(t, h.Verify(hash, "Hello, World!"))
		assert.False(t, h.Verify(hash, "Hello, World"))
	})
}

func TestBcryptHasher_CustomCost(t *testing.T) {
	t.Run("custom cost", func(t *testing.T) {
		h := NewBcryptHasher(WithBcryptCost(12))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("minimum cost", func(t *testing.T) {
		h := NewBcryptHasher(WithBcryptCost(bcrypt.MinCost))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("invalid cost is ignored", func(t *testing.T) {
		h := NewBcryptHasher(WithBcryptCost(0))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("cost too high is ignored", func(t *testing.T) {
		h := NewBcryptHasher(WithBcryptCost(100))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})
}

func TestBcryptHasher_Check(t *testing.T) {
	h := NewBcryptHasher()
	hash, err := h.Hash("password")
	require.NoError(t, err)

	assert.True(t, h.Check(hash, "password"))
	assert.False(t, h.Check(hash, "wrong"))
}

func TestBcryptHasher_Algorithm(t *testing.T) {
	h := NewBcryptHasher()
	assert.Equal(t, "bcrypt", h.Algorithm())
}

func TestBcryptResolver(t *testing.T) {
	resolver := &BcryptResolver{}

	t.Run("correct password", func(t *testing.T) {
		hash := "$2a$10$k8fBIpJInrE70BzYy5rO/OUSt1w2.IX0bWhiMdb2mJEhjheVHDhvK"
		assert.True(t, resolver.Check(hash, "Hello, World!"))
	})

	t.Run("incorrect password", func(t *testing.T) {
		hash := "$2a$10$k8fBIpJInrE70BzYy5rO/OUSt1w2.IX0bWhiMdb2mJEhjheVHDhvK"
		assert.False(t, resolver.Check(hash, "Wrong Password"))
	})

	t.Run("invalid hash", func(t *testing.T) {
		assert.False(t, resolver.Check("invalid", "password"))
		assert.False(t, resolver.Check("", "password"))
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
