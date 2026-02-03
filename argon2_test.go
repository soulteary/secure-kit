package secure

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// argon2ErrorReader is a mock reader that always returns an error.
type argon2ErrorReader struct{}

func (e *argon2ErrorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("mock random source error")
}

func TestArgon2Hasher_Hash(t *testing.T) {
	h := NewArgon2Hasher()

	t.Run("basic hash", func(t *testing.T) {
		hash, err := h.Hash("password123")
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.Contains(t, hash, ":")
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
}

func TestArgon2Hasher_HashWithParams(t *testing.T) {
	h := NewArgon2Hasher()

	t.Run("PHC format", func(t *testing.T) {
		hash, err := h.HashWithParams("password123")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(hash, "$argon2id$"))
		assert.Contains(t, hash, "$v=")
		assert.Contains(t, hash, "$m=")
	})
}

func TestArgon2Hasher_Verify(t *testing.T) {
	h := NewArgon2Hasher()

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

	t.Run("PHC format verification", func(t *testing.T) {
		password := "testPassword"
		hash, err := h.HashWithParams(password)
		require.NoError(t, err)

		assert.True(t, h.Verify(hash, password))
		assert.False(t, h.Verify(hash, "wrongPassword"))
	})

	t.Run("invalid hash format", func(t *testing.T) {
		assert.False(t, h.Verify("invalid", "password"))
		assert.False(t, h.Verify("", "password"))
		assert.False(t, h.Verify("no:colon:here:extra", "password"))
	})

	t.Run("invalid base64 salt in simple format", func(t *testing.T) {
		// Invalid base64 in salt part
		assert.False(t, h.Verify("!!!invalid-base64!!!:validhash", "password"))
	})

	t.Run("invalid base64 hash in simple format", func(t *testing.T) {
		// Valid base64 salt but invalid base64 hash
		assert.False(t, h.Verify("dGVzdHNhbHQ=:!!!invalid-base64!!!", "password"))
	})

	t.Run("invalid PHC format verification", func(t *testing.T) {
		// Invalid PHC format should return false
		assert.False(t, h.Verify("$argon2id$v=19$invalid", "password"))
		assert.False(t, h.Verify("$argon2id$v=19$m=abc,t=1,p=4$salt$hash", "password"))
	})

	t.Run("PHC with excessive parameters rejected (DoS prevention)", func(t *testing.T) {
		// Valid base64 salt (16 bytes) and hash (32 bytes); memory exceeds maxArgon2MemoryKB
		malicious := "$argon2id$v=19$m=999999999,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		assert.False(t, h.Verify(malicious, "password"))
		// Excessive time
		maliciousT := "$argon2id$v=19$m=65536,t=999,p=4$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		assert.False(t, h.Verify(maliciousT, "password"))
	})

	t.Run("empty password verification", func(t *testing.T) {
		hash, err := h.Hash("")
		require.NoError(t, err)

		assert.True(t, h.Verify(hash, ""))
		assert.False(t, h.Verify(hash, "notEmpty"))
	})
}

func TestArgon2Hasher_CustomParameters(t *testing.T) {
	t.Run("custom time parameter", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2Time(2))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("custom memory parameter", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2Memory(32 * 1024))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("custom threads parameter", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2Threads(2))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("custom key length", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2KeyLen(64))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("custom salt length", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2SaltLen(32))
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("invalid parameters are ignored", func(t *testing.T) {
		h := NewArgon2Hasher(
			WithArgon2Time(0),
			WithArgon2Memory(0),
			WithArgon2Threads(0),
			WithArgon2KeyLen(0),
			WithArgon2SaltLen(0),
		)
		// Should use defaults
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})
}

func TestArgon2Hasher_Check(t *testing.T) {
	h := NewArgon2Hasher()
	hash, err := h.Hash("password")
	require.NoError(t, err)

	assert.True(t, h.Check(hash, "password"))
	assert.False(t, h.Check(hash, "wrong"))
}

func TestArgon2Hasher_Algorithm(t *testing.T) {
	h := NewArgon2Hasher()
	assert.Equal(t, "argon2id", h.Algorithm())
}

func TestParseArgon2PHC(t *testing.T) {
	t.Run("valid PHC format", func(t *testing.T) {
		h := NewArgon2Hasher()
		hash, err := h.HashWithParams("password")
		require.NoError(t, err)

		params, salt, hashBytes, err := parseArgon2PHC(hash)
		require.NoError(t, err)
		assert.NotNil(t, params)
		assert.NotEmpty(t, salt)
		assert.NotEmpty(t, hashBytes)
	})

	t.Run("invalid format", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("invalid")
		assert.Error(t, err)
	})

	t.Run("wrong variant", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2i$v=19$m=65536,t=1,p=4$salt$hash")
		assert.Error(t, err)
	})

	t.Run("invalid parameters", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$invalid$salt$hash")
		assert.Error(t, err)
	})

	t.Run("invalid parameter format - missing equals", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m65536,t1,p4$salt$hash")
		assert.Error(t, err)
	})

	t.Run("invalid parameter value - not a number", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=abc,t=1,p=4$c2FsdA$aGFzaA")
		assert.Error(t, err)
	})

	t.Run("invalid salt encoding", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$!!!invalid-base64!!!$aGFzaA")
		assert.Error(t, err)
	})

	t.Run("invalid hash encoding", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$!!!invalid-base64!!!")
		assert.Error(t, err)
	})

	t.Run("too few parts", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$salt")
		assert.Error(t, err)
	})

	t.Run("too many parts", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$salt$hash$extra")
		assert.Error(t, err)
	})
}

func TestArgon2Hash_WithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&argon2ErrorReader{})

	h := NewArgon2Hasher()
	_, err := h.Hash("password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate salt")
}

func TestArgon2HashWithParams_WithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&argon2ErrorReader{})

	h := NewArgon2Hasher()
	_, err := h.HashWithParams("password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate salt")
}

func BenchmarkArgon2Hash(b *testing.B) {
	h := NewArgon2Hasher()
	password := "benchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(password)
	}
}

func BenchmarkArgon2Verify(b *testing.B) {
	h := NewArgon2Hasher()
	hash, _ := h.Hash("benchmarkPassword123!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Verify(hash, "benchmarkPassword123!")
	}
}
