package secure

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRandomBytes(t *testing.T) {
	t.Run("generates correct length", func(t *testing.T) {
		for _, length := range []int{1, 16, 32, 64, 128} {
			b, err := RandomBytes(length)
			require.NoError(t, err)
			assert.Len(t, b, length)
		}
	})

	t.Run("generates different values", func(t *testing.T) {
		b1, err := RandomBytes(32)
		require.NoError(t, err)

		b2, err := RandomBytes(32)
		require.NoError(t, err)

		assert.NotEqual(t, b1, b2)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomBytes(0)
		assert.Error(t, err)

		_, err = RandomBytes(-1)
		assert.Error(t, err)
	})
}

func TestRandomBytesOrPanic(t *testing.T) {
	t.Run("valid length", func(t *testing.T) {
		b := RandomBytesOrPanic(32)
		assert.Len(t, b, 32)
	})

	t.Run("panics on invalid length", func(t *testing.T) {
		assert.Panics(t, func() {
			RandomBytesOrPanic(0)
		})
	})
}

func TestRandomHex(t *testing.T) {
	t.Run("generates correct length", func(t *testing.T) {
		// Each byte = 2 hex chars
		hex, err := RandomHex(16)
		require.NoError(t, err)
		assert.Len(t, hex, 32)
	})

	t.Run("valid hex characters", func(t *testing.T) {
		hex, err := RandomHex(32)
		require.NoError(t, err)

		matched, err := regexp.MatchString("^[0-9a-f]+$", hex)
		require.NoError(t, err)
		assert.True(t, matched)
	})

	t.Run("generates different values", func(t *testing.T) {
		hex1, err := RandomHex(16)
		require.NoError(t, err)

		hex2, err := RandomHex(16)
		require.NoError(t, err)

		assert.NotEqual(t, hex1, hex2)
	})
}

func TestRandomBase64(t *testing.T) {
	t.Run("generates base64 string", func(t *testing.T) {
		b64, err := RandomBase64(32)
		require.NoError(t, err)
		assert.NotEmpty(t, b64)
	})

	t.Run("valid base64 characters", func(t *testing.T) {
		b64, err := RandomBase64(32)
		require.NoError(t, err)

		// Standard base64 characters
		matched, err := regexp.MatchString("^[A-Za-z0-9+/]+=*$", b64)
		require.NoError(t, err)
		assert.True(t, matched)
	})
}

func TestRandomBase64URL(t *testing.T) {
	t.Run("generates URL-safe base64 string", func(t *testing.T) {
		b64, err := RandomBase64URL(32)
		require.NoError(t, err)
		assert.NotEmpty(t, b64)
	})

	t.Run("valid URL-safe base64 characters", func(t *testing.T) {
		b64, err := RandomBase64URL(32)
		require.NoError(t, err)

		// URL-safe base64 characters (no +, /, or =)
		assert.NotContains(t, b64, "+")
		assert.NotContains(t, b64, "/")
		assert.NotContains(t, b64, "=")
	})
}

func TestRandomString(t *testing.T) {
	t.Run("generates correct length", func(t *testing.T) {
		s, err := RandomString(10, CharsetAlphanumeric)
		require.NoError(t, err)
		assert.Len(t, s, 10)
	})

	t.Run("uses only charset characters", func(t *testing.T) {
		s, err := RandomString(100, "abc")
		require.NoError(t, err)

		for _, c := range s {
			assert.True(t, c == 'a' || c == 'b' || c == 'c')
		}
	})

	t.Run("generates different values", func(t *testing.T) {
		s1, err := RandomString(32, CharsetAlphanumeric)
		require.NoError(t, err)

		s2, err := RandomString(32, CharsetAlphanumeric)
		require.NoError(t, err)

		assert.NotEqual(t, s1, s2)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomString(0, CharsetAlphanumeric)
		assert.Error(t, err)

		_, err = RandomString(-1, CharsetAlphanumeric)
		assert.Error(t, err)
	})

	t.Run("empty charset", func(t *testing.T) {
		_, err := RandomString(10, "")
		assert.Error(t, err)
	})
}

func TestRandomDigits(t *testing.T) {
	t.Run("generates only digits", func(t *testing.T) {
		digits, err := RandomDigits(6)
		require.NoError(t, err)
		assert.Len(t, digits, 6)

		matched, err := regexp.MatchString("^[0-9]+$", digits)
		require.NoError(t, err)
		assert.True(t, matched)
	})

	t.Run("generates different codes", func(t *testing.T) {
		codes := make(map[string]bool)
		for i := 0; i < 100; i++ {
			code, err := RandomDigits(6)
			require.NoError(t, err)
			codes[code] = true
		}
		// Should have many unique codes
		assert.Greater(t, len(codes), 90)
	})
}

func TestRandomAlphanumeric(t *testing.T) {
	t.Run("generates alphanumeric", func(t *testing.T) {
		s, err := RandomAlphanumeric(20)
		require.NoError(t, err)
		assert.Len(t, s, 20)

		matched, err := regexp.MatchString("^[A-Za-z0-9]+$", s)
		require.NoError(t, err)
		assert.True(t, matched)
	})
}

func TestRandomToken(t *testing.T) {
	t.Run("generates token", func(t *testing.T) {
		token, err := RandomToken(32)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("URL safe", func(t *testing.T) {
		token, err := RandomToken(32)
		require.NoError(t, err)

		assert.NotContains(t, token, "+")
		assert.NotContains(t, token, "/")
		assert.NotContains(t, token, "=")
	})
}

func TestRandomUUID(t *testing.T) {
	t.Run("generates valid UUID format", func(t *testing.T) {
		uuid, err := RandomUUID()
		require.NoError(t, err)

		// UUID format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
		matched, err := regexp.MatchString(
			"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
			uuid,
		)
		require.NoError(t, err)
		assert.True(t, matched, "UUID format should match: %s", uuid)
	})

	t.Run("generates unique UUIDs", func(t *testing.T) {
		uuids := make(map[string]bool)
		for i := 0; i < 100; i++ {
			uuid, err := RandomUUID()
			require.NoError(t, err)
			uuids[uuid] = true
		}
		assert.Len(t, uuids, 100)
	})

	t.Run("version 4", func(t *testing.T) {
		uuid, err := RandomUUID()
		require.NoError(t, err)

		parts := strings.Split(uuid, "-")
		assert.Equal(t, '4', rune(parts[2][0]))
	})
}

func TestRandomInt(t *testing.T) {
	t.Run("generates values in range", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			n, err := RandomInt(100)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, n, int64(0))
			assert.Less(t, n, int64(100))
		}
	})

	t.Run("invalid max", func(t *testing.T) {
		_, err := RandomInt(0)
		assert.Error(t, err)

		_, err = RandomInt(-1)
		assert.Error(t, err)
	})
}

func TestRandomIntRange(t *testing.T) {
	t.Run("generates values in range", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			n, err := RandomIntRange(10, 20)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, n, int64(10))
			assert.LessOrEqual(t, n, int64(20))
		}
	})

	t.Run("same min and max", func(t *testing.T) {
		n, err := RandomIntRange(5, 5)
		require.NoError(t, err)
		assert.Equal(t, int64(5), n)
	})

	t.Run("invalid range", func(t *testing.T) {
		_, err := RandomIntRange(20, 10)
		assert.Error(t, err)
	})
}

func TestMustRandomBytes(t *testing.T) {
	// Deprecated function, should still work
	b := MustRandomBytes(16)
	assert.Len(t, b, 16)
}

func BenchmarkRandomBytes(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RandomBytes(32)
	}
}

func BenchmarkRandomHex(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RandomHex(32)
	}
}

func BenchmarkRandomDigits(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RandomDigits(6)
	}
}

func BenchmarkRandomUUID(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RandomUUID()
	}
}
