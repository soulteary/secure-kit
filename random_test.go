package secure

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// errorReader is a mock reader that always returns an error.
type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("mock random source error")
}

func TestRandomBytes(t *testing.T) {
	t.Run("generates correct length", func(t *testing.T) {
		for _, length := range []int{1, 16, 32, 64, 128} {
			b, err := RandomBytes(length)
			mustNoError(t, err)
			wantLen(t, b, length)
		}
	})

	t.Run("generates different values", func(t *testing.T) {
		b1, err := RandomBytes(32)
		mustNoError(t, err)

		b2, err := RandomBytes(32)
		mustNoError(t, err)

		if bytes.Equal(b1, b2) {
			t.Errorf("two reads of 32 random bytes returned the same value: %x", b1)
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomBytes(0)
		wantError(t, err)

		_, err = RandomBytes(-1)
		wantError(t, err)
	})

	t.Run("exceeds MaxRandomBytes", func(t *testing.T) {
		_, err := RandomBytes(MaxRandomBytes + 1)
		wantError(t, err)
		wantContains(t, err.Error(), "exceeds maximum")
	})

	t.Run("at MaxRandomBytes succeeds", func(t *testing.T) {
		b, err := RandomBytes(MaxRandomBytes)
		mustNoError(t, err)
		wantLen(t, b, MaxRandomBytes)
	})
}

func TestRandomBytesOrPanic(t *testing.T) {
	t.Run("valid length", func(t *testing.T) {
		b := RandomBytesOrPanic(32)
		wantLen(t, b, 32)
	})

	t.Run("panics on invalid length", func(t *testing.T) {
		wantPanic(t, func() {
			RandomBytesOrPanic(0)
		})
	})
}

func TestRandomHex(t *testing.T) {
	t.Run("generates correct length", func(t *testing.T) {
		// Each byte = 2 hex chars
		hex, err := RandomHex(16)
		mustNoError(t, err)
		wantLenString(t, hex, 32)
	})

	t.Run("valid hex characters", func(t *testing.T) {
		hex, err := RandomHex(32)
		mustNoError(t, err)

		matched, err := regexp.MatchString("^[0-9a-f]+$", hex)
		mustNoError(t, err)
		wantTrue(t, matched)
	})

	t.Run("generates different values", func(t *testing.T) {
		hex1, err := RandomHex(16)
		mustNoError(t, err)

		hex2, err := RandomHex(16)
		mustNoError(t, err)

		wantNotEqual(t, hex1, hex2)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomHex(0)
		wantError(t, err)

		_, err = RandomHex(-1)
		wantError(t, err)
	})
}

func TestRandomBase64(t *testing.T) {
	t.Run("generates base64 string", func(t *testing.T) {
		b64, err := RandomBase64(32)
		mustNoError(t, err)
		wantNotEmpty(t, b64)
	})

	t.Run("valid base64 characters", func(t *testing.T) {
		b64, err := RandomBase64(32)
		mustNoError(t, err)

		// Standard base64 characters
		matched, err := regexp.MatchString("^[A-Za-z0-9+/]+=*$", b64)
		mustNoError(t, err)
		wantTrue(t, matched)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomBase64(0)
		wantError(t, err)

		_, err = RandomBase64(-1)
		wantError(t, err)
	})
}

func TestRandomBase64URL(t *testing.T) {
	t.Run("generates URL-safe base64 string", func(t *testing.T) {
		b64, err := RandomBase64URL(32)
		mustNoError(t, err)
		wantNotEmpty(t, b64)
	})

	t.Run("valid URL-safe base64 characters", func(t *testing.T) {
		b64, err := RandomBase64URL(32)
		mustNoError(t, err)

		// URL-safe base64 characters (no +, /, or =)
		wantNotContains(t, b64, "+")
		wantNotContains(t, b64, "/")
		wantNotContains(t, b64, "=")
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomBase64URL(0)
		wantError(t, err)

		_, err = RandomBase64URL(-1)
		wantError(t, err)
	})
}

func TestRandomString(t *testing.T) {
	t.Run("generates correct length", func(t *testing.T) {
		s, err := RandomString(10, CharsetAlphanumeric)
		mustNoError(t, err)
		wantLenString(t, s, 10)
	})

	t.Run("uses only charset characters", func(t *testing.T) {
		s, err := RandomString(100, "abc")
		mustNoError(t, err)

		for _, c := range s {
			wantTrue(t, c == 'a' || c == 'b' || c == 'c')
		}
	})

	t.Run("generates different values", func(t *testing.T) {
		s1, err := RandomString(32, CharsetAlphanumeric)
		mustNoError(t, err)

		s2, err := RandomString(32, CharsetAlphanumeric)
		mustNoError(t, err)

		wantNotEqual(t, s1, s2)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomString(0, CharsetAlphanumeric)
		wantError(t, err)

		_, err = RandomString(-1, CharsetAlphanumeric)
		wantError(t, err)
	})

	t.Run("empty charset", func(t *testing.T) {
		_, err := RandomString(10, "")
		wantError(t, err)
	})
}

func TestRandomDigits(t *testing.T) {
	t.Run("generates only digits", func(t *testing.T) {
		digits, err := RandomDigits(6)
		mustNoError(t, err)
		wantLenString(t, digits, 6)

		matched, err := regexp.MatchString("^[0-9]+$", digits)
		mustNoError(t, err)
		wantTrue(t, matched)
	})

	t.Run("generates different codes", func(t *testing.T) {
		codes := make(map[string]bool)
		for i := 0; i < 100; i++ {
			code, err := RandomDigits(6)
			mustNoError(t, err)
			codes[code] = true
		}
		// Should have many unique codes
		if len(codes) <= 90 {
			t.Errorf("100 six-digit codes contained only %d distinct values", len(codes))
		}
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomDigits(0)
		wantError(t, err)

		_, err = RandomDigits(-1)
		wantError(t, err)
	})
}

func TestRandomAlphanumeric(t *testing.T) {
	t.Run("generates alphanumeric", func(t *testing.T) {
		s, err := RandomAlphanumeric(20)
		mustNoError(t, err)
		wantLenString(t, s, 20)

		matched, err := regexp.MatchString("^[A-Za-z0-9]+$", s)
		mustNoError(t, err)
		wantTrue(t, matched)
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomAlphanumeric(0)
		wantError(t, err)

		_, err = RandomAlphanumeric(-1)
		wantError(t, err)
	})
}

func TestRandomToken(t *testing.T) {
	t.Run("generates token", func(t *testing.T) {
		token, err := RandomToken(32)
		mustNoError(t, err)
		wantNotEmpty(t, token)
	})

	t.Run("URL safe", func(t *testing.T) {
		token, err := RandomToken(32)
		mustNoError(t, err)

		wantNotContains(t, token, "+")
		wantNotContains(t, token, "/")
		wantNotContains(t, token, "=")
	})

	t.Run("invalid length", func(t *testing.T) {
		_, err := RandomToken(0)
		wantError(t, err)

		_, err = RandomToken(-1)
		wantError(t, err)
	})
}

func TestRandomUUID(t *testing.T) {
	t.Run("generates valid UUID format", func(t *testing.T) {
		uuid, err := RandomUUID()
		mustNoError(t, err)

		// UUID format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
		matched, err := regexp.MatchString(
			"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
			uuid,
		)
		mustNoError(t, err)
		if !matched {
			t.Errorf("RandomUUID() = %q, which is not a version 4 UUID", uuid)
		}
	})

	t.Run("generates unique UUIDs", func(t *testing.T) {
		uuids := make(map[string]bool)
		for i := 0; i < 100; i++ {
			uuid, err := RandomUUID()
			mustNoError(t, err)
			uuids[uuid] = true
		}
		if len(uuids) != 100 {
			t.Errorf("100 calls to RandomUUID() produced %d distinct values", len(uuids))
		}
	})

	t.Run("version 4", func(t *testing.T) {
		uuid, err := RandomUUID()
		mustNoError(t, err)

		parts := strings.Split(uuid, "-")
		wantEqual(t, '4', rune(parts[2][0]))
	})
}

func TestRandomInt(t *testing.T) {
	t.Run("generates values in range", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			n, err := RandomInt(100)
			mustNoError(t, err)
			if n < 0 || n >= 100 {
				t.Errorf("RandomInt(100) = %d, want a value in [0, 100)", n)
			}
		}
	})

	t.Run("invalid max", func(t *testing.T) {
		_, err := RandomInt(0)
		wantError(t, err)

		_, err = RandomInt(-1)
		wantError(t, err)
	})
}

func TestRandomIntRange(t *testing.T) {
	t.Run("generates values in range", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			n, err := RandomIntRange(10, 20)
			mustNoError(t, err)
			if n < 10 || n > 20 {
				t.Errorf("RandomIntRange(10, 20) = %d, want a value in [10, 20]", n)
			}
		}
	})

	t.Run("same min and max", func(t *testing.T) {
		n, err := RandomIntRange(5, 5)
		mustNoError(t, err)
		wantEqual(t, int64(5), n)
	})

	t.Run("invalid range", func(t *testing.T) {
		_, err := RandomIntRange(20, 10)
		wantError(t, err)
	})
}

func TestMustRandomBytes(t *testing.T) {
	// Deprecated function, should still work
	b := MustRandomBytes(16)
	wantLen(t, b, 16)
}

func TestSetRandReader(t *testing.T) {
	t.Run("set nil resets to default", func(t *testing.T) {
		SetRandReader(nil)
		// Should work with default reader
		b, err := RandomBytes(16)
		mustNoError(t, err)
		wantLen(t, b, 16)
	})

	t.Run("set custom reader", func(t *testing.T) {
		// Save and restore
		defer SetRandReader(nil)

		SetRandReader(&errorReader{})

		_, err := RandomBytes(16)
		wantError(t, err)
		wantContains(t, err.Error(), "mock random source error")
	})
}

func TestRandomBytesWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomBytes(16)
	wantError(t, err)
	wantContains(t, err.Error(), "failed to generate random bytes")
}

func TestRandomHexWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomHex(16)
	wantError(t, err)
}

func TestRandomBase64WithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomBase64(16)
	wantError(t, err)
}

func TestRandomBase64URLWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomBase64URL(16)
	wantError(t, err)
}

func TestRandomStringWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomString(10, CharsetAlphanumeric)
	wantError(t, err)
	wantContains(t, err.Error(), "failed to generate random index")
}

func TestRandomUUIDWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomUUID()
	wantError(t, err)
}

func TestRandomIntWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomInt(100)
	wantError(t, err)
	wantContains(t, err.Error(), "failed to generate random int")
}

func TestRandomIntRangeWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomIntRange(10, 20)
	wantError(t, err)
}

func TestRandomDigitsWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomDigits(6)
	wantError(t, err)
}

func TestRandomAlphanumericWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomAlphanumeric(10)
	wantError(t, err)
}

func TestRandomTokenWithFailingReader(t *testing.T) {
	defer SetRandReader(nil)
	SetRandReader(&errorReader{})

	_, err := RandomToken(32)
	wantError(t, err)
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
