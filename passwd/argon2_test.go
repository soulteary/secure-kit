package passwd

import (
	secure "github.com/soulteary/secure-kit/v2"

	"encoding/base64"
	"errors"
	"strings"
	"testing"
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
		mustNoError(t, err)
		wantNotEmpty(t, hash)
		wantContains(t, hash, ":")
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
}

func TestArgon2Hasher_HashWithParams(t *testing.T) {
	h := NewArgon2Hasher()

	t.Run("PHC format", func(t *testing.T) {
		hash, err := h.HashWithParams("password123")
		mustNoError(t, err)
		wantTrue(t, strings.HasPrefix(hash, "$argon2id$"))
		wantContains(t, hash, "$v=")
		wantContains(t, hash, "$m=")
	})
}

func TestArgon2Hasher_Verify(t *testing.T) {
	h := NewArgon2Hasher()

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

	t.Run("PHC format verification", func(t *testing.T) {
		password := "testPassword"
		hash, err := h.HashWithParams(password)
		mustNoError(t, err)

		wantTrue(t, h.Verify(hash, password))
		wantFalse(t, h.Verify(hash, "wrongPassword"))
	})

	t.Run("invalid hash format", func(t *testing.T) {
		wantFalse(t, h.Verify("invalid", "password"))
		wantFalse(t, h.Verify("", "password"))
		wantFalse(t, h.Verify("no:colon:here:extra", "password"))
	})

	t.Run("invalid base64 salt in simple format", func(t *testing.T) {
		// Invalid base64 in salt part
		wantFalse(t, h.Verify("!!!invalid-base64!!!:validhash", "password"))
	})

	t.Run("invalid base64 hash in simple format", func(t *testing.T) {
		// Valid base64 salt but invalid base64 hash
		wantFalse(t, h.Verify("dGVzdHNhbHQ=:!!!invalid-base64!!!", "password"))
	})

	t.Run("simple format rejects oversized salt or hash", func(t *testing.T) {
		oversizedSalt := base64.URLEncoding.EncodeToString(make([]byte, maxArgon2SaltLen+1))
		validHash := base64.URLEncoding.EncodeToString(make([]byte, DefaultArgon2KeyLen))
		wantFalse(t, h.Verify(oversizedSalt+":"+validHash, "password"))

		validSalt := base64.URLEncoding.EncodeToString(make([]byte, DefaultArgon2SaltLen))
		oversizedHash := base64.URLEncoding.EncodeToString(make([]byte, maxArgon2HashLen+1))
		wantFalse(t, h.Verify(validSalt+":"+oversizedHash, "password"))
	})

	t.Run("invalid PHC format verification", func(t *testing.T) {
		// Invalid PHC format should return false
		wantFalse(t, h.Verify("$argon2id$v=19$invalid", "password"))
		wantFalse(t, h.Verify("$argon2id$v=19$m=abc,t=1,p=4$salt$hash", "password"))
	})

	t.Run("PHC with excessive parameters rejected (DoS prevention)", func(t *testing.T) {
		// Valid base64 salt (16 bytes) and hash (32 bytes); memory exceeds maxArgon2MemoryKB
		malicious := "$argon2id$v=19$m=999999999,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		wantFalse(t, h.Verify(malicious, "password"))
		// Excessive time
		maliciousT := "$argon2id$v=19$m=65536,t=999,p=4$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		wantFalse(t, h.Verify(maliciousT, "password"))
	})

	t.Run("PHC with invalid low parameters does not panic", func(t *testing.T) {
		malicious := "$argon2id$v=19$m=65536,t=0,p=1$MTIzNDU2Nzg5MDEyMzQ1Ng$YWJjZA"
		wantNoPanic(t, func() {
			wantFalse(t, h.Verify(malicious, "password"))
		})
	})

	t.Run("empty password verification", func(t *testing.T) {
		hash, err := h.Hash("")
		mustNoError(t, err)

		wantTrue(t, h.Verify(hash, ""))
		wantFalse(t, h.Verify(hash, "notEmpty"))
	})
}

func TestArgon2Hasher_CustomParameters(t *testing.T) {
	t.Run("custom time parameter", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2Time(2))
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})

	t.Run("custom memory parameter", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2Memory(32 * 1024))
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})

	t.Run("custom threads parameter", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2Threads(2))
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})

	t.Run("custom key length", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2KeyLen(64))
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})

	t.Run("custom salt length", func(t *testing.T) {
		h := NewArgon2Hasher(WithArgon2SaltLen(32))
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})

	// Silently keeping the default for a rejected value meant
	// WithArgon2Time(32) looked like it raised the work factor while leaving
	// it at 1: the caller believed the stored hashes were stronger than they
	// were, with nothing to reveal otherwise.
	t.Run("zero parameters are rejected", func(t *testing.T) {
		_, err := NewArgon2HasherStrict(
			WithArgon2Time(0),
			WithArgon2Memory(0),
			WithArgon2Threads(0),
			WithArgon2KeyLen(0),
			WithArgon2SaltLen(0),
		)
		mustError(t, err)

		wantPanic(t, func() { NewArgon2Hasher(WithArgon2Time(0)) })
	})

	t.Run("out-of-range parameters are rejected", func(t *testing.T) {
		_, err := NewArgon2HasherStrict(
			WithArgon2Time(maxArgon2Time+1),
			WithArgon2Memory(maxArgon2MemoryKB+1),
			WithArgon2KeyLen(maxArgon2HashLen+1),
			WithArgon2SaltLen(maxArgon2SaltLen+1),
		)
		mustError(t, err)
		wantContains(t, err.Error(), "out of range")
	})

	t.Run("valid parameters still apply", func(t *testing.T) {
		h, err := NewArgon2HasherStrict(WithArgon2Time(3), WithArgon2Memory(32*1024))
		mustNoError(t, err)
		wantEqual(t, uint32(3), h.time)
		wantEqual(t, uint32(32*1024), h.memory)

		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})
}

func TestArgon2Hasher_Check(t *testing.T) {
	h := NewArgon2Hasher()
	hash, err := h.Hash("password")
	mustNoError(t, err)

	wantTrue(t, h.Check(hash, "password"))
	wantFalse(t, h.Check(hash, "wrong"))
}

func TestArgon2Hasher_Algorithm(t *testing.T) {
	h := NewArgon2Hasher()
	wantEqual(t, "argon2id", h.Algorithm())
}

func TestParseArgon2PHC(t *testing.T) {
	t.Run("valid PHC format", func(t *testing.T) {
		h := NewArgon2Hasher()
		hash, err := h.HashWithParams("password")
		mustNoError(t, err)

		params, salt, hashBytes, err := parseArgon2PHC(hash)
		mustNoError(t, err)
		if params == nil {
			t.Fatal("parseArgon2PHC returned nil parameters for a hash it accepted")
		}
		if len(salt) == 0 || len(hashBytes) == 0 {
			t.Errorf("parseArgon2PHC returned salt of %d bytes and hash of %d bytes, want both non-empty",
				len(salt), len(hashBytes))
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("invalid")
		wantError(t, err)
	})

	t.Run("wrong variant", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2i$v=19$m=65536,t=1,p=4$salt$hash")
		wantError(t, err)
	})

	t.Run("wrong version", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=18$m=65536,t=1,p=4$c2FsdA$aGFzaA")
		wantError(t, err)
	})

	t.Run("invalid parameters", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$invalid$salt$hash")
		wantError(t, err)
	})

	t.Run("invalid parameter format - missing equals", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m65536,t1,p4$salt$hash")
		wantError(t, err)
	})

	t.Run("missing required parameter", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1$c2FsdA$aGFzaA")
		wantError(t, err)
	})

	t.Run("unknown parameter", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4,x=1$c2FsdA$aGFzaA")
		wantError(t, err)
	})

	t.Run("invalid low parameter values", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=0,p=1$c2FsdA$aGFzaA")
		wantError(t, err)
		_, _, _, err = parseArgon2PHC("$argon2id$v=19$m=4,t=1,p=1$c2FsdA$aGFzaA")
		wantError(t, err)
		_, _, _, err = parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=0$c2FsdA$aGFzaA")
		wantError(t, err)
	})

	t.Run("invalid parameter value - not a number", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=abc,t=1,p=4$c2FsdA$aGFzaA")
		wantError(t, err)
	})

	t.Run("invalid salt encoding", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$!!!invalid-base64!!!$aGFzaA")
		wantError(t, err)
	})

	t.Run("invalid hash encoding", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$!!!invalid-base64!!!")
		wantError(t, err)
	})

	t.Run("empty decoded salt/hash rejected", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$$")
		wantError(t, err)
	})

	t.Run("too few parts", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$salt")
		wantError(t, err)
	})

	t.Run("too many parts", func(t *testing.T) {
		_, _, _, err := parseArgon2PHC("$argon2id$v=19$m=65536,t=1,p=4$salt$hash$extra")
		wantError(t, err)
	})
}

func TestArgon2Hash_WithFailingReader(t *testing.T) {
	defer secure.SetRandReader(nil)
	secure.SetRandReader(&argon2ErrorReader{})

	h := NewArgon2Hasher()
	_, err := h.Hash("password")
	wantError(t, err)
	wantContains(t, err.Error(), "failed to generate salt")
}

func TestArgon2HashWithParams_WithFailingReader(t *testing.T) {
	defer secure.SetRandReader(nil)
	secure.SetRandReader(&argon2ErrorReader{})

	h := NewArgon2Hasher()
	_, err := h.HashWithParams("password")
	wantError(t, err)
	wantContains(t, err.Error(), "failed to generate salt")
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
