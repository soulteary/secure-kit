package secure

import (
	"testing"
)

func TestPlaintextHasher_Hash(t *testing.T) {
	h := NewPlaintextHasher()

	t.Run("returns unchanged", func(t *testing.T) {
		input := "password123"
		hash, err := h.Hash(input)
		mustNoError(t, err)
		wantEqual(t, input, hash)
	})

	t.Run("empty string", func(t *testing.T) {
		hash, err := h.Hash("")
		mustNoError(t, err)
		wantEqual(t, "", hash)
	})
}

func TestPlaintextHasher_Verify(t *testing.T) {
	h := NewPlaintextHasher()

	t.Run("correct match", func(t *testing.T) {
		wantTrue(t, h.Verify("password", "password"))
	})

	t.Run("incorrect match", func(t *testing.T) {
		wantFalse(t, h.Verify("password", "wrong"))
	})

	t.Run("empty strings match", func(t *testing.T) {
		wantTrue(t, h.Verify("", ""))
	})

	t.Run("case sensitive", func(t *testing.T) {
		wantFalse(t, h.Verify("Password", "password"))
	})
}

func TestPlaintextHasher_Check(t *testing.T) {
	h := NewPlaintextHasher()

	wantTrue(t, h.Check("password", "password"))
	wantFalse(t, h.Check("password", "wrong"))
}

func TestPlaintextHasher_Algorithm(t *testing.T) {
	h := NewPlaintextHasher()
	wantEqual(t, "plaintext", h.Algorithm())
}

func TestPlaintextResolver(t *testing.T) {
	resolver := &PlaintextResolver{}

	t.Run("correct match", func(t *testing.T) {
		wantTrue(t, resolver.Check("password", "password"))
	})

	t.Run("incorrect match", func(t *testing.T) {
		wantFalse(t, resolver.Check("password", "wrong"))
	})

	t.Run("empty strings", func(t *testing.T) {
		wantTrue(t, resolver.Check("", ""))
	})
}

func BenchmarkPlaintextHash(b *testing.B) {
	h := NewPlaintextHasher()
	password := "benchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(password)
	}
}

func BenchmarkPlaintextVerify(b *testing.B) {
	h := NewPlaintextHasher()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Verify("benchmarkPassword123!", "benchmarkPassword123!")
	}
}
