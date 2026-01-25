package secure

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSHA256Hasher_Hash(t *testing.T) {
	h := NewSHA256Hasher()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Hello World",
			input:    "Hello, World!",
			expected: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "simple text",
			input:    "test",
			expected: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := h.Hash(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, hash)
		})
	}
}

func TestSHA256Hasher_Verify(t *testing.T) {
	h := NewSHA256Hasher()

	t.Run("correct match", func(t *testing.T) {
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("incorrect match", func(t *testing.T) {
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.False(t, h.Verify(hash, "wrong"))
	})

	t.Run("case insensitive hash", func(t *testing.T) {
		hash, err := h.Hash("test")
		require.NoError(t, err)
		// Uppercase version should also match
		assert.True(t, h.Verify("9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08", "test"))
		assert.True(t, h.Verify(hash, "test"))
	})
}

func TestSHA256Hasher_Check(t *testing.T) {
	h := NewSHA256Hasher()
	hash, err := h.Hash("password")
	require.NoError(t, err)

	assert.True(t, h.Check(hash, "password"))
	assert.False(t, h.Check(hash, "wrong"))
}

func TestSHA256Hasher_Algorithm(t *testing.T) {
	h := NewSHA256Hasher()
	assert.Equal(t, "sha256", h.Algorithm())
}

func TestSHA512Hasher_Hash(t *testing.T) {
	h := NewSHA512Hasher()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Hello World",
			input:    "Hello, World!",
			expected: "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := h.Hash(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, hash)
		})
	}
}

func TestSHA512Hasher_Verify(t *testing.T) {
	h := NewSHA512Hasher()

	t.Run("correct match", func(t *testing.T) {
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.True(t, h.Verify(hash, "password"))
	})

	t.Run("incorrect match", func(t *testing.T) {
		hash, err := h.Hash("password")
		require.NoError(t, err)
		assert.False(t, h.Verify(hash, "wrong"))
	})

	t.Run("case insensitive hash", func(t *testing.T) {
		expectedHash := "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
		assert.True(t, h.Verify(expectedHash, "Hello, World!"))
		// Uppercase version
		assert.True(t, h.Verify("374D794A95CDCFD8B35993185FEF9BA368F160D8DAF432D08BA9F1ED1E5ABE6CC69291E0FA2FE0006A52570EF18C19DEF4E617C33CE52EF0A6E5FBE318CB0387", "Hello, World!"))
	})
}

func TestSHA512Hasher_Check(t *testing.T) {
	h := NewSHA512Hasher()
	hash, err := h.Hash("password")
	require.NoError(t, err)

	assert.True(t, h.Check(hash, "password"))
	assert.False(t, h.Check(hash, "wrong"))
}

func TestSHA512Hasher_Algorithm(t *testing.T) {
	h := NewSHA512Hasher()
	assert.Equal(t, "sha512", h.Algorithm())
}

func TestSHA512Resolver(t *testing.T) {
	resolver := &SHA512Resolver{}

	t.Run("correct match", func(t *testing.T) {
		hash := "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
		assert.True(t, resolver.Check(hash, "Hello, World!"))
	})

	t.Run("incorrect match", func(t *testing.T) {
		hash := "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"
		assert.False(t, resolver.Check(hash, "Wrong!"))
	})
}

func TestGetSHA512Hash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Hello World", "Hello, World!", "374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387"},
		{"Empty string", "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetSHA512Hash(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSHA256Hash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Hello World", "Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"},
		{"Empty string", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetSHA256Hash(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetSHA512Hash_Consistency(t *testing.T) {
	input := "test input"
	hash1 := GetSHA512Hash(input)
	hash2 := GetSHA512Hash(input)
	assert.Equal(t, hash1, hash2, "SHA512 hash should be consistent")
}

func TestGetSHA512Hash_Length(t *testing.T) {
	inputs := []string{"a", "12345", "!@#$%", "测试", "This is a test"}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			result := GetSHA512Hash(input)
			// SHA512 produces 128 hex characters (512 bits)
			assert.Equal(t, 128, len(result), "SHA512 hash should be 128 characters long")
		})
	}
}

func BenchmarkSHA256Hash(b *testing.B) {
	h := NewSHA256Hasher()
	password := "benchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(password)
	}
}

func BenchmarkSHA512Hash(b *testing.B) {
	h := NewSHA512Hasher()
	password := "benchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(password)
	}
}
