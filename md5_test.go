package secure

import (
	"testing"
)

func TestMD5Hasher_Hash(t *testing.T) {
	h := NewMD5Hasher()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Hello World",
			input:    "Hello, World!",
			expected: "65a8e27d8879283831b664bd8b7f0ad4",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:     "single character",
			input:    "a",
			expected: "0cc175b9c0f1b6a831c399e269772661",
		},
		{
			name:     "numbers",
			input:    "12345",
			expected: "827ccb0eea8a706c4c34a16891f84e7b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := h.Hash(tt.input)
			mustNoError(t, err)
			wantEqual(t, tt.expected, hash)
		})
	}
}

func TestMD5Hasher_Verify(t *testing.T) {
	h := NewMD5Hasher()

	t.Run("correct match", func(t *testing.T) {
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantTrue(t, h.Verify(hash, "password"))
	})

	t.Run("incorrect match", func(t *testing.T) {
		hash, err := h.Hash("password")
		mustNoError(t, err)
		wantFalse(t, h.Verify(hash, "wrong"))
	})

	t.Run("case insensitive hash", func(t *testing.T) {
		// MD5 of "Hello, World!" in uppercase
		wantTrue(t, h.Verify("65A8E27D8879283831B664BD8B7F0AD4", "Hello, World!"))
	})
}

func TestMD5Hasher_Check(t *testing.T) {
	h := NewMD5Hasher()
	hash, err := h.Hash("password")
	mustNoError(t, err)

	wantTrue(t, h.Check(hash, "password"))
	wantFalse(t, h.Check(hash, "wrong"))
}

func TestMD5Hasher_Algorithm(t *testing.T) {
	h := NewMD5Hasher()
	wantEqual(t, "md5", h.Algorithm())
}

func TestMD5Resolver(t *testing.T) {
	resolver := &MD5Resolver{}

	t.Run("correct match", func(t *testing.T) {
		hash := "65a8e27d8879283831b664bd8b7f0ad4"
		wantTrue(t, resolver.Check(hash, "Hello, World!"))
	})

	t.Run("incorrect match", func(t *testing.T) {
		hash := "65a8e27d8879283831b664bd8b7f0ad4"
		wantFalse(t, resolver.Check(hash, "Wrong!"))
	})

	t.Run("case insensitive", func(t *testing.T) {
		hash := "65A8E27D8879283831B664BD8B7F0AD4"
		wantTrue(t, resolver.Check(hash, "Hello, World!"))
	})
}

func TestGetMD5Hash(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Hello World", "Hello, World!", "65a8e27d8879283831b664bd8b7f0ad4"},
		{"Empty string", "", "d41d8cd98f00b204e9800998ecf8427e"},
		{"Single character", "a", "0cc175b9c0f1b6a831c399e269772661"},
		{"Numbers", "12345", "827ccb0eea8a706c4c34a16891f84e7b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetMD5Hash(tt.input)
			wantEqual(t, tt.expected, result)
		})
	}
}

func TestGetMD5Hash_VariousInputs(t *testing.T) {
	inputs := []string{"!@#$%", "测试", "This is a test", "123", "", "a"}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			result := GetMD5Hash(input)
			// MD5 produces 32 hex characters (128 bits)
			wantLenString(t, result, 32)
			// Verify it's a valid hex string
			for _, char := range result {
				isDigit := char >= '0' && char <= '9'
				isLowerHexLetter := char >= 'a' && char <= 'f'
				if !isDigit && !isLowerHexLetter {
					t.Errorf("GetMD5Hash(%q) = %q, which is not all lower-case hex", input, result)
					break
				}
			}
		})
	}
}

func TestGetMD5Hash_Consistency(t *testing.T) {
	input := "test input"
	hash1 := GetMD5Hash(input)
	hash2 := GetMD5Hash(input)
	if hash1 != hash2 {
		t.Errorf("GetMD5Hash(%q) returned %q and then %q", input, hash1, hash2)
	}
}

func BenchmarkMD5Hash(b *testing.B) {
	h := NewMD5Hasher()
	password := "benchmarkPassword123!"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = h.Hash(password)
	}
}
