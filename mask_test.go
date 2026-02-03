package secure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty email",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid email (no @)",
			input:    "invalid",
			expected: "***@***",
		},
		{
			name:     "invalid email (multiple @)",
			input:    "user@example.com@extra",
			expected: "***@***",
		},
		{
			name:     "empty local part",
			input:    "@example.com",
			expected: "***@example.com",
		},
		{
			name:     "single char local part",
			input:    "u@example.com",
			expected: "u***@example.com",
		},
		{
			name:     "normal email",
			input:    "user@example.com",
			expected: "u***@example.com",
		},
		{
			name:     "long local part",
			input:    "longuser@example.com",
			expected: "l*******@example.com",
		},
		{
			name:     "email with spaces",
			input:    " user@example.com ",
			expected: "u***@example.com",
		},
		{
			name:     "email with dots",
			input:    "test.user@example.com",
			expected: "t********@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskEmail(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskEmailPartial(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty email",
			input:    "",
			expected: "",
		},
		{
			name:     "invalid email",
			input:    "invalid",
			expected: "***",
		},
		{
			name:     "short local part",
			input:    "ab@example.com",
			expected: "ab***@example.com",
		},
		{
			name:     "normal email",
			input:    "john.doe@example.com",
			expected: "jo***@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskEmailPartial(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskPhone(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty phone",
			input:    "",
			expected: "",
		},
		{
			name:     "short phone",
			input:    "123",
			expected: "****",
		},
		{
			name:     "length 7 phone",
			input:    "1234567",
			expected: "123****",
		},
		{
			name:     "normal phone",
			input:    "13812345678",
			expected: "138****5678",
		},
		{
			name:     "long phone",
			input:    "138123456789",
			expected: "138*****6789",
		},
		{
			name:     "phone with spaces",
			input:    " 13812345678 ",
			expected: "138****5678",
		},
		{
			name:     "international format",
			input:    "+8613812345678",
			expected: "+86*******5678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskPhone(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskPhoneSimple(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short phone",
			input:    "123456",
			expected: "***",
		},
		{
			name:     "normal phone",
			input:    "+1234567890",
			expected: "+12***7890",
		},
		{
			name:     "longer phone",
			input:    "13812345678",
			expected: "138***5678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskPhoneSimple(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskString(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		visibleChars int
		expected     string
	}{
		{
			name:         "short string",
			input:        "short",
			visibleChars: 3,
			expected:     "***",
		},
		{
			name:         "normal string",
			input:        "1234567890",
			visibleChars: 3,
			expected:     "123***890",
		},
		{
			name:         "exact boundary",
			input:        "123456",
			visibleChars: 3,
			expected:     "***",
		},
		{
			name:         "long string",
			input:        "abcdefghijklmnop",
			visibleChars: 4,
			expected:     "abcd***mnop",
		},
		{
			name:         "visibleChars zero",
			input:        "1234567890",
			visibleChars: 0,
			expected:     "***",
		},
		{
			name:         "visibleChars negative no panic",
			input:        "1234567890",
			visibleChars: -1,
			expected:     "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskString(tt.input, tt.visibleChars)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskCreditCard(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "short number",
			input:    "123",
			expected: "****",
		},
		{
			name:     "normal card",
			input:    "4111111111111111",
			expected: "************1111",
		},
		{
			name:     "with dashes",
			input:    "4111-1111-1111-1111",
			expected: "****-****-****-1111",
		},
		{
			name:     "with spaces",
			input:    "4111 1111 1111 1111",
			expected: "************1111",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskCreditCard(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "IPv4",
			input:    "192.168.1.100",
			expected: "192.*.*.*",
		},
		{
			name:     "IPv6",
			input:    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			expected: "2001:****:****:****:****:****:****:****",
		},
		{
			name:     "localhost IPv4",
			input:    "127.0.0.1",
			expected: "127.*.*.*",
		},
		{
			name:     "invalid IPv4 - too few segments",
			input:    "192.168.1",
			expected: "****",
		},
		{
			name:     "invalid IPv4 - too many segments",
			input:    "192.168.1.100.200",
			expected: "****",
		},
		{
			name:     "single segment with no dots or colons",
			input:    "localhost",
			expected: "****",
		},
		{
			name:     "IPv6 with single colon only",
			input:    "2001",
			expected: "****",
		},
		{
			name:     "IPv6 short form",
			input:    "::1",
			expected: ":****:****:****:****:****:****:****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskIPAddress(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short key",
			input:    "key123",
			expected: "***",
		},
		{
			name:     "normal key",
			input:    "sk_live_abcdefghijklmnop",
			expected: "sk_l***mnop",
		},
		{
			name:     "long key",
			input:    "api_key_1234567890abcdefghij",
			expected: "api_***ghij",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskAPIKey(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMaskName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty",
			input:    "",
			expected: "",
		},
		{
			name:     "single name",
			input:    "Alice",
			expected: "A***",
		},
		{
			name:     "full name",
			input:    "John Doe",
			expected: "J*** D***",
		},
		{
			name:     "three names",
			input:    "John Michael Doe",
			expected: "J*** M*** D***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MaskName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{
			name:     "shorter than max",
			input:    "short",
			maxLen:   10,
			expected: "short",
		},
		{
			name:     "exact length",
			input:    "exact",
			maxLen:   5,
			expected: "exact",
		},
		{
			name:     "longer than max",
			input:    "this is a long string",
			maxLen:   10,
			expected: "this is a ...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TruncateString(tt.input, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func BenchmarkMaskEmail(b *testing.B) {
	email := "longusername@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MaskEmail(email)
	}
}

func BenchmarkMaskPhone(b *testing.B) {
	phone := "13812345678"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MaskPhone(phone)
	}
}
