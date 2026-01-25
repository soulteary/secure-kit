package secure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{
			name:     "equal strings",
			a:        "password123",
			b:        "password123",
			expected: true,
		},
		{
			name:     "different strings",
			a:        "password123",
			b:        "password456",
			expected: false,
		},
		{
			name:     "different lengths",
			a:        "short",
			b:        "much longer string",
			expected: false,
		},
		{
			name:     "empty strings",
			a:        "",
			b:        "",
			expected: true,
		},
		{
			name:     "one empty",
			a:        "something",
			b:        "",
			expected: false,
		},
		{
			name:     "unicode strings",
			a:        "密码测试",
			b:        "密码测试",
			expected: true,
		},
		{
			name:     "different unicode",
			a:        "密码测试",
			b:        "密码不同",
			expected: false,
		},
		{
			name:     "special characters",
			a:        "!@#$%^&*()",
			b:        "!@#$%^&*()",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConstantTimeEqual(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConstantTimeEqualBytes(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{
			name:     "equal bytes",
			a:        []byte{1, 2, 3, 4, 5},
			b:        []byte{1, 2, 3, 4, 5},
			expected: true,
		},
		{
			name:     "different bytes",
			a:        []byte{1, 2, 3, 4, 5},
			b:        []byte{1, 2, 3, 4, 6},
			expected: false,
		},
		{
			name:     "different lengths",
			a:        []byte{1, 2, 3},
			b:        []byte{1, 2, 3, 4, 5},
			expected: false,
		},
		{
			name:     "empty slices",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
		{
			name:     "nil slices",
			a:        nil,
			b:        nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConstantTimeEqualBytes(tt.a, tt.b)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSecureCompare(t *testing.T) {
	// SecureCompare is an alias for ConstantTimeEqual
	assert.True(t, SecureCompare("test", "test"))
	assert.False(t, SecureCompare("test", "different"))
}

func TestTimingSafeEqual(t *testing.T) {
	// TimingSafeEqual is an alias for ConstantTimeEqual
	assert.True(t, TimingSafeEqual("test", "test"))
	assert.False(t, TimingSafeEqual("test", "different"))
}

func BenchmarkConstantTimeEqual(b *testing.B) {
	a := "benchmarkPassword123!@#$%"
	c := "benchmarkPassword123!@#$%"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConstantTimeEqual(a, c)
	}
}

func BenchmarkConstantTimeEqualDifferent(b *testing.B) {
	a := "benchmarkPassword123!@#$%"
	c := "differentPassword123!@#$%"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConstantTimeEqual(a, c)
	}
}
