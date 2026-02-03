package secure

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
)

// MaxRandomBytes is the maximum number of bytes that RandomBytes will generate in one call.
// Larger requests return an error to prevent memory DoS. For longer output, call multiple times.
const MaxRandomBytes = 1 << 20 // 1 MiB

// randReader is the random source used by all random functions.
// It defaults to crypto/rand.Reader. Only replace via SetRandReader in tests, and restore with SetRandReader(nil).
var randReader io.Reader = rand.Reader

// SetRandReader sets the random reader for testing only. Do not use in production.
// Callers must call SetRandReader(nil) when the test ends to restore crypto/rand.Reader.
func SetRandReader(r io.Reader) {
	if r == nil {
		randReader = rand.Reader
	} else {
		randReader = r
	}
}

// RandomBytes generates cryptographically secure random bytes.
// Uses crypto/rand which is suitable for security-sensitive applications.
// n must be in [1, MaxRandomBytes]; larger values return an error to prevent memory DoS.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid byte count: %d", n)
	}
	if n > MaxRandomBytes {
		return nil, fmt.Errorf("byte count exceeds maximum %d: %d", MaxRandomBytes, n)
	}

	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// RandomBytesOrPanic is like RandomBytes but panics on error.
// Use only in initialization code where failure is unrecoverable.
func RandomBytesOrPanic(n int) []byte {
	b, err := RandomBytes(n)
	if err != nil {
		panic(err)
	}
	return b
}

// RandomHex generates a cryptographically secure random hex string.
// The returned string will be 2*n characters long (each byte = 2 hex chars).
func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// RandomBase64 generates a cryptographically secure random base64 string.
// Uses standard base64 encoding.
func RandomBase64(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// RandomBase64URL generates a cryptographically secure random URL-safe base64 string.
// Uses URL-safe base64 encoding (no padding).
func RandomBase64URL(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandomString generates a cryptographically secure random string
// using the specified character set.
func RandomString(length int, charset string) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("invalid length: %d", length)
	}
	if len(charset) == 0 {
		return "", fmt.Errorf("charset cannot be empty")
	}

	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		idx, err := rand.Int(randReader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		result[i] = charset[idx.Int64()]
	}

	return string(result), nil
}

// Common character sets for RandomString
const (
	// CharsetAlphanumeric contains lowercase, uppercase letters and digits
	CharsetAlphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// CharsetAlphanumericLower contains lowercase letters and digits
	CharsetAlphanumericLower = "abcdefghijklmnopqrstuvwxyz0123456789"

	// CharsetAlphanumericUpper contains uppercase letters and digits
	CharsetAlphanumericUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// CharsetDigits contains only digits
	CharsetDigits = "0123456789"

	// CharsetHex contains hexadecimal characters (lowercase)
	CharsetHex = "0123456789abcdef"

	// CharsetAlpha contains only letters (lowercase and uppercase)
	CharsetAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	// CharsetURLSafe contains URL-safe characters
	CharsetURLSafe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)

// RandomDigits generates a cryptographically secure random string of digits.
// Commonly used for OTP/verification codes.
func RandomDigits(length int) (string, error) {
	return RandomString(length, CharsetDigits)
}

// RandomAlphanumeric generates a cryptographically secure random alphanumeric string.
func RandomAlphanumeric(length int) (string, error) {
	return RandomString(length, CharsetAlphanumeric)
}

// RandomToken generates a cryptographically secure random token.
// Uses URL-safe base64 encoding, suitable for API tokens, session IDs, etc.
// The byte length determines the entropy; the returned string will be longer.
func RandomToken(byteLength int) (string, error) {
	return RandomBase64URL(byteLength)
}

// RandomUUID generates a cryptographically secure random UUID (v4).
// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
// where x is any hex digit and y is one of 8, 9, A, or B.
func RandomUUID() (string, error) {
	b, err := RandomBytes(16)
	if err != nil {
		return "", err
	}

	// Set version (4) and variant (RFC 4122)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// RandomInt generates a cryptographically secure random integer in [0, max).
func RandomInt(max int64) (int64, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive: %d", max)
	}

	n, err := rand.Int(randReader, big.NewInt(max))
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int: %w", err)
	}

	return n.Int64(), nil
}

// RandomIntRange generates a cryptographically secure random integer in [min, max].
func RandomIntRange(min, max int64) (int64, error) {
	if min > max {
		return 0, fmt.Errorf("min (%d) must not be greater than max (%d)", min, max)
	}
	if min == max {
		return min, nil
	}

	n, err := RandomInt(max - min + 1)
	if err != nil {
		return 0, err
	}

	return min + n, nil
}

// MustRandomBytes is like RandomBytes but panics on error.
// Deprecated: Use RandomBytesOrPanic instead.
func MustRandomBytes(n int) []byte {
	return RandomBytesOrPanic(n)
}
