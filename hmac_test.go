package secure

import (
	"encoding/base64"
	"testing"
)

func TestHMACAlgorithm_String(t *testing.T) {
	tests := []struct {
		algo     HMACAlgorithm
		expected string
	}{
		{HMACSHA1, "sha1"},
		{HMACSHA256, "sha256"},
		{HMACSHA512, "sha512"},
		{HMACAlgorithm(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.algo.String(); got != tt.expected {
				t.Errorf("HMACAlgorithm.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHMACAlgorithm_Prefix(t *testing.T) {
	tests := []struct {
		algo     HMACAlgorithm
		expected string
	}{
		{HMACSHA1, "sha1="},
		{HMACSHA256, "sha256="},
		{HMACSHA512, "sha512="},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.algo.Prefix(); got != tt.expected {
				t.Errorf("HMACAlgorithm.Prefix() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHMACVerifier_Sign(t *testing.T) {
	tests := []struct {
		name      string
		algorithm HMACAlgorithm
		secret    string
		payload   []byte
		expected  string
	}{
		{
			name:      "SHA1 signature",
			algorithm: HMACSHA1,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			expected:  "b17e04cbb22afa8ffbff8796fc1894ed27badd9e",
		},
		{
			name:      "SHA256 signature",
			algorithm: HMACSHA256,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			expected:  "f417af3a21bd70379b5796d5f013915e7029f62c580fb0f500f59a35a6f04c89",
		},
		{
			name:      "SHA512 signature",
			algorithm: HMACSHA512,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			expected:  "4ab17cc8ec668ead8bf498f87f8f32848c04d5ca3c9bcfcd3db9363f0deb44e580b329502a7fdff633d4d8fca301cc5c94a55a2fec458c675fb0ff2655898324",
		},
		{
			name:      "SHA1 empty payload",
			algorithm: HMACSHA1,
			secret:    "secret",
			payload:   []byte(``),
			expected:  "25af6174a0fcecc4d346680a72b7ce644b9a88e8",
		},
		{
			name:      "SHA256 empty payload",
			algorithm: HMACSHA256,
			secret:    "secret",
			payload:   []byte(``),
			expected:  "f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169",
		},
		{
			name:      "Invalid algorithm returns empty signature",
			algorithm: HMACAlgorithm(999),
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewHMACVerifier(tt.algorithm, tt.secret)
			got := v.Sign(tt.payload)
			if got != tt.expected {
				t.Errorf("HMACVerifier.Sign() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHMACVerifier_SignWithPrefix(t *testing.T) {
	v := NewHMACVerifier(HMACSHA256, "secret")
	got := v.SignWithPrefix([]byte(`{"a": "z"}`))
	expected := "sha256=f417af3a21bd70379b5796d5f013915e7029f62c580fb0f500f59a35a6f04c89"
	if got != expected {
		t.Errorf("HMACVerifier.SignWithPrefix() = %v, want %v", got, expected)
	}
}

func TestHMACVerifier_SignBase64(t *testing.T) {
	// MS Teams uses base64-encoded secret
	secret, _ := base64.StdEncoding.DecodeString("bmV2ZXJnb25uYWdpdmV5b3V1cA==")
	v := NewHMACVerifierFromBytes(HMACSHA256, secret)
	got := v.SignBase64([]byte(`{"a": "b"}`))
	expected := "gpjdTlOlaReTBLRFdwqdXhLqG7hFXVYTBorGDpaW5UE="
	if got != expected {
		t.Errorf("HMACVerifier.SignBase64() = %v, want %v", got, expected)
	}
}

func TestHMACVerifier_Verify(t *testing.T) {
	tests := []struct {
		name      string
		algorithm HMACAlgorithm
		secret    string
		payload   []byte
		signature string
		expected  bool
	}{
		// Valid signatures
		{
			name:      "SHA1 valid without prefix",
			algorithm: HMACSHA1,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			signature: "b17e04cbb22afa8ffbff8796fc1894ed27badd9e",
			expected:  true,
		},
		{
			name:      "SHA1 valid with prefix",
			algorithm: HMACSHA1,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			signature: "sha1=b17e04cbb22afa8ffbff8796fc1894ed27badd9e",
			expected:  true,
		},
		{
			name:      "SHA256 valid without prefix",
			algorithm: HMACSHA256,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			signature: "f417af3a21bd70379b5796d5f013915e7029f62c580fb0f500f59a35a6f04c89",
			expected:  true,
		},
		{
			name:      "SHA256 valid with prefix",
			algorithm: HMACSHA256,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			signature: "sha256=f417af3a21bd70379b5796d5f013915e7029f62c580fb0f500f59a35a6f04c89",
			expected:  true,
		},
		// Invalid signatures
		{
			name:      "SHA1 invalid",
			algorithm: HMACSHA1,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			signature: "XXXe04cbb22afa8ffbff8796fc1894ed27badd9e",
			expected:  false,
		},
		{
			name:      "SHA256 invalid",
			algorithm: HMACSHA256,
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			signature: "XXX7af3a21bd70379b5796d5f013915e7029f62c580fb0f500f59a35a6f04c89",
			expected:  false,
		},
		{
			name:      "Wrong secret",
			algorithm: HMACSHA1,
			secret:    "wrongsecret",
			payload:   []byte(`{"a": "z"}`),
			signature: "b17e04cbb22afa8ffbff8796fc1894ed27badd9e",
			expected:  false,
		},
		{
			name:      "Invalid algorithm fails closed",
			algorithm: HMACAlgorithm(999),
			secret:    "secret",
			payload:   []byte(`{"a": "z"}`),
			signature: "f417af3a21bd70379b5796d5f013915e7029f62c580fb0f500f59a35a6f04c89",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewHMACVerifier(tt.algorithm, tt.secret)
			got := v.Verify(tt.payload, tt.signature)
			if got != tt.expected {
				t.Errorf("HMACVerifier.Verify() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHMACVerifier_VerifyAny(t *testing.T) {
	v := NewHMACVerifier(HMACSHA1, "secret")
	payload := []byte(`{"a": "z"}`)

	tests := []struct {
		name       string
		signatures []string
		expected   bool
	}{
		{
			name:       "First signature valid",
			signatures: []string{"b17e04cbb22afa8ffbff8796fc1894ed27badd9e"},
			expected:   true,
		},
		{
			name:       "Second signature valid",
			signatures: []string{"invalid", "b17e04cbb22afa8ffbff8796fc1894ed27badd9e"},
			expected:   true,
		},
		{
			name:       "With prefix",
			signatures: []string{"sha1=b17e04cbb22afa8ffbff8796fc1894ed27badd9e"},
			expected:   true,
		},
		{
			name:       "All invalid",
			signatures: []string{"invalid1", "invalid2"},
			expected:   false,
		},
		{
			name:       "Empty signatures",
			signatures: []string{},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := v.VerifyAny(payload, tt.signatures)
			if got != tt.expected {
				t.Errorf("HMACVerifier.VerifyAny() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHMACVerifier_InvalidAlgorithm(t *testing.T) {
	v := NewHMACVerifier(HMACAlgorithm(999), "secret")
	payload := []byte(`{"a":"z"}`)

	if got := v.Sign(payload); got != "" {
		t.Errorf("Sign() with invalid algorithm should return empty, got %q", got)
	}
	if got := v.SignWithPrefix(payload); got != "" {
		t.Errorf("SignWithPrefix() with invalid algorithm should return empty, got %q", got)
	}
	if got := v.SignBase64(payload); got != "" {
		t.Errorf("SignBase64() with invalid algorithm should return empty, got %q", got)
	}
	if v.Verify(payload, "anything") {
		t.Error("Verify() with invalid algorithm should return false")
	}
	ok, expected := v.VerifyAny(payload, []string{"a", "b"})
	if ok || expected != "" {
		t.Errorf("VerifyAny() with invalid algorithm should fail closed, got ok=%v expected=%q", ok, expected)
	}
	if v.VerifyBase64(payload, "anything") {
		t.Error("VerifyBase64() with invalid algorithm should return false")
	}
}

func TestHMACVerifier_VerifyBase64(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString("bmV2ZXJnb25uYWdpdmV5b3V1cA==")
	v := NewHMACVerifierFromBytes(HMACSHA256, secret)

	tests := []struct {
		name      string
		payload   []byte
		signature string
		expected  bool
	}{
		{
			name:      "Valid base64 signature",
			payload:   []byte(`{"a": "b"}`),
			signature: "gpjdTlOlaReTBLRFdwqdXhLqG7hFXVYTBorGDpaW5UE=",
			expected:  true,
		},
		{
			name:      "Invalid base64 signature",
			payload:   []byte(`{"a": "b"}`),
			signature: "1337TlOlaReTBLRFdwqdXhLqG7hFXVYTBorGDpaW5UE=",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.VerifyBase64(tt.payload, tt.signature)
			if got != tt.expected {
				t.Errorf("HMACVerifier.VerifyBase64() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestComputeHMACFunctions(t *testing.T) {
	payload := []byte(`{"a": "z"}`)
	secret := "secret"

	// Test SHA1
	sha1Result := ComputeHMACSHA1(payload, secret)
	if sha1Result != "b17e04cbb22afa8ffbff8796fc1894ed27badd9e" {
		t.Errorf("ComputeHMACSHA1() = %v", sha1Result)
	}

	// Test SHA256
	sha256Result := ComputeHMACSHA256(payload, secret)
	if sha256Result != "f417af3a21bd70379b5796d5f013915e7029f62c580fb0f500f59a35a6f04c89" {
		t.Errorf("ComputeHMACSHA256() = %v", sha256Result)
	}

	// Test SHA512
	sha512Result := ComputeHMACSHA512(payload, secret)
	if sha512Result != "4ab17cc8ec668ead8bf498f87f8f32848c04d5ca3c9bcfcd3db9363f0deb44e580b329502a7fdff633d4d8fca301cc5c94a55a2fec458c675fb0ff2655898324" {
		t.Errorf("ComputeHMACSHA512() = %v", sha512Result)
	}
}

func TestVerifyHMACFunctions(t *testing.T) {
	payload := []byte(`{"a": "z"}`)
	secret := "secret"

	// Test VerifyHMACSHA1
	if !VerifyHMACSHA1(payload, secret, "b17e04cbb22afa8ffbff8796fc1894ed27badd9e") {
		t.Error("VerifyHMACSHA1() should return true for valid signature")
	}
	if VerifyHMACSHA1(payload, secret, "invalid") {
		t.Error("VerifyHMACSHA1() should return false for invalid signature")
	}

	// Test VerifyHMACSHA256
	if !VerifyHMACSHA256(payload, secret, "f417af3a21bd70379b5796d5f013915e7029f62c580fb0f500f59a35a6f04c89") {
		t.Error("VerifyHMACSHA256() should return true for valid signature")
	}
	if VerifyHMACSHA256(payload, secret, "invalid") {
		t.Error("VerifyHMACSHA256() should return false for invalid signature")
	}

	// Test VerifyHMACSHA512
	if !VerifyHMACSHA512(payload, secret, "4ab17cc8ec668ead8bf498f87f8f32848c04d5ca3c9bcfcd3db9363f0deb44e580b329502a7fdff633d4d8fca301cc5c94a55a2fec458c675fb0ff2655898324") {
		t.Error("VerifyHMACSHA512() should return true for valid signature")
	}
	if VerifyHMACSHA512(payload, secret, "invalid") {
		t.Error("VerifyHMACSHA512() should return false for invalid signature")
	}
}

func TestExtractSignatures(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		prefix   string
		expected []string
	}{
		{
			name:     "Single without prefix",
			source:   "abc123",
			prefix:   "sha256=",
			expected: []string{"abc123"},
		},
		{
			name:     "Single with prefix",
			source:   "sha256=abc123",
			prefix:   "sha256=",
			expected: []string{"abc123"},
		},
		{
			name:     "Multiple with prefix",
			source:   "sha256=invalid, sha256=abc123",
			prefix:   "sha256=",
			expected: []string{"invalid", "abc123"},
		},
		{
			name:     "Multiple mixed",
			source:   "sha1=xyz, sha256=abc123",
			prefix:   "sha256=",
			expected: []string{"abc123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSignatures(tt.source, tt.prefix)
			if len(got) != len(tt.expected) {
				t.Errorf("ExtractSignatures() len = %v, want %v", len(got), len(tt.expected))
				return
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("ExtractSignatures()[%d] = %v, want %v", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestHMACVerifier_Algorithm(t *testing.T) {
	v := NewHMACVerifier(HMACSHA256, "secret")
	if v.Algorithm() != HMACSHA256 {
		t.Errorf("HMACVerifier.Algorithm() = %v, want %v", v.Algorithm(), HMACSHA256)
	}
}
