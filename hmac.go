package secure

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strings"
)

// HMACAlgorithm represents supported HMAC algorithms.
type HMACAlgorithm int

const (
	// HMACSHA1 uses SHA-1 for HMAC computation.
	// Note: SHA-1 is considered weak but still used by many webhook providers (e.g., GitHub).
	HMACSHA1 HMACAlgorithm = iota
	// HMACSHA256 uses SHA-256 for HMAC computation (recommended).
	HMACSHA256
	// HMACSHA512 uses SHA-512 for HMAC computation.
	HMACSHA512
)

// String returns the algorithm name.
func (a HMACAlgorithm) String() string {
	switch a {
	case HMACSHA1:
		return "sha1"
	case HMACSHA256:
		return "sha256"
	case HMACSHA512:
		return "sha512"
	default:
		return "unknown"
	}
}

// Prefix returns the common signature prefix (e.g., "sha256=").
func (a HMACAlgorithm) Prefix() string {
	return a.String() + "="
}

// HMACVerifier provides HMAC signature generation and verification.
type HMACVerifier struct {
	algorithm HMACAlgorithm
	secret    []byte
}

func isValidHMACAlgorithm(a HMACAlgorithm) bool {
	switch a {
	case HMACSHA1, HMACSHA256, HMACSHA512:
		return true
	default:
		return false
	}
}

// NewHMACVerifier creates a new HMAC verifier with the specified algorithm and secret.
func NewHMACVerifier(algorithm HMACAlgorithm, secret string) *HMACVerifier {
	return &HMACVerifier{
		algorithm: algorithm,
		secret:    []byte(secret),
	}
}

// NewHMACVerifierFromBytes creates a new HMAC verifier with a byte slice secret.
// This is useful when the secret is already decoded (e.g., from base64).
func NewHMACVerifierFromBytes(algorithm HMACAlgorithm, secret []byte) *HMACVerifier {
	return &HMACVerifier{
		algorithm: algorithm,
		secret:    secret,
	}
}

// hashFunc returns the appropriate hash function for the algorithm.
func (v *HMACVerifier) hashFunc() func() hash.Hash {
	switch v.algorithm {
	case HMACSHA1:
		return sha1.New
	case HMACSHA256:
		return sha256.New
	case HMACSHA512:
		return sha512.New
	default:
		return sha256.New
	}
}

// Sign computes the HMAC signature for the given payload.
// Returns the signature as a lowercase hex string.
func (v *HMACVerifier) Sign(payload []byte) string {
	if !isValidHMACAlgorithm(v.algorithm) {
		return ""
	}
	mac := hmac.New(v.hashFunc(), v.secret)
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// SignWithPrefix computes the HMAC signature and returns it with the algorithm prefix.
// Example: "sha256=abc123..."
func (v *HMACVerifier) SignWithPrefix(payload []byte) string {
	if !isValidHMACAlgorithm(v.algorithm) {
		return ""
	}
	return v.algorithm.Prefix() + v.Sign(payload)
}

// SignBase64 computes the HMAC signature and returns it as base64.
// This is used by some providers like MS Teams.
func (v *HMACVerifier) SignBase64(payload []byte) string {
	if !isValidHMACAlgorithm(v.algorithm) {
		return ""
	}
	mac := hmac.New(v.hashFunc(), v.secret)
	mac.Write(payload)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks if the provided signature matches the computed HMAC.
// The signature can be with or without the algorithm prefix (e.g., "sha256=...").
// Uses constant-time comparison to prevent timing attacks.
func (v *HMACVerifier) Verify(payload []byte, signature string) bool {
	if !isValidHMACAlgorithm(v.algorithm) {
		return false
	}
	// Remove algorithm prefix if present
	sig := strings.TrimPrefix(signature, v.algorithm.Prefix())

	expected := v.Sign(payload)
	return ConstantTimeEqual(expected, sig)
}

// VerifyAny checks if any of the provided signatures match the computed HMAC.
// This is useful for webhooks that may send multiple signatures.
// Uses constant-time comparison to prevent timing attacks.
//
// The second return value is the matching signature, and is EMPTY when nothing
// matched. It previously returned the expected signature on the failure path
// too, which handed a caller the correct HMAC for a payload whose signature
// had just been rejected -- anything that logged or echoed it published a
// forgeable value.
func (v *HMACVerifier) VerifyAny(payload []byte, signatures []string) (bool, string) {
	if !isValidHMACAlgorithm(v.algorithm) {
		return false, ""
	}
	expected := v.Sign(payload)

	for _, sig := range signatures {
		// Remove algorithm prefix if present
		cleanSig := strings.TrimPrefix(sig, v.algorithm.Prefix())
		if ConstantTimeEqual(expected, cleanSig) {
			return true, expected
		}
	}

	return false, ""
}

// VerifyBase64 checks if the provided base64-encoded signature matches.
// This is used by some providers like MS Teams.
func (v *HMACVerifier) VerifyBase64(payload []byte, signature string) bool {
	if !isValidHMACAlgorithm(v.algorithm) {
		return false
	}
	expected := v.SignBase64(payload)
	return ConstantTimeEqual(expected, signature)
}

// Algorithm returns the HMAC algorithm being used.
func (v *HMACVerifier) Algorithm() HMACAlgorithm {
	return v.algorithm
}

// Helper functions for common use cases

// ComputeHMACSHA1 computes HMAC-SHA1 for the given payload and secret.
// Returns the signature as a lowercase hex string.
func ComputeHMACSHA1(payload []byte, secret string) string {
	v := NewHMACVerifier(HMACSHA1, secret)
	return v.Sign(payload)
}

// ComputeHMACSHA256 computes HMAC-SHA256 for the given payload and secret.
// Returns the signature as a lowercase hex string.
func ComputeHMACSHA256(payload []byte, secret string) string {
	v := NewHMACVerifier(HMACSHA256, secret)
	return v.Sign(payload)
}

// ComputeHMACSHA512 computes HMAC-SHA512 for the given payload and secret.
// Returns the signature as a lowercase hex string.
func ComputeHMACSHA512(payload []byte, secret string) string {
	v := NewHMACVerifier(HMACSHA512, secret)
	return v.Sign(payload)
}

// VerifyHMACSHA1 verifies an HMAC-SHA1 signature.
// Returns true if the signature is valid.
func VerifyHMACSHA1(payload []byte, secret, signature string) bool {
	v := NewHMACVerifier(HMACSHA1, secret)
	return v.Verify(payload, signature)
}

// VerifyHMACSHA256 verifies an HMAC-SHA256 signature.
// Returns true if the signature is valid.
func VerifyHMACSHA256(payload []byte, secret, signature string) bool {
	v := NewHMACVerifier(HMACSHA256, secret)
	return v.Verify(payload, signature)
}

// VerifyHMACSHA512 verifies an HMAC-SHA512 signature.
// Returns true if the signature is valid.
func VerifyHMACSHA512(payload []byte, secret, signature string) bool {
	v := NewHMACVerifier(HMACSHA512, secret)
	return v.Verify(payload, signature)
}

// ExtractSignatures extracts signatures from a comma-separated list.
// It also handles algorithm prefixes (e.g., "sha256=...").
//
// Entries carrying the prefix are returned with it stripped. Entries carrying
// a DIFFERENT algorithm prefix are dropped -- previously a single unprefixed
// value was returned verbatim whatever it was, so "sha1=xyz" came back as a
// candidate "sha256" signature while the same value inside a comma-separated
// list was correctly filtered out.
//
// Providers that send a bare signature with no prefix at all are still
// supported: when no entry carries any "alg=" prefix, the values are returned
// as-is.
// signaturePrefixOf returns the leading "alg=" prefix of part, or "" when part
// carries none.
//
// A bare Base64 signature ends in "=" padding, which is not an algorithm
// prefix. Treating any "=" as one made "gpjd...W5UE=" look prefixed, so a
// caller asking for "sha256=" filtered the value away and got an empty slice
// -- rejecting the valid bare signatures this function documents support for.
func signaturePrefixOf(part string) string {
	i := strings.IndexByte(part, '=')
	if i <= 0 {
		return ""
	}
	// Everything after the "=" being padding means this was padding too.
	if strings.Trim(part[i+1:], "=") == "" {
		return ""
	}
	for _, r := range part[:i] {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return ""
		}
	}
	return part[:i+1]
}

func ExtractSignatures(source, prefix string) []string {
	parts := strings.Split(source, ",")

	values := make([]string, 0, len(parts))
	anyPrefixed := false

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if signaturePrefixOf(part) != "" {
			anyPrefixed = true
		}
		values = append(values, part)
	}

	if prefix == "" || !anyPrefixed {
		return values
	}

	matched := make([]string, 0, len(values))
	for _, v := range values {
		if strings.HasPrefix(v, prefix) {
			matched = append(matched, strings.TrimPrefix(v, prefix))
		}
	}
	return matched
}
