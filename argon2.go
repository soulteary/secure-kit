package secure

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Maximum Argon2 parameters allowed when parsing PHC hashes (DoS prevention).
// Attackers who control stored hashes could otherwise set extreme values.
const (
	maxArgon2MemoryKB = 512 * 1024 // 512 MB
	maxArgon2Time     = 16
	maxArgon2Threads  = 255
	maxArgon2SaltLen  = 1024
	maxArgon2HashLen  = 1024
)

// Default Argon2 parameters
// These are recommended values for most use cases.
// For high-security applications, consider increasing memory and iterations.
const (
	DefaultArgon2Time    = 1         // Number of iterations
	DefaultArgon2Memory  = 64 * 1024 // 64 MB
	DefaultArgon2Threads = 4         // Parallelism
	DefaultArgon2KeyLen  = 32        // 256 bits
	DefaultArgon2SaltLen = 16        // 128 bits
)

// Argon2Hasher implements the Hasher interface using Argon2id algorithm.
// Argon2id is the recommended variant as it provides both side-channel attack
// resistance (from Argon2i) and GPU attack resistance (from Argon2d).
type Argon2Hasher struct {
	time    uint32 // Number of iterations
	memory  uint32 // Memory usage in KB
	threads uint8  // Parallelism factor
	keyLen  uint32 // Output key length in bytes
	saltLen int    // Salt length in bytes
}

// Argon2Option is a function that configures an Argon2Hasher.
type Argon2Option func(*Argon2Hasher)

// WithArgon2Time sets the number of iterations (time parameter).
// Higher values increase security but also computation time.
func WithArgon2Time(t uint32) Argon2Option {
	return func(h *Argon2Hasher) {
		if t > 0 && t <= maxArgon2Time {
			h.time = t
		}
	}
}

// WithArgon2Memory sets the memory usage in KB.
// Higher values increase memory-hardness and security.
func WithArgon2Memory(m uint32) Argon2Option {
	return func(h *Argon2Hasher) {
		if m > 0 && m <= maxArgon2MemoryKB {
			h.memory = m
		}
	}
}

// WithArgon2Threads sets the parallelism factor.
// Should not exceed the number of available CPU cores.
func WithArgon2Threads(t uint8) Argon2Option {
	return func(h *Argon2Hasher) {
		if t > 0 && t <= maxArgon2Threads {
			h.threads = t
		}
	}
}

// WithArgon2KeyLen sets the output key length in bytes.
func WithArgon2KeyLen(l uint32) Argon2Option {
	return func(h *Argon2Hasher) {
		if l > 0 && l <= maxArgon2HashLen {
			h.keyLen = l
		}
	}
}

// WithArgon2SaltLen sets the salt length in bytes.
func WithArgon2SaltLen(l int) Argon2Option {
	return func(h *Argon2Hasher) {
		if l > 0 && l <= maxArgon2SaltLen {
			h.saltLen = l
		}
	}
}

// NewArgon2Hasher creates a new Argon2id hasher with default or custom parameters.
func NewArgon2Hasher(opts ...Argon2Option) *Argon2Hasher {
	h := &Argon2Hasher{
		time:    DefaultArgon2Time,
		memory:  DefaultArgon2Memory,
		threads: DefaultArgon2Threads,
		keyLen:  DefaultArgon2KeyLen,
		saltLen: DefaultArgon2SaltLen,
	}

	for _, opt := range opts {
		opt(h)
	}

	return h
}

// Hash generates an Argon2id hash from the given plaintext.
// The returned format is: "salt:hash" where both are base64-encoded.
// This format is compatible with Herald's existing implementation.
func (h *Argon2Hasher) Hash(plaintext string) (string, error) {
	salt := make([]byte, h.saltLen)
	if _, err := io.ReadFull(getRandReader(), salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(plaintext), salt, h.time, h.memory, h.threads, h.keyLen)

	// Format: salt:hash (both base64-encoded)
	return base64.URLEncoding.EncodeToString(salt) + ":" + base64.URLEncoding.EncodeToString(hash), nil
}

// HashWithParams generates an Argon2id hash and includes all parameters in the output.
// The returned format is: "$argon2id$v=19$m=65536,t=1,p=4$salt$hash"
// This format is compatible with other Argon2 implementations (PHC format).
func (h *Argon2Hasher) HashWithParams(plaintext string) (string, error) {
	salt := make([]byte, h.saltLen)
	if _, err := io.ReadFull(getRandReader(), salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(plaintext), salt, h.time, h.memory, h.threads, h.keyLen)

	// PHC format: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.memory,
		h.time,
		h.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// Verify checks if the plaintext matches the given hash.
// Supports both simple format (salt:hash) and PHC format ($argon2id$...).
func (h *Argon2Hasher) Verify(hash, plaintext string) bool {
	// Try PHC format first
	if strings.HasPrefix(hash, "$argon2id$") {
		return h.verifyPHC(hash, plaintext)
	}

	// Fall back to simple format (salt:hash)
	return h.verifySimple(hash, plaintext)
}

// verifySimple verifies a hash in simple format (salt:hash).
func (h *Argon2Hasher) verifySimple(hash, plaintext string) bool {
	parts := strings.Split(hash, ":")
	if len(parts) != 2 {
		return false
	}

	if base64.URLEncoding.DecodedLen(len(parts[0])) > maxArgon2SaltLen {
		return false
	}
	if base64.URLEncoding.DecodedLen(len(parts[1])) > maxArgon2HashLen {
		return false
	}

	salt, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	if len(salt) == 0 || len(salt) > maxArgon2SaltLen {
		return false
	}

	expectedHash, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	if len(expectedHash) == 0 || len(expectedHash) > maxArgon2HashLen {
		return false
	}
	if len(expectedHash) != int(h.keyLen) {
		return false
	}

	actualHash := argon2.IDKey([]byte(plaintext), salt, h.time, h.memory, h.threads, h.keyLen)
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}

// verifyPHC verifies a hash in PHC format ($argon2id$v=19$m=65536,t=1,p=4$salt$hash).
func (h *Argon2Hasher) verifyPHC(hash, plaintext string) (ok bool) {
	// Protect callers from malformed PHC strings that would otherwise panic
	// inside x/crypto/argon2 parameter validation.
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	params, salt, expectedHash, err := parseArgon2PHC(hash)
	if err != nil {
		return false
	}

	actualHash := argon2.IDKey([]byte(plaintext), salt, params.time, params.memory, params.threads, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}

// Check implements the HashResolver interface.
func (h *Argon2Hasher) Check(hash, plaintext string) bool {
	return h.Verify(hash, plaintext)
}

// Algorithm returns the name of the hash algorithm.
func (h *Argon2Hasher) Algorithm() string {
	return "argon2id"
}

// argon2Params holds parsed Argon2 parameters.
type argon2Params struct {
	time    uint32
	memory  uint32
	threads uint8
}

// parseArgon2PHC parses an Argon2 hash in PHC format.
func parseArgon2PHC(hash string) (*argon2Params, []byte, []byte, error) {
	// Format: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid argon2 hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, errors.New("unsupported argon2 variant")
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return nil, nil, nil, errors.New("unsupported argon2 version")
	}

	// Parse parameters
	paramParts := strings.Split(parts[3], ",")
	if len(paramParts) != 3 {
		return nil, nil, nil, errors.New("invalid argon2 parameters")
	}

	params := &argon2Params{}
	var hasMemory, hasTime, hasThreads bool

	for _, p := range paramParts {
		kv := strings.Split(p, "=")
		if len(kv) != 2 {
			return nil, nil, nil, errors.New("invalid argon2 parameter format")
		}

		val, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid argon2 parameter value: %w", err)
		}

		switch kv[0] {
		case "m":
			params.memory = uint32(val)
			hasMemory = true
		case "t":
			params.time = uint32(val)
			hasTime = true
		case "p":
			params.threads = uint8(val)
			hasThreads = true
		default:
			return nil, nil, nil, errors.New("unknown argon2 parameter")
		}
	}
	if !hasMemory || !hasTime || !hasThreads {
		return nil, nil, nil, errors.New("missing required argon2 parameters")
	}
	if params.memory == 0 || params.time == 0 || params.threads == 0 {
		return nil, nil, nil, errors.New("argon2 parameters must be positive")
	}
	// x/crypto/argon2 requires memory >= 8 * threads.
	if params.memory < 8*uint32(params.threads) {
		return nil, nil, nil, errors.New("argon2 memory too small for parallelism")
	}

	if params.memory > maxArgon2MemoryKB {
		return nil, nil, nil, fmt.Errorf("argon2 memory exceeds maximum: %d", maxArgon2MemoryKB)
	}
	if params.time > maxArgon2Time {
		return nil, nil, nil, fmt.Errorf("argon2 time exceeds maximum: %d", maxArgon2Time)
	}
	if params.threads > maxArgon2Threads {
		return nil, nil, nil, fmt.Errorf("argon2 threads exceeds maximum: %d", maxArgon2Threads)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid salt encoding: %w", err)
	}
	if len(salt) == 0 || len(salt) > maxArgon2SaltLen {
		return nil, nil, nil, errors.New("argon2 salt length out of bounds")
	}

	hashBytes, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash encoding: %w", err)
	}
	if len(hashBytes) == 0 || len(hashBytes) > maxArgon2HashLen {
		return nil, nil, nil, errors.New("argon2 hash length out of bounds")
	}

	return params, salt, hashBytes, nil
}
