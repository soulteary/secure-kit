# secure-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/secure-kit.svg)](https://pkg.go.dev/github.com/soulteary/secure-kit)
[![Go Report Card](https://goreportcard.com/badge/github.com/soulteary/secure-kit)](https://goreportcard.com/report/github.com/soulteary/secure-kit)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![codecov](https://codecov.io/gh/soulteary/secure-kit/graph/badge.svg)](https://codecov.io/gh/soulteary/secure-kit)

[中文文档](README_CN.md)

A unified cryptographic toolkit for Go services. This package provides hash functions (Argon2, bcrypt, SHA, MD5), secure random number generation, constant-time comparison, and sensitive data masking utilities.

## Features

- **Multiple Hash Algorithms**: Argon2id, bcrypt, SHA-256, SHA-512, MD5 with unified interface
- **Secure Random**: Cryptographically secure random bytes, strings, digits, tokens, and UUIDs
- **Timing Attack Prevention**: Constant-time comparison functions
- **Data Masking**: Email, phone, credit card, IP address, API key masking for logging
- **Zero External Dependencies**: Only uses Go standard library and golang.org/x/crypto

## Installation

```bash
go get github.com/soulteary/secure-kit
```

## Usage

### Hash Interface

All hashers implement the unified `Hasher` interface:

```go
type Hasher interface {
    Hash(plaintext string) (string, error)
    Verify(hash, plaintext string) bool
    Algorithm() string
}
```

### Argon2 (Recommended for Passwords)

```go
import secure "github.com/soulteary/secure-kit"

// Create with default parameters
hasher := secure.NewArgon2Hasher()

// Or with custom parameters
hasher := secure.NewArgon2Hasher(
    secure.WithArgon2Time(2),
    secure.WithArgon2Memory(64*1024),
    secure.WithArgon2Threads(4),
)

// Hash a password
hash, err := hasher.Hash("myPassword123!")
if err != nil {
    log.Fatal(err)
}

// Verify a password
if hasher.Verify(hash, "myPassword123!") {
    fmt.Println("Password matches!")
}

// PHC format (compatible with other implementations)
hash, err := hasher.HashWithParams("password")
// Output: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
```

### bcrypt

```go
hasher := secure.NewBcryptHasher()

// Or with custom cost
hasher := secure.NewBcryptHasher(secure.WithBcryptCost(12))

hash, _ := hasher.Hash("password")
valid := hasher.Verify(hash, "password")
```

### SHA-256/SHA-512

```go
sha256Hasher := secure.NewSHA256Hasher()
sha512Hasher := secure.NewSHA512Hasher()

hash, _ := sha256Hasher.Hash("data")
valid := sha256Hasher.Verify(hash, "data")

// Helper functions
sha512Hash := secure.GetSHA512Hash("text")
sha256Hash := secure.GetSHA256Hash("text")
```

### MD5 (Legacy Only)

```go
// WARNING: MD5 is cryptographically broken. Use only for legacy compatibility.
hasher := secure.NewMD5Hasher()
hash, _ := hasher.Hash("data")

// Helper function
md5Hash := secure.GetMD5Hash("text")
```

### Secure Random

```go
// Random bytes
bytes, err := secure.RandomBytes(32)

// Random hex string
hex, err := secure.RandomHex(16) // Returns 32-char hex string

// Random Base64 strings
b64, err := secure.RandomBase64(32)
urlSafeB64, err := secure.RandomBase64URL(32)

// Random digits (for OTP codes)
code, err := secure.RandomDigits(6) // e.g., "847293"

// Random alphanumeric string
token, err := secure.RandomAlphanumeric(20)

// Random token (URL-safe base64)
token, err := secure.RandomToken(32)

// Random UUID (v4)
uuid, err := secure.RandomUUID() // e.g., "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"

// Random integers
n, err := secure.RandomInt(100)           // [0, 100)
n, err := secure.RandomIntRange(10, 20)   // [10, 20]

// Custom charset
s, err := secure.RandomString(10, secure.CharsetAlphanumeric)
```

### Constant-Time Comparison

```go
// Prevent timing attacks when comparing sensitive values
if secure.ConstantTimeEqual(userInput, secretKey) {
    // Valid key
}

// Aliases for familiarity
secure.SecureCompare(a, b)
secure.TimingSafeEqual(a, b)
secure.ConstantTimeEqualBytes([]byte(a), []byte(b))
```

### Data Masking

```go
// Email masking
secure.MaskEmail("user@example.com")        // "u***@example.com"
secure.MaskEmailPartial("john@example.com") // "jo***@example.com"

// Phone masking
secure.MaskPhone("13812345678")      // "138****5678"
secure.MaskPhoneSimple("+1234567890") // "+12***7890"

// Credit card masking
secure.MaskCreditCard("4111111111111111")    // "************1111"
secure.MaskCreditCard("4111-1111-1111-1111") // "****-****-****-1111"

// IP address masking
secure.MaskIPAddress("192.168.1.100") // "192.*.*.*"
secure.MaskIPAddress("2001:db8::1")   // "2001:****:****:..."

// API key masking
secure.MaskAPIKey("sk_live_abcdefghijklmnop") // "sk_l***mnop"

// Name masking
secure.MaskName("John Doe") // "J*** D***"

// Generic string masking
secure.MaskString("1234567890", 3) // "123***890"

// Truncation
secure.TruncateString("long text here", 8) // "long tex..."
```

### Drop-in Resolvers (Stargate Compatibility)

For backward compatibility with existing code:

```go
// These implement the HashResolver interface
var resolver secure.HashResolver

resolver = &secure.BcryptResolver{}
resolver = &secure.SHA512Resolver{}
resolver = &secure.MD5Resolver{}
resolver = &secure.PlaintextResolver{}

// Usage
if resolver.Check(storedHash, userPassword) {
    // Valid password
}
```

## Project Structure

```
secure-kit/
├── interface.go      # Hasher and HashResolver interfaces
├── argon2.go         # Argon2id implementation
├── bcrypt.go         # bcrypt implementation
├── sha.go            # SHA-256/SHA-512 implementation
├── md5.go            # MD5 implementation (legacy)
├── plaintext.go      # Plaintext comparison (testing only)
├── compare.go        # Constant-time comparison
├── random.go         # Secure random generation
├── mask.go           # Sensitive data masking
└── *_test.go         # Comprehensive tests
```

## Security Recommendations

| Use Case | Recommended Algorithm |
|----------|----------------------|
| Password hashing | Argon2id or bcrypt |
| OTP/verification codes | Argon2id |
| API tokens | RandomToken + constant-time compare |
| Checksums | SHA-256 or SHA-512 |
| Legacy systems | MD5 (migration to Argon2 recommended) |

**Never use** SHA-256, SHA-512, or MD5 for password hashing. These are fast hashes designed for integrity checks, not password security.

## Integration Example

### Herald (OTP Service)

```go
import secure "github.com/soulteary/secure-kit"

// Generate OTP code
code, _ := secure.RandomDigits(6)

// Hash for storage
hasher := secure.NewArgon2Hasher()
hash, _ := hasher.Hash(code)

// Store hash in Redis, send code via SMS/email

// Later, verify user input
if hasher.Verify(storedHash, userInputCode) {
    // Valid OTP
}
```

### Stargate (Auth Gateway)

```go
import secure "github.com/soulteary/secure-kit"

// Verify password with multiple algorithms
resolvers := map[string]secure.HashResolver{
    "bcrypt":    &secure.BcryptResolver{},
    "sha512":    &secure.SHA512Resolver{},
    "md5":       &secure.MD5Resolver{},
    "plaintext": &secure.PlaintextResolver{},
}

func verifyPassword(algorithm, hash, password string) bool {
    resolver, ok := resolvers[algorithm]
    if !ok {
        return false
    }
    return resolver.Check(hash, password)
}
```

## Requirements

- Go 1.25 or later
- golang.org/x/crypto (for Argon2 and bcrypt)

## Test Coverage

Run tests:

```bash
go test ./... -v

# With coverage
go test ./... -coverprofile=coverage.out -covermode=atomic
go tool cover -html=coverage.out -o coverage.html
go tool cover -func=coverage.out
```

## Benchmarks

```bash
go test -bench=. -benchmem
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

See [LICENSE](LICENSE) file for details.
