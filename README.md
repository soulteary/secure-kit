# secure-kit

[![Go Reference](https://pkg.go.dev/badge/github.com/soulteary/secure-kit.svg)](https://pkg.go.dev/github.com/soulteary/secure-kit)
[![Go Report Card](.github/goreportcard.svg)](.github/goreportcard-report.md)
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

// Default parameters
hasher := secure.NewArgon2Hasher()

// Custom parameters
hasher = secure.NewArgon2Hasher(
    secure.WithArgon2Time(2),
    secure.WithArgon2Memory(64*1024),
    secure.WithArgon2Threads(4),
)

hash, err := hasher.Hash("myPassword123!")
if err != nil {
    log.Fatal(err)
}

if hasher.Verify(hash, "myPassword123!") {
    fmt.Println("Password matches!")
}

// PHC format — records the parameters alongside the hash
hash, err = hasher.HashWithParams("password")
// $argon2id$v=19$m=65536,t=1,p=4$salt$hash
```

#### Option validation

An out-of-range option value is **rejected, not ignored**. `NewArgon2Hasher`
panics on one; `NewArgon2HasherStrict` reports it as an error:

```go
hasher, err := secure.NewArgon2HasherStrict(secure.WithArgon2Time(32))
if err != nil {
    // "WithArgon2Time: 32 out of range (1..16)"
}
```

| Option | Valid range |
|--------|-------------|
| `WithArgon2Time` | 1–16 |
| `WithArgon2Memory` | 1–524288 (KiB, i.e. up to 512 MiB) |
| `WithArgon2Threads` | 1–255 |
| `WithArgon2KeyLen` | 1–1024 |
| `WithArgon2SaltLen` | 1–1024 |

Use the `Strict` constructor wherever the parameters come from configuration, so
a bad value fails startup rather than the process.

#### Choose the storage format deliberately

`Hash` produces the simple `salt:hash` format, which **records no parameters**.
`Verify` therefore re-derives with whatever the hasher is configured with *now*:
any later change to memory, time, threads or keyLen makes **every stored hash
fail**, reported as a wrong password, with no way to migrate.

`HashWithParams` produces PHC format, which carries the parameters, so old hashes
keep verifying after you raise the work factor. Use it unless an existing store
forces the simple format.

### bcrypt

### bcrypt

```go
hasher := secure.NewBcryptHasher()

// Or with custom cost
hasher := secure.NewBcryptHasher(secure.WithBcryptCost(12))

hash, _ := hasher.Hash("password")
valid := hasher.Verify(hash, "password")
```

An out-of-range cost is rejected the same way — `NewBcryptHasher` panics,
`NewBcryptHasherStrict` returns an error:

```go
hasher, err := secure.NewBcryptHasherStrict(secure.WithBcryptCost(14))
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

### HMAC Signatures

```go
verifier := secure.NewHMACVerifier(secure.HMACSHA256, "shared-secret")
verifier = secure.NewHMACVerifierFromBytes(secure.HMACSHA256, secretBytes)

sig := verifier.Sign(payload)            // hex
sigB64 := verifier.SignBase64(payload)   // base64
sigPrefixed := verifier.SignWithPrefix(payload) // "sha256=<hex>"

ok := verifier.Verify(payload, sig)
ok = verifier.VerifyBase64(payload, sigB64)
```

Algorithms: `secure.HMACSHA1`, `secure.HMACSHA256`, `secure.HMACSHA512`. The
one-shot helpers are `ComputeHMACSHA1`, `ComputeHMACSHA256` and
`ComputeHMACSHA512`.

#### Verifying against several candidate signatures

A webhook header may carry more than one signature during key rotation:

```go
candidates := secure.ExtractSignatures(r.Header.Get("X-Hub-Signature-256"), "sha256")

ok, matched := verifier.VerifyAny(payload, candidates)
if !ok {
    // matched is EMPTY here. Safe to log.
    return errUnauthorized
}
log.Printf("verified with %s", matched)
```

`matched` is the signature that matched, and is **empty when nothing did** — do
not expect the expected value back on the failure path. `ExtractSignatures`
applies its prefix filter uniformly, whether the source is a single value or a
comma-separated list, and still accepts a bare unprefixed signature from
providers that send one.

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

// Custom charset — indexed by rune, so a non-ASCII charset works
s, err := secure.RandomString(10, secure.CharsetAlphanumeric)
s, err = secure.RandomString(10, "我你他abc")
```

Charsets: `CharsetAlpha`, `CharsetAlphanumeric`, `CharsetAlphanumericLower`,
`CharsetAlphanumericUpper`, `CharsetDigits`, `CharsetHex`, `CharsetURLSafe`.

`RandomIntRange` computes its span in `big.Int`, so the full `int64` range works
— including `[0, math.MaxInt64]` and `[math.MinInt64, math.MaxInt64]`.

`RandomBytes` refuses a request above `secure.MaxRandomBytes` (1 MiB).
`MustRandomBytes` and `RandomBytesOrPanic` panic instead of returning an error.
`SetRandReader` swaps the entropy source, for tests only.

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

All hash verification in this package uses constant-time comparison to avoid timing side-channel leaks.

### Security Notes

- Prefer `HashWithParams` (PHC format) for long-lived storage, so Argon2 parameters are preserved alongside the hash.
- Treat stored hashes as trusted configuration. If your system accepts hashes from untrusted sources, enforce size/cost limits (e.g., Argon2 parameter caps and bcrypt cost caps) to avoid CPU or memory DoS.
- `PlaintextHasher` and `MD5Hasher` exist only for legacy compatibility; avoid them in production paths.

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

## Upgrade Notes (v1.6.0)

**Two constructors can now panic where they previously returned a weaker hasher
than you asked for.** That is the fix, not a regression.

- **An out-of-range option value is rejected, not discarded.**
  `WithArgon2Time(32)` left the work factor at `1`, and `WithBcryptCost(14)` left
  the cost at `10` — no error, no panic, no way to tell. The caller believed the
  stored hashes were stronger than they were, which is the worst failure mode for
  a parameter whose whole purpose is strength. `NewArgon2Hasher` and
  `NewBcryptHasher` now **panic** on an invalid value; `NewArgon2HasherStrict` and
  `NewBcryptHasherStrict` report it as an error. **If you pass option values from
  configuration, switch to the `Strict` constructors** so a bad value fails
  startup instead of the process — and check whether any value you were passing
  was silently out of range, because your stored hashes are weaker than intended.
- **`VerifyAny` no longer returns the expected signature on failure.** The second
  return value is documented as the matching signature, and on the failure path it
  was the correct HMAC for the payload just rejected — so any caller that logged or
  echoed it **published a forgeable value**. It is empty now unless something
  matched.
- **`RandomString` indexes runes, not bytes.** The parameter is documented as a
  character set; indexing by byte split multi-byte runes and produced invalid UTF-8
  for any non-ASCII charset.
- **`RandomIntRange` handles the full `int64` range.** `max-min+1` was computed in
  `int64`, so `[0, MaxInt64]` produced a negative bound and an error, and
  `[MinInt64, MaxInt64]` wrapped. The span is computed in `big.Int`.
- **`ExtractSignatures` filters the prefix uniformly.** The single-value path
  skipped filtering entirely, so `"sha1=xyz"` came back as a candidate `sha256`
  signature while the same value inside a comma-separated list was correctly
  dropped.
- **Documented, not changed**: the simple `salt:hash` Argon2 format records no
  parameters, so `Verify` re-derives with the hasher's *current* settings and any
  parameter change makes every stored hash fail as a wrong password. Use
  `HashWithParams` (PHC) unless an existing store forces the simple format.
- **Requirements said Go 1.26**; `go.mod` requires `1.27.0`.

## Requirements

- **Go 1.27+** (`go.mod` declares `go 1.27.0`)
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
