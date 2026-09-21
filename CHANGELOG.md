# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Import Versioning](https://go.dev/ref/mod#major-version-suffixes).

## [2.0.0] - 2026-09-21

The release exists to get `golang.org/x/crypto` out of the dependency graph of
every service that imports this kit without hashing a password.

### Changed (breaking)

- **The module path is now `github.com/soulteary/secure-kit/v2`.** Required by
  Go's import compatibility rule, because this release removes exported
  symbols. Every importer must update, including ones that hash no passwords:

  ```bash
  go get github.com/soulteary/secure-kit/v2
  go mod edit -droprequire github.com/soulteary/secure-kit
  ```

- **Argon2id and bcrypt moved to the `passwd` subpackage**
  (`github.com/soulteary/secure-kit/v2/passwd`). They are the only things in the
  kit that need `golang.org/x/crypto`; keeping them in the root package meant
  every importer linked it. No shims were left behind — a shim would import
  x/crypto again and give back the whole benefit.

  | Before | After |
  |---|---|
  | `secure.NewArgon2Hasher(...)` | `passwd.NewArgon2Hasher(...)` |
  | `secure.NewArgon2HasherStrict(...)` | `passwd.NewArgon2HasherStrict(...)` |
  | `secure.NewBcryptHasher(...)` | `passwd.NewBcryptHasher(...)` |
  | `secure.NewBcryptHasherStrict(...)` | `passwd.NewBcryptHasherStrict(...)` |
  | `secure.WithArgon2*`, `secure.WithBcryptCost` | `passwd.WithArgon2*`, `passwd.WithBcryptCost` |
  | `secure.Argon2Hasher`, `secure.BcryptHasher`, `secure.BcryptResolver` | same names under `passwd.` |

### Added

- `secure.RandReader()` exports the package's current entropy source, so the
  `passwd` subpackage draws salts from it and `secure.SetRandReader` still
  controls them across the package boundary.
- `deps_test.go` fails if anything in the root package imports a module outside
  the standard library. Nothing else notices that regression: adding an
  x/crypto import back to a root file compiles and passes every other test.

### Measured effect

For a program importing only the root package, against v1.6.0:

- 113 → 107 linked packages.
- `golang.org/x/crypto` and `golang.org/x/sys` leave `go.mod` entirely — no
  `// indirect` requirement remains — and four lines leave `go.sum`.
- ~2.8% smaller binary.

The binary saving is the small part. The point is that a service which never
hashes a password stops shipping, and stops answering for, a cryptographic
library it does not call.

### Unchanged

`secure.Hasher`, `secure.HashResolver`, `secure.SetRandReader`, the random,
HMAC, comparison, masking, SHA and MD5 helpers all stay in the root package
under their existing names. No hash format, parameter default or behaviour
changed: **hashes written by v1.6.0 verify under v2.0.0.**

## [1.6.0] - 2026-09-12

### Fixed

- **Out-of-range option values are rejected, not discarded.** `WithArgon2Time(32)`
  left the work factor at `1` and `WithBcryptCost(14)` left the cost at `10` —
  no error, no panic, no way to tell the hashes were weaker than asked for.
  `NewArgon2Hasher` and `NewBcryptHasher` now panic on an invalid value;
  `NewArgon2HasherStrict` and `NewBcryptHasherStrict` report it as an error.
  Combined Argon2 parameters are validated together, not only field by field.
- **`VerifyAny` no longer returns the expected signature on failure.** On the
  failure path the second return value was the correct HMAC for the payload just
  rejected, so any caller that logged it published a forgeable value. It is
  empty now unless something matched.
- **`RandomString` indexes runes, not bytes.** Indexing by byte split multi-byte
  runes and produced invalid UTF-8 for any non-ASCII charset.
- **`RandomIntRange` handles the full `int64` range.** `max-min+1` was computed
  in `int64`, so `[0, MaxInt64]` produced a negative bound and `[MinInt64,
  MaxInt64]` wrapped. The span is computed in `big.Int`.
- **`ExtractSignatures` filters the prefix uniformly.** The single-value path
  skipped filtering, so `"sha1=xyz"` came back as a candidate `sha256`
  signature while the same value inside a comma-separated list was dropped.
- Argon2 PHC parsing no longer reads Base64 padding as a prefix.

### Documented

- The simple `salt:hash` Argon2 format records no parameters, so `Verify`
  re-derives with the hasher's *current* settings and any parameter change makes
  every stored hash fail as a wrong password. Use `HashWithParams` (PHC) unless
  an existing store forces the simple format.
- Requirements said Go 1.26; `go.mod` requires `1.27.0`.

## [1.5.0] - 2026-08-27

- Go 1.27.0.
- Go Report Card in CI, with the badge linked to the generated report.

## [1.4.0] - 2026-08-12

- Dependency upgrades.

## [1.3.0] - 2026-03-06

- Hardened Argon2 simple-format verification.
- Security improvements; dependency and golangci-lint upgrades.

## [1.2.0] - 2026-02-03

- Security improvements; dependency upgrades.

## [1.1.1] - 2026-02-01

- CI fixes.

## [1.1.0] - 2026-01-27

### Added

- HMAC computation and verification: `HMACVerifier`, the `ComputeHMACSHA*` and
  `VerifyHMACSHA*` helpers, and `ExtractSignatures`.

## [1.0.0] - 2026-01-25

Initial release: Argon2id, bcrypt, SHA-256/512 and MD5 hashers behind a unified
`Hasher` interface, secure random generation, constant-time comparison and
sensitive-data masking.

[2.0.0]: https://github.com/soulteary/secure-kit/releases/tag/v2.0.0
[1.6.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.6.0
[1.5.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.5.0
[1.4.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.4.0
[1.3.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.3.0
[1.2.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.2.0
[1.1.1]: https://github.com/soulteary/secure-kit/releases/tag/v1.1.1
[1.1.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.1.0
[1.0.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.0.0
