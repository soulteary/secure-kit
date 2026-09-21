# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Import Versioning](https://go.dev/ref/mod#major-version-suffixes).

## [2.1.0] - 2026-09-21

v2.0.0 took `golang.org/x/crypto` out of the dependency graph of every service
that imports this kit without hashing a password. It missed one dependency,
because that one arrives through the test files: this release removes it and
adds the checks that keep either from coming back.

Nothing in the API changed and the import path is the same, so `go get -u
github.com/soulteary/secure-kit/v2` is the whole upgrade.

### Changed

- **The kit's own tests no longer use testify**, which takes
  `github.com/stretchr/testify` and `go.yaml.in/yaml/v3` out of `go.mod`
  entirely. A test dependency here was never private to the kit: `go mod tidy`
  in an importing module walks the tests of the packages it imports, so the
  chain

  ```
  yourservice -> secure-kit/v2 -> secure-kit/v2.test -> testify/assert
  ```

  held, and put both modules into that service's module graph and four lines
  into its `go.sum` — for a test binary it never builds. `assert_test.go` in
  each package holds the standard-library assertions that replaced testify's;
  coverage is unchanged at 98.8% (root) and 95.2% (`passwd`), and each
  conversion was checked against a deliberately broken implementation to
  confirm the assertions still fail.
- CI actions moved to the versions the other kits run: `actions/checkout`,
  `actions/setup-go` and `actions/upload-artifact` v6 → v7,
  `codecov/codecov-action` v5 → v7, `soulteary/goreportcard-action` v1.0.0 →
  v1.1.2.

### Added

- `deps_test.go` now guards the **test binary** as well as the package graph
  (`go list -deps -test .`). The test binary is the half that reaches
  importers, and the old guard passed with testify imported, by construction.
  `passwd/deps_test.go` is new and bounds that package, tests included, to
  x/crypto and x/sys.
- Runnable `Example` tests for both packages, so pkg.go.dev shows working code
  and `go test` fails when the documented output stops being the real one. They
  cover the webhook-signature path, the masking helpers' exact output, pinning
  the entropy source with `SetRandReader`, and the Argon2 simple format's trap:
  `Hash` records no parameters, so raising the work factor makes every stored
  hash read as a wrong password, while `HashWithParams` survives it.
- `.github/workflows/release.yml`: a release gate. Nine tags existed and
  nothing had ever checked one — CI runs on pushes to main and on pull
  requests, so a tag was published without a single check against the commit it
  names. It runs the CI gate on the tagged commit plus the three checks that
  only matter at tag time: the module path carries the tag's major version, the
  README install instructions point at that path, and the CHANGELOG has a
  section for the version.
- `.github/dependabot.yml`: weekly grouped updates for Go modules and workflow
  actions, majors kept separate.
- README and README_CN gained "What Importing Costs" / "导入的代价": the
  measured table, why test dependencies count, and the MVS caveat below.

### Measured effect

Go 1.27, for a program that imports only the root package, against v2.0.0:

| | v2.0.0 | v2.1.0 |
|---|---|---|
| lines in its `go.sum` | 6 | 2 |
| modules in `go list -m all` | 5 | 3 |
| `// indirect` requirements | 0 | 0 |
| linked packages | 107 | 107 |

A program that imports `passwd` goes from 10 `go.sum` lines to 6, and keeps
x/crypto and x/sys as its two indirect requirements.

Linked packages and binary size are identical, because no compiled code
changed. What changed is what an importer fetches, records and answers for.

### Unchanged, and why

- **`golang.org/x/crypto v0.57.0` is still a version floor for every
  importer**, including one that never imports `passwd`. Minimal version
  selection reads this kit's `go.mod` whatever your program imports from it, so
  a module pinning an older x/crypto has it raised. Nothing links it, `go mod
  why -m` says the main module does not need it, and `go mod tidy` records no
  requirement for it — but `go list -m all` lists it. A subpackage can keep a
  dependency out of a binary and a `go.sum`; it cannot keep a lower bound out
  of a module graph.
- **Argon2id and bcrypt stay in one `passwd` package.** Splitting them further
  would save a bcrypt-only importer `golang.org/x/sys` — one indirect
  requirement and two `go.sum` lines, measured — because bcrypt needs only
  x/crypto/blowfish while Argon2's blake2b needs x/sys/cpu. That is not worth a
  v3 and an import-path edit for every user of both hashers. Breaking changes
  for this kit belong in one major release, not a series of them.
- **The Go dependencies were already current**: x/crypto v0.57.0 and, while it
  lasted, testify v1.12.1 were both the latest releases at the time of writing.
  There was nothing to upgrade, which is why this release is about what the kit
  requires rather than which versions it requires.

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

[2.1.0]: https://github.com/soulteary/secure-kit/releases/tag/v2.1.0
[2.0.0]: https://github.com/soulteary/secure-kit/releases/tag/v2.0.0
[1.6.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.6.0
[1.5.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.5.0
[1.4.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.4.0
[1.3.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.3.0
[1.2.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.2.0
[1.1.1]: https://github.com/soulteary/secure-kit/releases/tag/v1.1.1
[1.1.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.1.0
[1.0.0]: https://github.com/soulteary/secure-kit/releases/tag/v1.0.0
