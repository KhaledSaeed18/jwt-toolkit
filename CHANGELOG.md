# Changelog

All notable changes to jwt-toolkit. New entries are written by release-please from Conventional Commit messages; entries up to 1.2.1 were copied from the GitHub release notes.

## [1.4.0](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v1.3.0...v1.4.0) (2026-11-23)


### Features

* **audit:** verify signatures against a JWKS through one core verifier ([#70](https://github.com/KhaledSaeed18/jwt-toolkit/issues/70)) ([3c5790d](https://github.com/KhaledSaeed18/jwt-toolkit/commit/3c5790dd4d3665b8238eef3c4a1b69a275cb9111))


### Bug Fixes

* **crypto:** reject JWS parts with altered base64url pad bits ([#73](https://github.com/KhaledSaeed18/jwt-toolkit/issues/73)) ([3842089](https://github.com/KhaledSaeed18/jwt-toolkit/commit/3842089caee15c254071e917e2945c33c88063df))


### Security

* **core:** bound and strictly validate token input ([#72](https://github.com/KhaledSaeed18/jwt-toolkit/issues/72)) ([e60ede2](https://github.com/KhaledSaeed18/jwt-toolkit/commit/e60ede2adaf31be222a242c288abae4ce886a567))


### Documentation

* add a code of conduct and an accessibility statement ([#66](https://github.com/KhaledSaeed18/jwt-toolkit/issues/66)) ([2e8765a](https://github.com/KhaledSaeed18/jwt-toolkit/commit/2e8765a02e91f90da1033e95d2c0eeae9f1d727e))

## [1.3.0](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v1.2.1...v1.3.0) (2026-11-23)


### Features

* **cli:** report a specific cause code next to broad --json error codes ([34dabae](https://github.com/KhaledSaeed18/jwt-toolkit/commit/34dabaef92005971473ed031da1e367dfdbb0e19))


### Bug Fixes

* **cli:** emit no escape codes under NO_COLOR and --no-color ([#58](https://github.com/KhaledSaeed18/jwt-toolkit/issues/58)) ([0a6384d](https://github.com/KhaledSaeed18/jwt-toolkit/commit/0a6384dc8c8438eecd5b1bc6c3ced56304a6a05f))


### Security

* **cli:** never echo credentials from JWKS or wordlist source URLs ([34dabae](https://github.com/KhaledSaeed18/jwt-toolkit/commit/34dabaef92005971473ed031da1e367dfdbb0e19))

## [1.2.1](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v1.2.0...v1.2.1) (2026-11-23)

### Fixes

- **Malformed tokens are rejected on Python 3.15.** Python 3.15 stopped rejecting characters outside the base64 alphabet, so a token segment such as `ab!c` decoded to bytes instead of failing. jwt-toolkit now checks the RFC 7515 base64url alphabet itself, so every supported Python rejects such tokens (exit code 2). This also applies to `crack --encoding base64` wordlist entries. ([#55](https://github.com/KhaledSaeed18/jwt-toolkit/pull/55))
- **`download-wordlists` on Windows.** The bundled wordlist stays byte-exact on Windows checkouts, so its pinned SHA-256 matches. ([#55](https://github.com/KhaledSaeed18/jwt-toolkit/pull/55))

### Platform support

CI now tests CPython 3.13, 3.14 and 3.15 on Linux and Windows, plus 3.13 on macOS. Workflows are hardened: read-only token, SHA-pinned actions, zizmor, and no cache in the publish job. ([#55](https://github.com/KhaledSaeed18/jwt-toolkit/pull/55))

No changes to the CLI grammar, `--json` output (`schema_version` is still `0.1`), error codes or exit codes.

## [1.2.0](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v1.1.0...v1.2.0) (2026-10-19)

Hardening release from an end-to-end review of 1.1.0. No `--json` field was renamed or removed (`schema_version` stays `0.1`), and there are no new dependencies.

### Behavior changes

- **`verify` reports attack-shaped tokens as invalid.** A token with `alg: none`, an unknown or mis-cased `alg`, or an `alg` from the other key family than the one you supplied (algorithm confusion, CVE-2016-10555) now fails the signature check and exits **1** with a normal verify report. It used to exit **2** with an error document. Both reject the token; exit 2 remains for operator errors such as no key or two keys.
- **`audit --secret` grades F for a guessable secret.** When the secret verifies the token and is in the bundled common-secrets list, the audit reports it as CRITICAL.

### New

- `audit` checks supplied key material: secrets from the common-secrets list (CRITICAL), secrets shorter than RFC 7518 3.2 requires (WARN), RSA keys under 2048 bits (CRITICAL). It also flags stripped signatures, gives `x5c` its own rule, and checks `iss`/`sub`/`aud` types.
- `crack --json` for CI, with new error codes `signature_missing`, `wordlist_missing`, `wordlist_unreadable`, and `wordlist_empty`.
- Tokens pasted as `Bearer <jwt>` work in every command.
- `sign --private-key` without `--alg` picks the algorithm from the key (RS256, ES256/384/512, Ed25519, Ed448).
- `verify --jwks-url` refuses keys published for encryption, responses over 1 MiB, and https-to-http redirects, and warns when keys come over plain `http://`.

### Fixed

- `--quiet` no longer hides results and errors (`--quiet generate-secret` printed nothing).
- Errors and progress go to stderr, so `sign ... > token.jwt` no longer captures an error panel.
- No more tracebacks on non-ASCII signatures, a directory as the `crack` wordlist, binary `@file` tokens, or malformed JWKS entries.
- `crack --output` saves the exact secret, readable by its owner only.
- `download-wordlists --force` keeps the existing copy when a download fails its checksum or is interrupted.
- `forge` emits JSON errors under `--json` and refuses a private key passed as `--public-key`.

### Internal

mypy strict mode, claim checks and wordlist streaming moved into `core/`, pre-commit hooks synced with `uv.lock`, and CI installs with `--locked`.

## [1.1.0](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v1.0.0...v1.1.0) (2026-10-17)

### Highlights

- **New `diff` command.** Compare two tokens field by field, with JSON Pointer paths and identity, permission, and lifetime fields highlighted. Supports `--json` and `--exit-code`. ([#37](https://github.com/KhaledSaeed18/jwt-toolkit/pull/37))
- **EdDSA support.** `Ed25519`, `Ed448`, and `EdDSA` in `sign`, `verify`, `audit`, and JWKS (`kty: OKP`). ([#33](https://github.com/KhaledSaeed18/jwt-toolkit/pull/33))
- **`crack` works out of the box.** The curated wordlist ships with the package and is used when no wordlist is given. ([#34](https://github.com/KhaledSaeed18/jwt-toolkit/pull/34)) Candidates are checked in worker processes, which ran about twice as fast in our 5M-candidate test. ([#28](https://github.com/KhaledSaeed18/jwt-toolkit/pull/28))
- **Safer and easier inputs.** `--secret-file` for `sign`, `verify`, and `audit` ([#38](https://github.com/KhaledSaeed18/jwt-toolkit/pull/38)); X.509 certificates as public keys and encrypted private keys via `--passphrase-file` or a prompt ([#35](https://github.com/KhaledSaeed18/jwt-toolkit/pull/35)); `sign --payload-file` and `--expires-in 15m` ([#39](https://github.com/KhaledSaeed18/jwt-toolkit/pull/39)); `generate-secret --raw` ([#36](https://github.com/KhaledSaeed18/jwt-toolkit/pull/36)).
- **Readable time claims.** `decode` shows `iat`, `nbf`, and `exp` in UTC and relative to now. ([#41](https://github.com/KhaledSaeed18/jwt-toolkit/pull/41))
- **New README** with full documentation and a new header image. ([#43](https://github.com/KhaledSaeed18/jwt-toolkit/pull/43))

### Behavior changes

These are fixes, but they can change results you rely on:

- `alg` is matched case-sensitively, as RFC 7515 requires. `verify` rejects `hs256`, and `sign --header` no longer accepts lowercase names. ([#25](https://github.com/KhaledSaeed18/jwt-toolkit/pull/25))
- `verify` rejects tokens that use `crit`, treats a token as expired at its `exp` second, and rejects non-numeric, `NaN`, or infinite time claims. ([#25](https://github.com/KhaledSaeed18/jwt-toolkit/pull/25))
- Headers and payloads must be JSON objects. Other values are a decode error (exit 2) instead of a crash. ([#25](https://github.com/KhaledSaeed18/jwt-toolkit/pull/25))
- Every `--json` failure path now prints a JSON error document with a stable `error` code. ([#25](https://github.com/KhaledSaeed18/jwt-toolkit/pull/25))
- `crack` tries wordlist lines exactly as written. Leading or trailing spaces, lines starting with `#`, and non-UTF-8 bytes are no longer skipped or altered. `--threads` is now `--workers` (the old name still works), with a default of 4. ([#27](https://github.com/KhaledSaeed18/jwt-toolkit/pull/27), [#28](https://github.com/KhaledSaeed18/jwt-toolkit/pull/28))
- `audit --require` flags any listed claim, not only `iss`, `aud`, and `iat`. A `--strict` gate may now fail where it passed before. ([#42](https://github.com/KhaledSaeed18/jwt-toolkit/pull/42))
- `download-wordlists` fetches from this release's tag and no longer has an unverified-TLS fallback. ([#26](https://github.com/KhaledSaeed18/jwt-toolkit/pull/26))

`--json` output keeps `schema_version` `0.1`. All changes to it are additive, such as `header_only` on `forge` variants ([#31](https://github.com/KhaledSaeed18/jwt-toolkit/pull/31)) and the `input` field on `diff` errors.

### Security fixes

- Token contents, wordlist lines, and paths are rendered as literal text. A crafted claim such as `[/x]` could crash `audit`, `verify`, `decode`, `forge`, or `crack`, and balanced markup could restyle a report. ([#40](https://github.com/KhaledSaeed18/jwt-toolkit/pull/40), [#26](https://github.com/KhaledSaeed18/jwt-toolkit/pull/26))
- `forge` marks the four header-only variants, whose rejection does not prove the named flaw is absent. ([#31](https://github.com/KhaledSaeed18/jwt-toolkit/pull/31))

### Packaging and project

- Ships `py.typed` and exposes `jwt_toolkit.__version__`. ([#32](https://github.com/KhaledSaeed18/jwt-toolkit/pull/32))
- The publish workflow runs the full check suite on the tagged commit and refuses tags that do not match the package version. ([#30](https://github.com/KhaledSaeed18/jwt-toolkit/pull/30))
- SECURITY.md describes the 1.x support policy. ([#29](https://github.com/KhaledSaeed18/jwt-toolkit/pull/29))
- The sdist no longer bundles README images. ([#45](https://github.com/KhaledSaeed18/jwt-toolkit/pull/45))

## [1.0.0](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v0.1.3...v1.0.0) (2026-07-03)

First stable release of **jwt-toolkit**: a defensive CLI for inspecting, verifying, auditing, forging (for self-audit), and brute-forcing weak HMAC secrets on JSON Web Tokens.

The public surface (CLI grammar, `--json` schema `0.1`, and `core/errors.py` codes) is unchanged from `v0.1.3`; this release promotes the project to a committed `1.0` line.

### Changes since v0.1.3

- **Security:** bump `cryptography` to `49.0.0` (GHSA-537c-gmf6-5ccf) and `msgpack` to `1.2.1` (GHSA-6v7p-g79w-8964); `pip-audit` is clean.
- **Deps:** routine dependency and GitHub Actions updates via Dependabot.
- **Docs:** refreshed README badges and added a feature overview for the PyPI homepage.
- **Packaging:** development status promoted to `4 - Beta`.


## [0.1.3](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v0.1.2...v0.1.3) (2026-05-26)

Maintenance release.

## [0.1.2](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v0.1.1...v0.1.2) (2026-05-25)

Maintenance release.

## [0.1.1](https://github.com/KhaledSaeed18/jwt-toolkit/compare/v0.1.0...v0.1.1) (2026-05-25)

Maintenance release.

## 0.1.0 (2026-05-25)

Initial release of jwt-toolkit: decode, sign, verify (incl. JWKS), audit, forge, crack, generate-secret, download-wordlists.
