# core/ — invariants

This package is the pure-logic layer. Files here are imported by `jwt_toolkit/commands/`, by the test suite, and (transitively) by anything downstream that links against this package.

## Layering

- **No `click`, no `rich`.** Functions here return data, raise typed exceptions from `errors.py`, or write to explicit file/stream arguments. They never call `print()`, `click.echo()`, or `console.print()`. Rendering belongs in `cli/` and `commands/`.
- **No `sys.exit()`.** Raise a domain exception (a `JwtToolkitError` subclass); the CLI error boundary renders it and exits 2.
- **No process-wide state.** No globals that hold a token, key, or wordlist between calls. Caches (e.g., JWKS) must be passed in or stored on an object the caller owns.

## Crypto invariants

- **Comparisons of secrets, signatures, MACs, and tags MUST use `hmac.compare_digest`** (or `cryptography`'s built-in `.verify(...)` which is constant-time). Never `==`, never `bytes.startswith`, never `if a != b`. A `==` on signature bytes is a regression even if the test passes.
- Every JWS algorithm is described once, in the `ALGORITHMS` registry in `algorithms.py`. The public tables (`SUPPORTED_ALGORITHMS` for HMAC, which `crack` iterates, and `RSA_ALGORITHMS`, `EC_ALGORITHMS`, `PSS_ALGORITHMS`) are derived from it and re-exported by `crypto.py`. They are a **public API surface**: don't rename keys or reshape them; add new algorithms at the end. `tests/test_algorithms.py` pins their values.
- Keys are `HmacKey`, `PublicKey` and `PrivateKey` objects (`keys.py`); `check_algorithm(spec)` on the key decides which algorithms it may be used with. Signature checking for `verify` and `audit` goes through one pipeline, `verifier.py`.
- **Reject `alg=none`** in the verifier by default and forever. `forge` may *produce* an `alg=none` variant — that is its job (defensive self-audit). The verifier must never accept one without an explicit, loud caller opt-in.
- **Reject algorithm confusion.** A token presenting `HS256` must never be verified against a public key loaded for `RS256`. Algorithm family must be derived from the key material the caller supplied, not from the token's `alg` header.
- **No new dependencies for crypto primitives.** Use `hashlib`, `hmac`, or `cryptography`. Do not pull in `pyjwt`, `python-jose`, `authlib`, etc. at runtime: re-implementing JWS visibly is part of this project's value. PyJWT is allowed only in the dev group, for the interoperability tests.

## Token input

Tokens are hostile input; read them the way a strict server would (`decoder.py`, `encoding.py`):

- At most `MAX_TOKEN_BYTES` (256 KiB). `cli/decoding.py` reads stdin and `@file` only up to that limit.
- Every part is canonical base64url: no `=` padding, no stray pad bits (`base64url_decode(..., canonical=True)`), so a token has exactly one valid spelling. The signature is decoded by the verifier, which reports a malformed one as a failed check, not an input error.
- Header and payload go through `strict_json_loads`: UTF-8 only, no duplicate member names, at most `MAX_JSON_DEPTH` (32) levels, measured by a linear scan before parsing (Python versions differ in how the parser itself recurses), no `NaN`, `Infinity` or overflowing numbers.
- Whitespace inside a token is an error; only `decode` passes `tolerate_whitespace=True`.
- A refined rejection keeps its existing `code` and adds a `cause` (for example `invalid_json` / `duplicate_member`), so `--json` consumers keep working.
- Any scan of untrusted text must be linear: no regex that can backtrack on hostile input.

## Error model

- Exceptions live in `errors.py` as frozen dataclasses, declared with `@frozen_error` (a plain `@dataclass(frozen=True)` breaks when Python sets `__traceback__` on a propagating exception). Every one subclasses `JwtToolkitError`, which is a `ValueError` for callers that caught `ValueError` before.
- Never `raise ValueError` for a domain failure; pick the typed error or add one with a new code.
- URLs in messages go through `redact_url()`; it drops userinfo, query, and fragment.
- Each carries a stable machine-readable `code` field. **`code` values are forever** — `--json` consumers key off them. Renaming is a breaking change; bump `JSON_SCHEMA_VERSION` and call it out.
- `headline` is the one-line user-facing message; `details` is an optional tuple of supporting lines. Keep both short, security-outcome-shaped, and free of internal jargon.
- Never include secret material in any exception field. That includes the supplied `--secret`, the contents of a private key file, or the raw signature bytes when the failure is "didn't match".

## Network and I/O

- `jwks.py` is the only module allowed to make outbound HTTP requests, and it talks to JWKS endpoints only. No other module fetches over the network.
- File reads (PEM keys, wordlists) are explicit: the caller passes a `Path`. Don't sniff `$HOME`, `~/.config`, or arbitrary env vars from inside `core/`.
- JWKS fetches must be testable offline. Tests use fixtures from `tests/conftest.py` / `tests/helpers.py` — never hit the network.

## Wordlists

- `crack` streams the wordlist line-by-line. Do not load it fully into memory; some real-world lists are gigabytes.
- Decode lines as UTF-8 with `errors="replace"`, strip the BOM if present on the first line, and strip trailing `\r\n` / `\n` — not arbitrary whitespace (a candidate secret may legitimately contain leading or trailing spaces).

## When changing this package

- If you touch any public-API surface listed above (algorithm dicts, error codes, exception shape, signature of an exported function), say so explicitly in the PR description and confirm whether it needs a `JSON_SCHEMA_VERSION` bump.
- Add a test under `tests/test_<module>.py` that exercises the new behavior **without** going through the CLI. CLI-level coverage in `tests/test_cmd_*.py` is necessary but not sufficient.
