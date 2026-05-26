# core/ — invariants

This package is the pure-logic layer. Files here are imported by `jwt_toolkit/commands/`, by the test suite, and (transitively) by anything downstream that links against this package.

## Layering

- **No `click`, no `rich`, no `pyfiglet`.** Functions here return data, raise typed exceptions from `errors.py`, or write to explicit file/stream arguments. They never call `print()`, `click.echo()`, or `console.print()`. Rendering belongs in `cli/` and `commands/`.
- **No `sys.exit()`.** Raise a domain exception; the command layer translates it into `click.ClickException` (and thus exit 1).
- **No process-wide state.** No globals that hold a token, key, or wordlist between calls. Caches (e.g., JWKS) must be passed in or stored on an object the caller owns.

## Crypto invariants

- **Comparisons of secrets, signatures, MACs, and tags MUST use `hmac.compare_digest`** (or `cryptography`'s built-in `.verify(...)` which is constant-time). Never `==`, never `bytes.startswith`, never `if a != b`. A `==` on signature bytes is a regression even if the test passes.
- HMAC algorithms are exposed via `SUPPORTED_ALGORITHMS` in `crypto.py`. This dict is a **public API surface** — `crack` iterates it. Don't rename the keys; add new ones at the end.
- Asymmetric algorithm sets (`RSA_ALGORITHMS`, `EC_ALGORITHMS`, `PSS_ALGORITHMS`) are likewise public. Don't reshape them.
- **Reject `alg=none`** in the verifier by default and forever. `forge` may *produce* an `alg=none` variant — that is its job (defensive self-audit). The verifier must never accept one without an explicit, loud caller opt-in.
- **Reject algorithm confusion.** A token presenting `HS256` must never be verified against a public key loaded for `RS256`. Algorithm family must be derived from the key material the caller supplied, not from the token's `alg` header.
- **No new dependencies for crypto primitives.** Use `hashlib`, `hmac`, or `cryptography`. Do not pull in `pyjwt`, `python-jose`, `authlib`, etc. — re-implementing JWS visibly is part of this project's value.

## Error model

- Exceptions live in `errors.py` as frozen dataclasses.
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
