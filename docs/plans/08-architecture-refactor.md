# 08 — Architecture refactor

Status: proposed, P1; candidate `v1.1.0`. Baseline and evidence definitions: [index](README.md).

## Objective

Make `core/` a real library that other people can import, and keep commands thin, as `CLAUDE.md` already requires. Today several concepts are defined more than once, verification logic lives in the command layer, and core reports failures as untyped `ValueError` strings. This blocks most planned features: EdDSA, a public Python API, `scan`, and batch verification all need one shared verifier, one algorithm table, and typed errors.

Refactors here should preserve behavior. Land the P0 fixes from [01](01-correctness-and-robustness.md) first as small PRs with regression tests, so those tests guard the refactor.

## Current structure problems (inspected)

| Problem | Where |
| --- | --- |
| Verification logic (temporal, `iss`, `aud`, key dispatch) lives in a command | `commands/verify.py::_check_temporal_claims`, `_check_issuer`, `_check_audience`, `_verify_signature` |
| Signature verification is implemented twice; the `audit` copy has no JWKS support | `commands/audit.py::_check_signature` vs `commands/verify.py::_verify_signature` |
| Key-source validation is implemented twice | `commands/sign.py::_validate_key_inputs`, `commands/verify.py::_validate_key_inputs` |
| Algorithm facts are spread across five tables in three modules | `core/crypto.py` (`_HASH_BY_ALG`, `_EC_CURVE_BY_ALG`, `_EC_RAW_SIG_HALF_BYTES`), `core/jwks.py` (`_KTY_BY_ALG`, `_CRV_BY_ALG`), `core/auditor.py` (its own `SYMMETRIC_ALGORITHMS` / `ASYMMETRIC_ALGORITHMS`) |
| Wire-format algorithm validation sits in `cli/`, not `core/` | `cli/algorithms.py::ensure_signing_algorithm`, `ensure_hmac_algorithm` |
| 30 `raise ValueError(...)` in core with no stable code; `UnsupportedAlgorithmError` has no `code` | `core/crypto.py`, `core/jwks.py`, `core/forge.py`, `core/errors.py` |
| 31 scattered `raise SystemExit(...)` in the CLI layer, each rendering its own error | every file in `commands/`, plus `cli/decoding.py` |
| The whole crack engine (candidate stream, threads, HMAC loop) is in a command | `commands/crack.py` |
| HMAC secrets are `str` only, so a secret found with `crack --encoding hex|base64` cannot be passed to `sign`/`verify`/`audit` | `core/crypto.py::sign` (`secret.encode()`) |
| `__version__` is defined in `cli/__init__.py`; the package root is empty and there is no `py.typed` | `jwt_toolkit/__init__.py` |
| `from __future__ import annotations` despite the 3.13-only rule | `cli/console.py`, `cli/banner.py` |

## REF-001 — Single algorithm registry

Add `core/algorithms.py` with one frozen `AlgorithmSpec` per JWS algorithm: name, family (HMAC/RSA/PSS/EC/OKP), hash, key type, JWK `kty`/`crv`, curve, and raw signature size.

- Derive the existing public names from it: `SUPPORTED_ALGORITHMS`, `RSA_ALGORITHMS`, `EC_ALGORITHMS`, `PSS_ALGORITHMS`, `ASYMMETRIC_ALGORITHMS`, `ALL_SIGNING_ALGORITHMS`, and the auditor's `SYMMETRIC_ALGORITHMS` / `ASYMMETRIC_ALGORITHMS`. Their names, key order, and value types stay the same; they are public API (`core/CLAUDE.md`).
- Move exact-case wire validation of the token `alg` (BUG-004) into core as `require_algorithm(header) -> AlgorithmSpec`. `cli/algorithms.py` keeps only presentation copy.
- After this, adding EdDSA (RFC 8037) is a registry entry plus one sign/verify branch.

Acceptance: a test asserts that every derived public set equals its pre-refactor literal, and every module consults the registry instead of a private table.

## REF-002 — Key model

Add `core/keys.py` with explicit key objects: `HmacKey(bytes)`, `PublicKey`, and `PrivateKey`, each wrapping the `cryptography` object and its family.

- Loaders: PEM public key, X.509 certificate (PEM/DER), PEM private key with an optional passphrase, JWK, and a selected JWKS entry. Every loader takes explicit bytes or a `Path` (no environment sniffing).
- `HmacKey` is bytes-first. The CLI decodes `--secret` according to a `--secret-encoding` option (UX-001), so secrets `crack` finds in hex or base64 work in `sign`/`verify`.
- The verifier derives the permitted algorithm family from the key, not from the token header (`core/CLAUDE.md`, algorithm-confusion invariant). An RSA key can never verify an `HS*` token, by construction instead of by flag checks.
- Keep `crypto.sign`, `verify_signature`, `sign_asymmetric`, and `verify_asymmetric` as thin compatible wrappers.

Acceptance: the existing crypto tests pass unchanged through the wrappers. New tests cover each loader's malformed-input path and the key/algorithm family matrix.

## REF-003 — Typed error model

- Add a `JwtToolkitError` base in `core/errors.py`. Every core failure raises a frozen-dataclass subclass with a stable `code`, `headline`, and `details`.
- Proposed new codes (add only, never rename): `unsupported_algorithm`, `key_parse_failed`, `key_algorithm_mismatch`, `key_passphrase_required`, `jwks_fetch_failed`, `jwks_invalid`, `jwks_no_matching_key`, `jwks_ambiguous`, `invalid_header`, `invalid_claims`, `wordlist_unreadable`, `forge_variant_unknown`, `forge_variant_needs_key`.
- Give `UnsupportedAlgorithmError` a `code`, and keep its current fields.
- Messages must never contain secrets, key bytes, or credential-bearing URLs. `jwks.py` currently interpolates `{url!r}` into errors, so sanitize userinfo and query strings.

Acceptance: core has no `raise ValueError` for domain failures, a test asserts every code is unique, and a leak test seeds a distinctive secret and a `user:pass@` URL and confirms neither appears in any error field.

## REF-004 — Core verification pipeline

Add `core/verifier.py`:

```python
def verify_token(
    token: str,
    *,
    key: VerificationKey | KeyResolver,
    expected: Expectations = Expectations(),
    now: float | None = None,
) -> VerificationResult: ...
```

- `VerificationResult` holds an ordered tuple of `Check(id, status, message)` items, where `status` is `pass`, `fail`, `warn`, or `not_evaluated`, plus an overall `valid`. This is the shared result model that POL-001 and BATCH-001 depend on.
- Move the temporal, issuer, and audience checks out of `commands/verify.py`. Use one injected `now` per call (POL-001 rule 7).
- `audit --secret/--public-key` calls the same pipeline. That removes `_check_signature` and gives `audit` JWKS support.
- Keep the `--json` shape (`valid`, `checks[].result/check/detail`) byte-compatible. Map the new `status` values onto the existing `PASS`/`FAIL`/`WARN` strings, and only add new optional fields.

Acceptance: the existing `tests/test_cmd_verify.py` passes unchanged. A new `tests/test_verifier.py` exercises every check without Click, using a frozen clock.

## REF-005 — Single CLI error boundary

- Subclass `click.Group` (or wrap `invoke`) to catch `JwtToolkitError` once. It renders the error panel, or the JSON error envelope when the command was invoked with `--json`, and maps the error to an exit code. This removes the 31 scattered `SystemExit` raises and the per-command `print_error` calls.
- **Exit-code decision:** the code and tests use `2` for input/operational errors, but `CLAUDE.md` says command failures exit `1` through `ClickException`. Changing the code would break scripts. Recommendation: keep current behavior (`0` accepted, `1` rejected or finding, `2` input/operational error, with `crack`'s inverted meaning preserved) and update `CLAUDE.md` to describe it.
- This is where BUG-005 (JSON on every failure path) gets fixed in general.

Acceptance: `grep -r SystemExit jwt_toolkit/commands` is empty, and every `--json` command emits a parseable envelope for every error code.

## REF-006 — Shared CLI options and input resolution

- Add `cli/options.py` with reusable decorators: `token_argument` (with the `-`/`@path` handling, a size limit from HARD-001, and stripping of a leading `Bearer ` prefix), `key_source_options` (secret / secret-file / public-key / jwks-url / jwks-file with declared mutual exclusion), and `output_options` (`--json` now, `--format` later).
- `resolve_token` stops calling `click.echo` + `SystemExit` itself and raises a typed error instead.

Acceptance: `sign`, `verify`, and `audit` declare key options through one decorator, and help text stays identical apart from intended additions.

## REF-007 — Crack engine in core

Add `core/cracker.py`:

- `iter_candidates(path, encoding)` follows the wordlist invariants (BUG-006).
- `crack(signing_input, signature, alg, candidates, *, workers, on_progress) -> CrackResult` is pure and has no Rich dependency. The command passes in a progress callback.
- Parallelism uses processes (`concurrent.futures.ProcessPoolExecutor` or `multiprocessing.Pool.imap_unordered`) over chunked batches, which fixes BUG-007. If `sys._is_gil_enabled()` is false (free-threaded build), threads are acceptable.
- Hot loop: decode the target signature to bytes once, use the one-shot `hmac.digest(key, msg, digest)`, and compare with `hmac.compare_digest` on bytes.
- Expose `--workers` and keep `--threads` as an alias. Add `--json` output with `schema_version`.

Acceptance: benchmark a generated 1M-line list at 1, 2, 4, and 8 workers and record the results in the PR, with a near-linear target up to physical cores. Results are deterministic: the first match in file order wins, whichever worker finds it. Ctrl-C leaves no orphan processes.

## REF-008 — Package hygiene

- Move `__version__` to `jwt_toolkit/__init__.py`, ship a `py.typed` marker, and define `__all__` for a documented public Python API.
- Remove the two `from __future__ import annotations` lines.
- Type `_ConsoleProxy` well enough to drop the `type: ignore[arg-type]` at the Rich `Progress` call sites.
- `pyfiglet` is a runtime dependency used only for the bare-invocation banner. Recommendation: replace it with a pre-rendered string constant and drop the dependency. Keeping it behind an optional `banner` extra is the alternative.

## Order and dependencies

REF-003 → REF-001 → REF-002 → REF-004 → REF-005/REF-006. REF-007 and REF-008 are independent and can land at any time. Each step is its own `refactor/` PR and must pass `make check`.

## Public-surface impact

None intended. Any change to `--json` fields, error codes, or the public algorithm dicts is a bug in the refactor unless it is called out and versioned per `CLAUDE.md`.
