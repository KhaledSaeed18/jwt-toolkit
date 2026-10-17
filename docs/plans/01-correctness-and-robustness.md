# 01 — Correctness and robustness

Status: proposed. Baseline and evidence definitions: [index](README.md).

## Objective

Malformed or unsupported tokens must produce deterministic failures, never unhandled exceptions or misleading successful verification. Prioritize this work for a candidate `v1.0.1` patch.

## BUG-001 — Require JSON objects for JWT headers and claims

Evidence: **Confirmed**, P0.

`core/decoder.py::decode_token` accepts the result of `json.loads` without checking its shape. CLI verification of an array header or array payload raises `AttributeError` and exits 1 instead of producing a structured input error. `commands/sign.py::_parse_json_arg` has the same missing shape validation by inspection; reproduce its individual paths before fixing them.

Implementation scope:

- Require a JSON object for both the protected header and JWT claims set.
- Return `TokenDecodeError` or an equivalent typed input error before accessing mapping methods.
- Apply consistent object validation to signing inputs.
- Keep generic JWS payloads outside the existing JWT command contract.

Acceptance and tests:

- Arrays, null, strings, booleans, and numbers are rejected as top-level header/payload values.
- Decode, audit, verify, forge, and crack produce controlled errors wherever they consume decoded tokens.
- `sign` rejects non-object payload/header arguments without a traceback.
- Existing valid-token fixtures still pass; JSON failures remain parseable and use documented exit codes.

Likely files: `core/decoder.py`, `core/errors.py`, `cli/decoding.py`, `commands/sign.py`, `tests/test_decoder.py`, and affected command tests.

## BUG-002 — Reject invalid NumericDate values

Evidence: **Confirmed** for `exp: NaN`, P0. Other boundary cases below are required investigations/tests.

Python's default JSON parser accepts non-standard `NaN`; `_check_temporal_claims` accepts floats and comparisons against NaN do not mark the token expired. A correctly signed test token with `exp: NaN` returns `valid: true` and exit 0.

Implementation scope:

- Reject non-standard JSON numeric constants (`NaN`, positive/negative infinity).
- Validate claim numbers as finite numeric values; explicitly exclude booleans despite Python's `bool` subclassing `int`.
- Cover values that overflow to infinity when parsing otherwise valid JSON exponent syntax.
- Preserve legitimate fractional NumericDates; do not require integers without a separate policy reason.
- Review `exp`, `nbf`, and `iat` consistently across audit and verify.
- Fix or confirm the exact expiry boundary: with zero leeway, a token is expired when `now >= exp`.
- Keep a missing optional claim distinct from a present claim of the wrong type. Required claims are addressed by [policies](02-verification-policies.md).

Acceptance and tests:

- Invalid numeric values never produce a successful verification result.
- Freeze/inject time for exact expiry, not-before, issued-at, and leeway tests.
- Test booleans, strings, null, non-finite values, large exponents, and fractional seconds.
- Specify whether malformed input exits 2 or invalid claims exit 1; preserve the existing distinction where possible.

Likely files: `core/decoder.py`, `commands/verify.py::_check_temporal_claims`, temporal helpers in `core/auditor.py`, and decoder/auditor/verify tests.

Reference: [RFC 7519 NumericDate and registered claims](https://www.rfc-editor.org/rfc/rfc7519.html).

## BUG-003 — Enforce critical-header semantics during verification

Evidence: **Confirmed**, P0.

A correctly signed HS256 token with `crit: ["custom"]` and `custom: true` passes verification although the implementation does not support that extension. Audit findings do not substitute for verifier enforcement.

Implementation scope:

- Validate `crit` type, entries, uniqueness, non-emptiness, and references to present headers.
- Reject extensions not explicitly implemented by the verifier.
- Review `b64` handling and reject unsupported unencoded-payload semantics; do not accidentally accept them through ordinary JWT decoding.
- Do not provide an option that merely ignores unknown critical extensions.

Acceptance and tests:

- Reproduced unknown-extension token no longer passes.
- Add tests for invalid lists, missing referenced headers, duplicate entries, and unsupported `b64` behavior.
- Ordinary tokens without critical extensions retain their existing behavior.
- Audit may explain unsupported input, but must not describe it as verified.

Likely files: `commands/verify.py`, `cli/algorithms.py`, a shared header-validation helper, `tests/test_cmd_verify.py`.

Reference: [RFC 7515 section 4.1.11 and Appendix E](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11).

## BUG-004 — Respect case-sensitive algorithm identifiers

Evidence: **Confirmed**, P0.

`cli/algorithms.py` uppercases token-provided `alg`, so a token carrying `hs256` is accepted as HS256. Related crypto and JWK paths also normalize names by inspection.

Implementation scope:

- Require the untrusted token `alg` to be a string with an exact supported identifier.
- Audit all token/JWK algorithm comparisons for silent normalization.
- Separate convenient user input handling from wire-format validation: accepting `sign --alg hs256` can remain convenient if the emitted header is canonical `HS256`.
- Investigate custom signing headers with missing/conflicting `alg`; ensure emitted tokens declare the algorithm actually used.

Acceptance and tests:

- Lowercase/mixed-case wire identifiers and non-string `alg` values fail predictably.
- Canonical identifiers continue to work for all supported families.
- JWK metadata mismatch tests cover case and type.
- Signing tests check emitted header consistency, including custom headers.

Reference: [RFC 7515 section 4.1.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1).

## BUG-005 — Honor JSON output on failure paths

Evidence: **Confirmed** for missing verification key, P0. Other paths are inspected candidates.

`verify ... --json` without a required key prints a human-readable error rather than JSON. Unsupported-algorithm rendering, key/network errors, token-file errors, and Click parsing errors require a complete inventory.

Implementation scope:

- Define one error envelope with schema version, stable error code, safe message, and optional details.
- Route parse, algorithm, key selection, filesystem, and network errors through that contract.
- Determine how format selection is recognized for Click usage errors before callback execution.
- Preserve useful human output without banners, progress, or ANSI escapes contaminating machine output.
- Sanitize exception messages so secrets and credential-bearing URLs are not echoed.

Acceptance and tests:

- Every supported `--json` command returns valid JSON on both success and failure.
- Missing/unreadable files, malformed keys, unsupported algorithms, conflicting options, and network failures have explicit tests.
- stdout is the machine result; stderr is reserved for documented diagnostics.
- Assert no unhandled exception, not only a nonzero exit status.

Depends on error-contract decisions in [reports](03-reports-and-automation.md); implement the minimal contract here before batch support.

## HARD-001 — Bound and strictly validate input

Evidence: **Proposed**, P1. These are hardening investigations, not all confirmed defects.

- Set documented limits for token bytes, individual segments, and JSON nesting. Enforce limits while reading stdin/files, not only after loading everything.
- Validate URL-safe base64 characters and padding according to the JWT/JWS contract.
- Review the current removal of all whitespace: verification must not silently repair arbitrary embedded whitespace. Decide whether inspection can offer a clearly labeled tolerant mode.
- Require UTF-8 explicitly; a JSON bytes parser can accept encodings beyond UTF-8.
- Choose a duplicate-member policy. Recommend rejection for predictable cross-parser behavior, while noting RFC 7515/7519 also allow a parser that selects the last duplicate member.
- Normalize parser recursion/size failures into controlled input errors.

Acceptance: boundary tests just below/at/above limits; invalid encoding, deep nesting, duplicate names, and malformed signatures never crash or hang. Document any compatibility change before release. Preserve invalid-token inspection only through explicit, unverified output.

## Additional defects found in the 2026-10-17 review

Same baseline commit. BUG-001 through BUG-005 were re-run and still reproduce. The items below are new.

### BUG-006 — `crack` mangles wordlist candidates

Evidence: **Confirmed**, P0.

`commands/crack.py::_iter_candidates` calls `line.strip()`, skips every line beginning with `#`, and opens the file with `errors="ignore"`. A token signed with ` leading-space`, `#hashsecret`, or `trailing<TAB>` is reported as "Secret not found in this wordlist" even when that exact line is present. That green "Wordlist Check Passed" verdict is a false negative. It also violates the wordlist invariants in `core/CLAUDE.md`, which require stripping only `\r\n`/`\n`, decoding with `errors="replace"`, and stripping a leading BOM.

The `seen` dedup set also grows with every unique candidate, so memory scales with the wordlist. That contradicts the streaming requirement for multi-gigabyte lists. The file is also read twice: once by `_count_raw_lines` and once to crack.

Scope:

- Strip only the line terminator and a first-line BOM. Keep blank-line skipping.
- Remove comment skipping. The bundled list contains no `#` lines, and common external lists treat `#` as data. If comment support is wanted, make it an explicit opt-in flag.
- Bound or remove cross-line dedup. Dedup within the expansions of a single line (`--encoding all`) is enough.
- Replace the full pre-count with a size-based estimate, or count lazily.

Acceptance: secrets with leading/trailing spaces or tabs, a leading `#`, non-UTF-8 bytes, CRLF endings, and a BOM are all found. A large generated list cracks with flat memory use.

### BUG-007 — `crack --threads` gives no speedup

Evidence: **Confirmed**, P1.

On a 400,000-candidate list on a 10-core macOS machine (CPython 3.13, GIL enabled), `--threads 1` took 1.49 s and `--threads 8` took 1.66 s. `hashlib` releases the GIL only for large inputs, and JWT signing inputs are small, so the worker threads serialize. The flag implies parallelism that doesn't happen.

The fix belongs in the crack-engine refactor ([REF-007](08-architecture-refactor.md#ref-007--crack-engine-in-core)). Keep `--threads` as a compatible alias if the option is renamed.

### BUG-008 — Some `forge` variants cannot detect the vulnerability they name

Evidence: **Inspected** (deterministic by construction), P0.

`jwk_embedded`, `jku_attacker`, `kid_path_traversal`, and `kid_sql_injection` change the header but reuse the original signature, which was computed over the original header. A verifier that really has the named flaw would still reject them:

- one that trusts an embedded `jwk` verifies against the embedded key;
- one that fetches `jku` verifies against the fetched keys;
- one that reads a key file named by `kid` reads that file.

None of these keys produced the original signature. The variant is rejected, and the operator wrongly concludes the verifier is safe. `jwk_embedded` even embeds an `oct` key, but the signature was not made with it.

Scope:

- Change the variant descriptions now so they state these variants test header tolerance only, and that a rejection does not prove the verifier is free of the named flaw.
- Reworking the variants themselves needs a separate, scoped design review under the project's defensive-use policy. It is not part of this patch.

Acceptance: `forge` output and `--json` descriptions no longer claim these variants detect the named flaw, and the variant names and JSON shape are unchanged.

### BUG-009 — `download-wordlists` carries a dead unverified-TLS fallback and a `main`-pinned URL

Evidence: **Confirmed**, P1. Corrected after reproduction: the initial inspection overstated the impact.

`commands/download_wordlists.py::_open_url` catches `ssl.SSLCertVerificationError` and retries with `ssl._create_unverified_context()`. Against a local self-signed HTTPS server, `urlopen` raises `URLError` wrapping the certificate error, so that branch never runs and the download already fails closed with a raw "Network error". The fallback is still a latent downgrade that a refactor could activate.

Separately, the default URL targets `main` while the SHA-256 pin ships with each release. Any wordlist update on `main` would make integrity checks fail for every already-released version.

Scope:

- Remove the unverified fallback, and report certificate failures with guidance (`SSL_CERT_FILE`, proxy CA bundles).
- Fetch from the version tag (`.../v{version}/wordlists/...`), or ship the list in the wheel, so the pin and the content always match.
- Follow-ons: an optional `--sha256` for custom sources, and a bounded response size.

Acceptance: an untrusted certificate causes a hard failure and leaves no file behind, and updating the list on `main` does not break released versions.

## Reproduction script for the confirmed baseline observations

Run from the repository root with a synced development environment. This uses only throwaway local data and does not contact a server. On the baseline, the first two cases raise `AttributeError`; the next three return `valid: true`; the missing-key case is not JSON. Once fixed, these observations should change and be captured as regression tests.

```python
import json
from click.testing import CliRunner
from jwt_toolkit.cli import cli
from jwt_toolkit.core.crypto import sign
from jwt_toolkit.core.encoding import base64url_encode


def token(header, payload):
    h = base64url_encode(json.dumps(header).encode())
    p = base64url_encode(json.dumps(payload).encode())
    signature = sign(h, p, "local-test-secret")
    return f"{h}.{p}.{signature}"


cases = [
    ("non-object header", [], {}),
    ("non-object payload", {"alg": "HS256"}, []),
    ("NaN expiry", {"alg": "HS256"}, {"exp": float("nan")}),
    (
        "unknown critical header",
        {"alg": "HS256", "crit": ["custom"], "custom": True},
        {"exp": 4102444800},
    ),
    ("lowercase algorithm", {"alg": "hs256"}, {"exp": 4102444800}),
]
for label, header, payload in cases:
    result = CliRunner().invoke(
        cli,
        [
            "--quiet",
            "verify",
            token(header, payload),
            "--secret",
            "local-test-secret",
            "--json",
        ],
    )
    print(label, result.exit_code, type(result.exception).__name__, result.output)

result = CliRunner().invoke(
    cli,
    [
        "--quiet",
        "verify",
        token({"alg": "HS256"}, {}),
        "--json",
    ],
)
print("missing key", result.exit_code, result.output)
```

Do not publicly characterize these observations as a CVE or authentication bypass without a separate impact assessment. Follow the repository's private reporting policy for security-sensitive details.
