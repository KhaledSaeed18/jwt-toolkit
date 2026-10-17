# 04 — JWKS and issuer discovery

Status: proposed, P1/P2. Baseline: [index](README.md).

## Existing behavior and evidence

By source inspection, `core/jwks.py` accepts HTTPS, HTTP, and file URLs; uses a 10-second timeout; reads the entire response without a size bound; and relies on urllib's redirect behavior. Key selection requires an exact `kid` match or an unambiguous single-key set. It checks key type, algorithm metadata, and EC curve, but not JWK `use` or `key_ops`.

URLs are currently supplied by the CLI user. This review did not establish an attacker-controlled URL exploit. Preserve that trust boundary: a token's `jku`, `x5u`, or `iss` must not silently authorize a network request.

## JWKS-001 — Explicit sources and bounded fetching

Scope:

- Add `--jwks-file` for offline documents and retain a reviewed migration path for existing `file://` usage.
- Default remote retrieval to HTTPS; provide an explicit, clearly documented local-development HTTP override.
- Separate reading, parsing, selection, and materialization for independent testing.
- Enforce a documented response-byte limit while streaming and a bounded redirect count.
- Validate scheme and destination on every redirect, not only the initial URL. Reject HTTPS-to-HTTP downgrade by default.
- Define connection/read timeout behavior and bounded retry rules. Do not retry indefinitely.
- Normalize invalid encoding, invalid JSON, malformed `keys`, non-object entries, and I/O errors into safe errors.
- Reject credential-bearing URLs or sanitize them everywhere they can appear in output.

Open decision: whether to offer optional host/network restrictions for automated use. Private identity providers are legitimate; do not globally prohibit private networks without a documented use case and explicit override design.

Acceptance/tests: offline tests and a local HTTP test server cover redirects, downgrade, oversized bodies, timeout, malformed documents, and non-object keys. Tests must not depend on a public identity provider. Invalid sources/configuration never cause unintended fetches.

## JWKS-002 — Key intent and parameter validation

Scope:

- When present, require `use` to permit signatures and `key_ops` to permit verification; validate their types and consistency.
- Enforce exact algorithm metadata (BUG-004), key-type compatibility, and EC curve compatibility.
- Preserve refusal to guess among ambiguous matching keys.
- Validate numeric/key fields with controlled errors, including a malformed single-key set without a `kid`.
- Surface key sizes and invalid/undersized RSA parameters. Decide whether size requirements are protocol enforcement or configurable policy, with standards references and migration notes.

Acceptance/tests: wrong use/operations, duplicate IDs, missing ID, algorithm mismatch, invalid curve/coordinates, missing parameters, malformed key entries, and valid metadata-absent keys have explicit cases. A correctly formed key is not accepted for a use its metadata prohibits.

## JWKS-003 — Inspection command

Proposed interface:

```bash
jwt-toolkit jwks inspect --file public-jwks.json --json
```

Display key IDs, key types, declared algorithms, curves, key sizes, use/operations, and ambiguity/configuration findings. Mark missing metadata as unspecified rather than guessing. Public-key inspection must not print private JWK parameters if a user supplies a mixed/private document; flag their presence without exposing values.

Acceptance: deterministic output; shared validation with verify; malformed entries represented clearly; redacted output tests. Do not change verification's selection rules merely to produce an inspection table.

## JWKS-004 — Cache and rotation for batches

Scope:

- Start with an in-memory cache scoped to one invocation; persistent storage is a separate decision.
- Key cache entries by trusted source/configuration; use bounded lifetime and size.
- On an unknown `kid`, allow at most a bounded refresh, with cooldown/negative caching to prevent a request per bad token.
- Specify behavior on fetch failure, expired entries, removed keys, and no-cache mode. Do not silently use stale keys forever.
- Bound concurrent refreshes if concurrency is later introduced.

Acceptance: repeated valid records share a fetch; a newly rotated key is discovered within the refresh policy; adversarial unknown IDs cannot produce unbounded refresh traffic; stale/error behavior is deterministic under a fake clock.

## OIDC-001 — Discovery from an explicitly trusted issuer

Follow-on scope, after JWKS-001/002 and policy foundations:

- Accept an issuer supplied by CLI/configuration, not discovered implicitly from untrusted token claims.
- Retrieve the standards-defined discovery document and require the returned issuer to match the expected issuer exactly.
- Resolve `jwks_uri` under the same fetching rules as direct JWKS URLs.
- Validate conflicting key-source options and preserve offline verification.
- Keep discovery distinct from full OIDC ID-token validation. Nonce, authorized-party, and flow-specific checks require a separate explicit profile.

Acceptance: issuer mismatch, malicious redirect, malformed metadata, absent JWKS URI, and unavailable discovery endpoint fail predictably. Document allowed cross-host JWKS behavior; legitimate providers may host keys on a different domain.

## Dependencies and references

Likely files: `core/jwks.py`, `commands/verify.py`, `tests/test_jwks.py`, and future keyset CLI tests. Integrate reporting contracts from [03](03-reports-and-automation.md).

Before implementation, consult the current primary specifications:

- [RFC 7517 — JWK, including use/key_ops](https://www.rfc-editor.org/rfc/rfc7517.html)
- [RFC 7518 — algorithms and key parameters](https://www.rfc-editor.org/rfc/rfc7518.html)
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

These are implementation references; the roadmap does not claim discovery support exists today.
