# 05 — Developer workflows

Status: proposed, P1/P2. Baseline: [index](README.md).

## UX-001 — Safer secret input

Value: avoid requiring an HMAC secret in command-line arguments, where it can appear in shell history or process inspection.

Scope:

- Add a secret-file option and an explicit hidden prompt to commands that accept HMAC secrets (`sign`, `verify`, and optional signature checking in `audit`).
- Keep the existing `--secret` option for compatibility, with safer examples in documentation.
- Enforce one secret source. Never prompt unexpectedly in a non-interactive process.
- Define file content semantics: literal text with a documented newline rule versus binary bytes. Do not call unrestricted `.strip()` on secret material.
- Consider explicit `--secret-encoding utf8|hex|base64` as a follow-on so binary keys have unambiguous handling. If added, share byte-level semantics across sign and verify.
- Resolve stdin conflicts when both token and secret sources would consume it.
- Support encrypted private-key passphrase prompts only as a separately scoped extension with the same no-echo rules.

Acceptance/tests:

- File and prompt inputs produce signatures identical to the existing equivalent text secret.
- Conflicting inputs fail with stable errors; a non-TTY invocation never hangs waiting for input.
- Secrets and passphrases never appear in validation errors or diagnostics.
- Cover newline handling, whitespace that is part of a key, unreadable files, prompt cancellation, and stdin ownership.

Likely files: `commands/sign.py`, `commands/verify.py`, `commands/audit.py`, new shared credential-input helper, corresponding tests.

## UX-002 — Raw secret generation

Current state: `generate-secret` renders a rich panel and metadata, so its stdout is inconvenient to consume directly.

Proposed interface:

```bash
jwt-toolkit generate-secret --bits 256 --encoding base64 --raw
```

Scope: emit exactly the encoded secret plus one newline, without a banner or styling. Keep the existing human presentation as default. Clarify that the current base64 output is URL-safe and whether it includes padding; do not silently change the encoding.

Acceptance: output round-trips to the requested number of random bytes; no metadata or ANSI escapes; existing validation still applies; raw output remains clean regardless of terminal settings.

Coordinate with UX-001 so file consumption and generated output have documented compatible semantics. Never promise strength from length alone for user-supplied secrets.

## UX-003 — Easier signing fixtures

Proposed interface:

```bash
jwt-toolkit sign --payload-file fixture.json \
  --private-key test-private.pem --alg RS256 --expires-in 15m
```

Scope:

- Add payload-file input, mutually exclusive with inline JSON, with optional stdin support if unambiguous.
- Add a duration option for fixture lifetime. Define whether it also sets `iat`; recommend setting both from one captured clock value when requested.
- Reject ambiguous conflicts with explicit `exp`/`iat` values unless an explicit override mechanism is designed.
- Validate units, positivity, overflow, JSON object shape, and custom-header algorithm consistency.
- Keep default signing behavior unchanged when conveniences are unused.

Acceptance: deterministic output claims with a fake clock, correct signatures across supported families, clear conflicts, no accidental mutation of source JSON, controlled filesystem errors.

Non-goals: credential issuance service, production key management, or automatic storage of generated tokens.

## UX-004 — Understandable timestamps

Scope:

- Show UTC absolute time and relative interpretation for `exp`, `nbf`, and `iat` in human output, alongside original numeric values.
- Clearly label missing, invalid, unverified, and policy-dependent information.
- Use one reference time per report; avoid local timezone ambiguity.
- Keep numeric values stable in JSON; any added display fields require schema documentation.

Acceptance: tests cover past/future/boundary timestamps, fractional values, out-of-range dates, and invalid types without crashing. Relative text must not imply a valid signature or successful authorization.

Likely files: decode/audit/verify renderers and a shared time-formatting helper.

## UX-005 — Compare two tokens

Proposed interface:

```bash
jwt-toolkit diff @before.jwt @after.jwt --redact --json
```

Scope:

- Report added, removed, and changed header/claim fields with stable nested paths.
- Highlight changes to issuer, audience, subject, roles, scopes, and lifetime without asserting authorization implications.
- Distinguish identical claims from different signatures/serialization.
- Treat arrays as ordered unless a documented field-specific view explicitly says otherwise; do not normalize away meaningful changes.
- Label both inputs unverified by default. If verification is requested, show separate results for each token.
- Redact sensitive values using REPORT-003 while preserving paths and change categories.

Acceptance: nested objects, arrays, added/removed claims, ordering-only JSON serialization changes, malformed input on either side, and redaction all have tests. Define two-input stdin handling and reject ambiguous usage. Do not rewrite or re-sign tokens.

Dependencies: parser fixes, reporting contracts, and redaction; optional verification integration follows POL-001. Likely additions: a pure core diff function, new Click command, registration/help updates, and focused tests.

## Documentation requirements for these features

For each implemented capability, update command help and add a copyable example using synthetic tokens and test keys. Existing token `-`/`@path` support should be documented more visibly, not rebuilt. Check that command descriptions reflect asymmetric signing as well as HMAC.
