# 03 — Reports and automation

Status: proposed, P1/P2; candidate `v1.1.0` foundations and `v1.2.0` batch/reporting. Baseline: [index](README.md).

## REPORT-001 — Stable findings and output contracts

Current state: audit findings have severity, field, message, and recommendation, but no stable rule ID. Some JSON errors are inconsistent (BUG-005). Existing JSON schema version is `0.1`; inventory actual consumers and payloads before changing it.

Scope:

- Give every finding a stable ID, e.g. `JWT_MISSING_EXP`, independent of wording.
- Publish a rule catalogue with meaning, evidence type, default severity, remediation, and relevant references.
- Define a result envelope and error envelope with schema versions.
- Keep human rendering separate from result creation.
- Preserve existing `--json` behavior where possible; use versioning/migration notes for breaking schema changes.
- Add `audit --fail-on warning|critical` (final spelling to be decided). Define its relationship to existing `--strict`; conflicting inputs should not be silently accepted.
- Document per-command exit semantics. Verify convention: 0 accepted, 1 rejected, 2 input/configuration/operational error. Do not blindly impose verify semantics on `crack`, which currently uses exit 1 when it finds a weak secret.

Acceptance: tests assert IDs, schema, and exit behavior rather than full prose; all machine output is parseable without banner/color stripping; no raw tracebacks for expected failures.

## REPORT-002 — Separate observations from security conclusions

Evidence: **Inspected** improvement opportunity. The auditor warns for all HMAC algorithms and assigns letter grades from warning counts. A static token cannot reveal whether an unseen HMAC secret has sufficient entropy, or whether an application's verifier is vulnerable to a header pattern.

Scope:

- Mark static observations, verified findings, and policy violations distinctly.
- Make the report explicit when no signature verification occurred.
- Explain limits of letter grades; consider retaining them for compatibility while making findings primary.
- Describe HMAC strength as dependent on secret generation and handling. Do not infer weakness solely from HS256.
- Keep CVE references as educational context, not proof that the audited application has that CVE.

Acceptance: well-configured HMAC use is not presented as confirmed weak-key evidence; unverified tokens never receive a misleading verified-safe verdict; references and severities have catalogue tests/review.

## REPORT-003 — Redacted, shareable reports

Scope:

- Add an explicit redacted output mode for human and JSON reports.
- Omit raw compact tokens, signatures, secrets, and sensitive claim values.
- Define allowlisted metadata, field paths, and safe finding explanations; avoid leaking values through error detail strings.
- Decide how custom claims and nested values are treated. Recommended report mode: suppress values by default, with explicit opt-in reveal.
- Redaction of a report must not suggest that modifying a token preserves its original signature.

Acceptance: tests seed distinctive sensitive strings into nested claims, headers, key errors, and URL credentials, then assert absence from stdout/stderr and exported reports. Normal decode behavior must not change silently.

## BATCH-001 — Streaming verification and audit

Proposed interface (not implemented):

```bash
jwt-toolkit verify --input tokens.jsonl --policy jwt-policy.toml \
  --public-key public.pem --format jsonl
```

Example input record:

```json
{"id":"login-fixture-1","token":"<synthetic-token>"}
```

Scope:

- Add mutually exclusive positional-token and batch-input modes.
- Process records incrementally with bounded record size and memory.
- Produce one result per record with its safe ID/line reference; do not echo the raw token.
- Continue after record-level malformed input, while failing immediately on invalid global configuration.
- Provide counts and an aggregate exit code. Recommended precedence: operational/input errors (2), rejected tokens (1), all accepted (0); document mixed outcomes.
- For JSONL stdout, either emit a typed final summary record or put the summary elsewhere. Pick one documented format before implementation.
- Share trusted key material and bounded JWKS cache across the batch.
- Document interrupt behavior and preserve completed output records.

Acceptance: mixed valid/invalid/malformed records yield stable per-record results; invalid config causes no partial processing; a large stream does not accumulate all tokens; repeated remote-key use does not trigger a fetch for every token.

## CI-REPORT-001 — JUnit and eventual SARIF

Add JUnit first: one test case per supplied token or rule group, with useful failure messages and redacted metadata. Include an example CI workflow that generates synthetic tokens and checks a version-controlled policy.

Evaluate SARIF only after stable rule IDs and meaningful source/fixture locations exist. Do not fabricate source line locations for tokens supplied through stdin. Document platform capabilities before promising GitHub annotations or code-scanning features.

Acceptance: parse exported XML/JSON with independent parsers; validate escaping and schemas; confirm sensitive values are absent; demonstrate an intentionally failing synthetic CI fixture.

## Dependencies, tests, and likely files

- BUG-005 supplies consistent errors; POL-001 supplies shared policy evaluation.
- REPORT-001 precedes redaction, batch, and CI exporters.
- Hardened JWKS fetching is required before adding concurrent remote batch operations.
- Likely files: `core/auditor.py::Finding`, command renderers, `cli/decoding.py`, new reporting/export modules and focused tests.
- Keep default execution sequential until profiling justifies concurrency. No live production token collection or log crawling is included.
