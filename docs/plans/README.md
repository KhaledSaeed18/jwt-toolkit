# JWT Toolkit development plans

Status: proposed; no implementation work authorized by these documents.

Prepared: 2026-10-13. Evidence baseline: commit `62bc741a0cc60187eac6cccc83e44e5cee33e6a8` on `main`, package version `1.0.0`.

Revised: 2026-10-17. BUG-001 through BUG-005 re-verified on the same commit; BUG-006 through BUG-009 and the architecture refactor plan (08) added.

## Purpose

Make JWT Toolkit a dependable local and CI tool for inspecting tokens, verifying them against application requirements, and producing actionable security reports. Prioritize correctness and predictable behavior before expanding command coverage.

This directory records the findings and proposals from the October 13 review. It is a handoff for future developers and agents, not a claim that the proposed behavior exists. The user requested documentation only. Do not treat a future reader opening this directory as authorization to implement, publish, merge, or create issues.

## Reading order

| Plan | Work covered | Priority |
| --- | --- | --- |
| [01 — Correctness and robustness](01-correctness-and-robustness.md) | Confirmed parser, verifier, JSON-output, `crack`, `forge`, and download defects; additional hardening | P0/P1 |
| [02 — Verification policies](02-verification-policies.md) | Algorithm allowlists and reusable application acceptance rules | P1 |
| [03 — Reports and automation](03-reports-and-automation.md) | Stable findings, redaction, batch input, CI output | P1/P2 |
| [04 — JWKS and discovery](04-jwks-and-discovery.md) | Fetching boundaries, key metadata, inspection, rotation, issuer discovery | P1/P2 |
| [05 — Developer workflows](05-developer-workflows.md) | Secret inputs, raw output, signing fixtures, timestamps, token diff | P1/P2 |
| [06 — Quality and releases](06-quality-and-releases.md) | Interoperability, property tests, build validation, release gates, documentation | P0/P1 |
| [07 — Delivery and handoff](07-delivery-and-handoff.md) | Dependency order, candidate releases, shared decisions, completion checklist | Planning |
| [08 — Architecture refactor](08-architecture-refactor.md) | Algorithm registry, key model, typed errors, core verifier, CLI error boundary, crack engine | P1 |

P0 means resolve before the next release; it is a delivery priority, not a vulnerability severity or CVSS score. P1 means foundational work for the next feature release. P2 means follow-on work after foundations stabilize.

## Evidence labels

- **Confirmed:** reproduced locally with synthetic input, with observed results recorded in the relevant plan.
- **Inspected:** supported by source or configuration review but not demonstrated end to end.
- **Proposed:** a new capability or hardening measure, not an existing bug claim.
- **Investigate:** a question requiring reproduction or a design decision before changing behavior.

The review was targeted, not a comprehensive security audit. Malformed tokens were created with a known local test secret. The observed acceptance cases do not establish signature forgery or exploitation of another application.

## Current capabilities to preserve

The CLI already includes `decode`, `audit`, `verify`, `sign`, `forge`, `crack`, `generate-secret`, and `download-wordlists`. It supports HMAC, RSA, RSA-PSS, and ECDSA signing/verification; PEM and remote JWKS verification; issuer/audience checks; clock skew; static auditing; and JSON output on several commands.

Token input already supports a literal token, `-` for stdin, and `@path` for a file. `audit` already has `--strict` and `--required-claims`; this is not the same as enforcing a verification policy. Avoid implementing these existing capabilities again.

At the baseline, the local suite had 291 passing tests and approximately 87.42% coverage. These are historical results, not evidence that future changes pass.

## Scope boundaries

- Keep static audit heuristics distinct from verified facts and application policy failures.
- Keep trust configuration separate from untrusted token contents.
- Preserve documented CLI behavior unless a correctness fix or an explicitly reviewed migration requires a change.
- Examples in these plans are proposed interfaces. Resolve and document open decisions before treating them as contracts.
- Do not add a web service, GUI, general network attack runner, JWE implementation, or new algorithm family as part of this roadmap without a separate proposal.
- No release dates or effort estimates are committed. Candidate version numbers describe intended scope, subject to compatibility review.

## Repository orientation

- `jwt_toolkit/core/`: encoding, decoding, crypto, audit, and JWKS logic.
- `jwt_toolkit/commands/`: Click commands and presentation orchestration.
- `jwt_toolkit/cli/`: input resolution, errors, algorithm selection, and output utilities.
- `tests/`: existing unit and CLI integration tests.
- `.github/workflows/`: CI and publication.
- `pyproject.toml`: package metadata, tool configuration, and dependency groups.

Paths above are relative to the repository root. Each plan names likely files, but implementations should follow the repository state at the time work begins.
