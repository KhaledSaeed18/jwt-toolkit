# 06 — Quality, testing, and releases

Status: proposed. Baseline: [index](README.md).

## RELEASE-001 — Enforce validation before publishing

Evidence: **Inspected**, P0.

At the baseline, `.github/workflows/publish.yml` builds and runs strict Twine metadata checks, then publishes with `needs: build`. It does not itself require tests, lint, type checking, or security scans for the release commit. `SECURITY.md` says releases are blocked on a clean audit. Separate successful main-branch CI is not proof that every dispatched release ref passed validation.

Scope:

- Factor reusable validation or explicitly run the required checks against the exact release commit before publication.
- Make the publish job depend on successful validation and the validated artifacts.
- Verify the release tag agrees with package metadata; define permitted manual-dispatch refs.
- Retain Trusted Publishing and artifact attestations.
- Keep build and validation jobs read-only; restrict publishing permissions to the publication job.
- Review environment protections separately. The workflow names the `pypi` environment, but that alone does not prove manual approval is configured in GitHub settings.
- Use the committed lockfile reproducibly (`uv sync --locked` or an equivalent reviewed approach), and audit the intended runtime/development environment.

Acceptance/tests:

- Demonstrate with a safe test workflow or non-publishing path that a failed required check blocks publish.
- Reject mismatched tag/version and unauthorized manual-dispatch ref choices before upload.
- Verify the uploaded artifacts are the artifacts produced and validated for that commit.
- Do not publish a real PyPI version merely to test the gate.

## DOC-001 — Correct support and security documentation

Evidence: **Inspected**, P0.

`SECURITY.md` still says the project is pre-1.0 and supports the latest `0.x.y`, although the package/release is `1.0.0`. Its release-blocking statement is stronger than the workflow's explicit dependencies.

Scope:

- State the actual supported release line and upgrade policy.
- Align security-control claims with verified workflow/account configuration.
- Clarify static audit versus signature verification versus application acceptance.
- Review command summaries for stale descriptions, including signing support beyond HMAC.
- Add release notes distinguishing correctness changes, features, dependency maintenance, and compatibility changes.

Acceptance: every security guarantee has a corresponding implemented check or explicitly documented external configuration; support language matches the released version policy.

## QA-001 — Independent interoperability checks

Priority: P1.

The project intentionally implements JWS using cryptography rather than delegating to a JWT runtime library. Tests that only sign and verify with the same implementation can miss matching mistakes.

Scope:

- Add standards test vectors for supported algorithms and malformed-input cases.
- Cross-check supported operations with at least one independent maintained JOSE implementation used as a development dependency only.
- Test both directions: external signing/toolkit verification and toolkit signing/external verification.
- Cover HMAC, RSA, PSS, and ECDSA, including raw-versus-DER ECDSA encoding, curve restrictions, and PSS salt requirements.
- Resolve differing acceptance behavior against the relevant specification rather than treating the other library as unquestionable authority.

Acceptance: every supported family has cross-implementation coverage and meaningful negative cases; dependency/source versions are recorded; tests run offline after dependency installation; no external service or production key is needed.

## QA-002 — Property-based and adversarial-input tests

Priority: P1; start alongside correctness fixes.

Scope:

- Generate malformed segment structures, base64url inputs, JSON shapes, Unicode, numeric claims, and JWK shapes.
- Assert typed failures, bounded resource use, and stable result envelopes.
- Use a bounded input strategy so CI does not intentionally exhaust memory or time.
- Keep minimized regressions when a generator finds a failure.
- Inject clocks and randomness where behavior needs reproducibility.

Acceptance: parser/validator entry points never leak unexpected exceptions for the bounded corpus; failures include a reproducible example; deterministic security boundary tests remain readable alongside generative tests.

Candidate tool: Hypothesis, subject to a development-dependency review at implementation time. No runtime dependency is needed for test generation.

## QA-003 — Platform and Python coverage

Priority: P1.

Current CI tests Python 3.13 on Ubuntu, while metadata declares Python >=3.13 and OS independence.

Scope:

- Select an explicit matrix covering the minimum supported Python and current supported stable versions at implementation time.
- Add Windows and macOS smoke coverage for filesystem paths, stdin, encoding, CLI entry points, and packaging.
- Keep the full matrix proportionate: full suite on primary platforms and targeted smoke jobs where sufficient.
- Confirm terminal/banner behavior does not affect machine output across platforms.

Acceptance: supported interpreter/platform claims have representative passing checks; failures are not hidden with blanket allowed-failure settings; matrix versions are documented and maintained.

## QA-004 — Validate installed distributions

Priority: P1.

Scope:

- Build wheel and source distribution in CI; run strict metadata checks.
- Install the wheel into an isolated environment outside the repository so local imports cannot mask packaging defects.
- Exercise `--version`, `--help`, and a synthetic sign/verify round trip through the installed entry point.
- Confirm the source distribution can build a usable wheel.
- Inspect packaged contents for unintended local files or test secrets.

Acceptance: smoke commands use the installed package path, fail on absent files/entry points, and run without unpublished workspace state. Artifact tests do not write credentials or publish packages.

## Quality gates for implementation work

Use the repository's existing `make check` gate after implementation changes and run targeted tests while developing. Use build/Twine/install checks when changing packaging or release behavior. Passing coverage alone is not evidence of standards compliance; prioritize tests for security-sensitive branches and unexpected failures.

The docs-only creation of this roadmap does not require rerunning the application test suite.

## Likely files

`.github/workflows/ci.yml`, `.github/workflows/publish.yml`, `pyproject.toml`, `uv.lock`, `SECURITY.md`, command help/README, and new interoperability/property/package tests. Keep workflow fixes separable from product features so they can be reviewed and shipped independently.
