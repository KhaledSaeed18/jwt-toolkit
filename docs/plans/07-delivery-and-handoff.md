# 07 — Delivery sequence and contributor handoff

Status: proposal, partly delivered. Baseline: [index](README.md). Delivered items are tracked in the [index](README.md#implementation-status).

## Candidate releases

| Milestone | Intended content | Completion evidence |
| --- | --- | --- |
| v1.0.1 | BUG-001–006, BUG-008 (relabel), BUG-009; expiry-boundary investigation; RELEASE-001 and DOC-001 | Reproduced failures have regression tests; errors are predictable; publication requires checks on the release commit |
| v1.1.0 | REF-001–008 (including BUG-007); POL-001; REPORT-001/002; UX-001/002; foundational QA work | A checked-in policy accepts/rejects synthetic fixtures predictably; IDs and output contracts are documented |
| v1.2.0 | REPORT-003; BATCH-001; CI-REPORT-001 JUnit; JWKS-001–004 | Bounded batch verification, redacted exports, offline/local-server tests for fetching and rotation |
| v1.3.0 | UX-003–005; OIDC-001; optional SARIF after feasibility review | Useful fixture/diff workflows and issuer discovery without weakening trust boundaries |

These are scope suggestions, not deadlines. Move independently valuable hardening earlier when ready. If a change breaks documented public behavior beyond rejecting invalid input, review versioning and migration before assigning a release number. Do not defer a confirmed correctness fix merely to bundle it with features.

## Suggested pull-request order

1. Parser shape/numeric validation (BUG-001/002) with focused reproductions.
2. Header/algorithm enforcement (BUG-003/004) and shared validation tests.
3. Consistent error envelope (BUG-005), including file/key/network errors.
4. Release gate and documentation alignment (RELEASE-001/DOC-001).
5. `crack` wordlist handling (BUG-006), download TLS fallback and URL pin (BUG-009), and `forge` description relabel (BUG-008), each independently reviewable.
6. Behavior-preserving refactor steps from [08](08-architecture-refactor.md), in its stated order, before the policy and reporting work that depends on a core verifier.
7. Input-boundary hardening (HARD-001) with explicit compatibility decisions.
8. Reporting primitives and rule catalogue (REPORT-001/002).
9. Policy parsing/evaluation (POL-001), then CLI integration.
10. Secret input/raw output (UX-001/002), independently reviewable.
11. Harden JWKS transport/selection (JWKS-001/002), then inspection/cache (JWKS-003/004).
12. Redacted reports (REPORT-003), streaming batch (BATCH-001), then CI exporters.
13. Signing conveniences, timestamp views, and token diff (UX-003–005).
14. Trusted issuer discovery (OIDC-001), with separate protocol review.

QA-001–004 should accompany the affected work rather than wait until all features are complete. Work may be reordered if dependencies and acceptance evidence remain explicit. These are possible PR boundaries, not a requirement to combine unrelated fixes.

## Dependency map

| Work | Depends on |
| --- | --- |
| Policy verification | Parser/header fixes, typed errors, shared result model |
| Stable CI reports | Finding IDs, documented schemas and exit behavior |
| Redacted reports | A complete inventory of outputs and error details |
| Batch processing | Shared evaluator, reporting contract, bounded input, safe JWKS reuse |
| JWKS cache/rotation | Hardened fetching and key validation |
| Token diff with verification | Parser fixes, redaction, policy/verification result reuse |
| Issuer discovery | Trusted-source configuration, hardened JWKS fetch, issuer comparison rules |
| Safe releases | Checks on exact release commit, validated artifacts, tag/version agreement |

## Design decisions to record before coding

Each implementing PR should record its relevant decisions in the owning plan or a linked design note:

- Exact CLI spelling and conflicts with existing positional arguments/options.
- JSON schema evolution and compatibility for existing consumers.
- Exit-code treatment of malformed records, failed verification, operational failures, and mixed batches.
- Policy precedence, required-claim semantics, lifetime versus age, and clock skew.
- Parser size/depth limits, duplicate-member policy, whitespace handling, and UTF-8 enforcement.
- Network timeout/redirect/size bounds, local HTTP opt-in, cache freshness, and refresh cooldown.
- Redaction defaults and handling of custom/nested claims, URLs, and exception messages.
- Secret encoding/newline semantics and stdin ownership.
- Support matrix, independent test implementation, and release-ref restrictions.

Open decisions are not permission requests by themselves. Resolve routine choices using the authorized implementation scope and current repository conventions. Ask the user when product intent or compatibility requirements cannot reasonably be inferred.

## Pickup checklist for a developer or agent

1. Confirm the user has authorized the selected implementation work; these plans alone are not authorization.
2. Read the selected plan, the index, applicable repository instructions, and current contribution guidance.
3. Inspect the latest repository state and any existing work. Do not assume the baseline is still current.
4. Reproduce confirmed bugs against the current version; label already-fixed items rather than duplicating work.
5. For inspected/proposed items, establish behavior and choose a bounded scope before editing.
6. Preserve unrelated local changes and follow branch/worktree conventions.
7. Implement the smallest coherent change, including meaningful regression tests and documentation.
8. Run targeted checks and the relevant repository quality gates; record actual commands/results.
9. Review compatibility, output leakage, and relevant standards against primary sources.
10. Update the plan status and link implementation evidence when work is complete. Follow the user's authorization for pushing, PRs, merging, and publishing.

## Definition of done for a work item

- Every acceptance criterion in the owning plan is met or explicitly deferred with a reason.
- Tests demonstrate intended behavior and at least the relevant failure cases.
- Existing supported behavior remains intact or a migration is documented.
- Help/examples and machine-output contracts match the implementation.
- No real tokens, secrets, or private keys are added to fixtures, logs, or reports.
- Required checks pass on the implementing commit.
- Any claim of standards compliance or security protection is supported by a concrete check.
- The item's evidence/status is updated with commit/PR references and remaining limitations.

## Progress record template

Append a record to the owning plan when work is actually performed:

```text
Work item:
Status: proposed | in progress | implemented | deferred
Implementation commit/PR:
Behavior and compatibility decisions:
Validation commands/results:
Remaining limitations:
Documentation updated:
```

Do not mark an item implemented because a design exists or because a PR was opened. Keep tests, merge state, and release state distinct.

## Explicitly deferred expansions

A GUI, hosted token service, generic remote verifier attack runner, JWE implementation, additional algorithm families, and a public stable Python SDK require their own scoped proposals. They are not included in the candidate releases above. Shared internal modules may make later work easier, but should not accidentally promise an externally stable API.
