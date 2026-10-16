# 02 — Verification policies

Status: proposed, P1; candidate `v1.1.0`. Baseline: [index](README.md).

## POL-001 — Reusable application acceptance rules

### Problem and value

Signature verification alone does not establish that a token belongs to the expected issuer, audience, lifetime, or token purpose. The CLI currently offers issuer, audience, and leeway options but no caller-controlled algorithm allowlist or complete reusable policy.

A policy file should let a team put its JWT contract in version control and reuse it locally and in CI.

### Proposed interface

```bash
jwt-toolkit verify @token.txt \
  --public-key public.pem \
  --policy jwt-policy.toml \
  --json
```

Proposed TOML (not currently supported):

```toml
schema_version = 1
allowed_algorithms = ["RS256"]
issuer = "https://auth.example.com"
audience = "orders-api"
required_claims = ["exp", "iat", "sub"]
max_lifetime_seconds = 900
clock_skew_seconds = 30
```

### Scope

- Parse and validate a versioned TOML policy with actionable errors for unknown fields and wrong types.
- Add an algorithm allowlist usable without a file, with a final CLI spelling chosen during implementation.
- Validate issuer, audience, required claims, maximum lifetime, and clock skew.
- Offer expected token type and maximum token age as explicit follow-on fields once their semantics are specified.
- Keep keys/secrets outside policy files; do not make policies credential stores.
- Use a shared verification result independent of Click/Rich for later batch reuse.

### Rules to settle before implementation

1. **Precedence:** recommend rejecting conflicting CLI and file settings rather than silently weakening a policy. Allow identical settings and explicit documented overrides only if needed.
2. **Lifetime:** recommend `exp - iat`, requiring valid values for both claims when this rule is enabled. Maximum age is a separate rule, evaluated against the current time.
3. **Required:** distinguish a missing key from null, wrong type, or empty value. Standard claims need their own type checks; custom claims require a documented presence rule.
4. **Audience:** define expected-audience lists as any-match or all-match explicitly. Start with a single expected audience to avoid ambiguity.
5. **Clock skew:** specify its application to each temporal check and preserve strict lifetime limits independently of skew.
6. **Default behavior:** introduce policy enforcement additively. Do not silently turn every optional JWT claim into a required claim for existing invocations.
7. **Time:** inject one reference time per verification operation to avoid contradictory checks at boundaries.

### Result semantics

Expose signature status, claim status, and policy status separately. Overall success requires all applicable mandatory checks to pass. A valid signature does not excuse an invalid policy result. Use an explicit not-evaluated state where necessary; never equate an unperformed check with a pass.

### Acceptance criteria

- A correctly signed token using a disallowed algorithm fails before verification dispatch.
- Wrong issuer/audience, missing required claims, excessive lifetime, and invalid policy configuration produce distinct stable results.
- No network request occurs for invalid policy configuration.
- Policy results are deterministic under a fixed clock.
- Single-token and future batch verification use the same rule evaluator.
- Existing behavior without a policy remains compatible except for documented correctness fixes.

### Tests

Table-driven positive/negative cases for each rule; invalid configuration types and unknown fields; conflicting options; fractional timestamps and leeway boundaries; all supported algorithm families; wrong-key and wrong-policy cases distinguished; JSON output schema tests.

### Dependencies and likely files

Complete BUG-001 through BUG-005 first. Coordinate output shape with [reports](03-reports-and-automation.md). Likely changes: `commands/verify.py`, `cli/algorithms.py`, new `core/policy.py` and shared verification module, plus policy/CLI tests.

### Non-goals

No arbitrary Python expressions, remote policy downloads, application authorization engine, or claim that this tool implements a complete OAuth/OIDC login flow.

Reference: [RFC 8725 algorithm verification and application-specific rules](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1).
