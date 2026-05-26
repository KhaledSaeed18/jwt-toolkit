# Security Policy

`jwt-toolkit` is a defensive command-line tool for inspecting, verifying, auditing, and stress-testing JSON Web Tokens. Because it operates on credentials and signing material, we take vulnerability reports seriously and ask that they be handled through the channels below rather than in public issues.

## Supported versions

`jwt-toolkit` follows semantic versioning and is pre-1.0 (`0.x.y`). Only the latest published minor on PyPI receives security fixes.

| Version                | Supported                                  |
| ---------------------- | ------------------------------------------ |
| Latest `0.x.y` on PyPI | Yes — fixes ship in the next patch release |
| Older `0.x.y` lines    | No — please upgrade                        |

You can confirm the latest version with `pip index versions jwt-toolkit` or by visiting <https://pypi.org/project/jwt-toolkit/>.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

The preferred channel is **GitHub's private vulnerability reporting**:

1. Go to <https://github.com/KhaledSaeed18/jwt-toolkit/security/advisories/new>.
2. Fill in the form with a description, affected versions, and reproduction steps.
3. Submit. Only repository maintainers will see the report.

This keeps the disclosure private until a fix is available, lets us coordinate a CVE if appropriate, and gives you credit in the published advisory.

If GitHub private vulnerability reporting is not available to you for any reason, open a regular issue with a minimal placeholder title (e.g., "Requesting a private security contact") — do **not** include reproduction details — and a maintainer will follow up with a private channel.

## Hardening this project relies on

For transparency, the project ships through the following supply-chain controls; reports about weaknesses in any of these are welcome:

- **PyPI Trusted Publishing (OIDC)** from `KhaledSaeed18/jwt-toolkit`'s `publish.yml` workflow, gated by a manual approval on the `pypi` GitHub Environment. No long-lived PyPI tokens.
- **PEP 740 artifact attestations** on the wheel and sdist, signed via sigstore through the publish workflow.
- **`pip-audit`** runs in CI against `uv.lock` on every push and PR; releases are blocked on a clean audit.
- **`bandit`** runs in CI at medium severity; new findings block the gate.
- **Dependabot** opens grouped weekly PRs for runtime and CI dependency bumps.

If any of these stop working as described, that itself is a reportable issue.
