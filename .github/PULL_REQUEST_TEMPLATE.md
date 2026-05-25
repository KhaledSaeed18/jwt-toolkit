<!--
Thanks for contributing to jwt-toolkit. Please fill in the sections below.
Keep the title concise and in the conventional-commits style, for example:
  feat(audit): flag jku header pointing to non-https URL
  fix(crack): handle wordlists with trailing whitespace
  docs(readme): add JWKS verification example
-->

## Summary

<!-- One or two sentences describing what this PR changes and why. -->

## Type of change

<!-- Check all that apply. -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing CLI surface or behavior)
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] Tests only
- [ ] Build, CI, or tooling

## Related issues

<!-- Link issues this PR closes or relates to. Use "Closes #123" to auto-close. -->

Closes #

## Changes

<!-- A short bulleted list of what changed. Focus on user-facing impact. -->

-
-

## How to test

<!--
Concrete commands a reviewer can run to verify this PR.
Include sample tokens, expected output, or screenshots for CLI changes.
-->

```bash
make check
# or specific commands:
jwt-toolkit audit <token>
```

## Checklist

- [ ] I read [CONTRIBUTING.md](../CONTRIBUTING.md) and followed the branch and commit conventions.
- [ ] `make check` passes locally (lint, typecheck, tests, security scan, dependency audit).
- [ ] I added or updated tests for the change.
- [ ] I updated the README, command help text, or other docs if user-facing behavior changed.
- [ ] I did not introduce new runtime dependencies, or I justified each new one in the PR description.
- [ ] This PR does not contain real secrets, private keys, or production tokens.

## Additional notes

<!-- Optional. Anything the reviewer should know: tradeoffs, follow-ups, screenshots. -->
