# Contributing to jwt-toolkit

Thank you for considering a contribution. This document explains the project layout, how to set up a development environment, and the conventions we follow for branches, commits, and pull requests. The aim is to keep the contributor experience predictable so that you can focus on the change itself.

If anything here is unclear, open a documentation issue using the [Documentation issue template](.github/ISSUE_TEMPLATE/documentation.yml).

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Project scope](#project-scope)
- [Repository layout](#repository-layout)
- [Development setup](#development-setup)
- [Common tasks](#common-tasks)
- [Branch naming](#branch-naming)
- [Commit messages](#commit-messages)
- [Pull request workflow](#pull-request-workflow)
- [Testing guidelines](#testing-guidelines)
- [Code style](#code-style)
- [Security policy](#security-policy)
- [Releasing](#releasing)

## Code of conduct

Be respectful, be patient, and assume good intent. Personal attacks, harassment, and discriminatory language are not acceptable in any project space, including issues, pull requests, discussions, and commit messages.

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Report unacceptable behavior to the contact listed there.

Accessibility barriers are bugs. [ACCESSIBILITY.md](ACCESSIBILITY.md) describes what the CLI aims for and how to report one; a change to human-readable output should keep every verdict in words and keep `NO_COLOR` free of escape codes.

## Project scope

`jwt-toolkit` is a defensive command-line tool for inspecting, verifying, auditing, and stress-testing JSON Web Tokens. Contributions that fit this scope are welcome:

- New audit rules with a clear security rationale, ideally referencing a CVE, RFC, or well-known attack pattern.
- Additional verification options (algorithms, key formats, JWKS behaviors).
- CLI ergonomics, better output, and machine-readable formats.
- Tests, documentation, and tooling improvements.

Out of scope:

- Features that primarily enable offensive use against systems the user does not own.
- Network probing, exfiltration, or any behavior that targets remote systems beyond fetching public JWKS documents.
- Heavy runtime dependencies. Each new dependency must be justified.

## Repository layout

```
jwt-toolkit/
├── jwt_toolkit/              # Source package
│   ├── __init__.py           # Package version
│   ├── cli/                  # CLI plumbing: banner, console, panels, decoding helpers
│   │   ├── __init__.py       # Click root group, global flags, command registration
│   │   ├── algorithms.py     # CLI-side algorithm validation
│   │   ├── banner.py         # Startup banner, help screen, and the COMMANDS/EXAMPLES lists
│   │   ├── banner_art.py     # Pre-rendered banner lettering
│   │   ├── console.py        # Result, error, and status consoles (quiet, no-color)
│   │   ├── credentials.py    # --secret / --secret-file handling
│   │   ├── decoding.py       # Token input (argument, @file, stdin, size limit)
│   │   ├── errors.py         # ToolkitCommand error boundary, JSON error document, schema version
│   │   ├── panels.py         # Reusable Rich panels for errors and results
│   │   └── wordlists.py      # Location of the bundled wordlist
│   ├── commands/             # One file per `jwt-toolkit <command>`
│   │   ├── audit.py
│   │   ├── crack.py
│   │   ├── decode.py
│   │   ├── diff.py
│   │   ├── download_wordlists.py
│   │   ├── forge.py
│   │   ├── generate_secret.py
│   │   ├── sign.py
│   │   └── verify.py
│   └── core/                 # Pure logic, no Click and no Rich
│       ├── algorithms.py     # The JWS algorithm registry and the public algorithm tables
│       ├── auditor.py        # Static audit rules, key-material checks, and grading
│       ├── claims.py         # Claim and critical-header checks used by verify
│       ├── cracker.py        # Batched, optionally parallel HMAC secret search
│       ├── crypto.py         # HMAC and asymmetric signing and verification
│       ├── decoder.py        # JWT splitting and strict decoding, with input limits
│       ├── diff.py           # Field-by-field token comparison
│       ├── encoding.py       # Canonical base64url and strict JSON (UTF-8, no duplicates, depth limit)
│       ├── errors.py         # Domain-specific exceptions with stable codes
│       ├── forge.py          # Defensive attack-shaped variant generation
│       ├── jwks.py           # JWKS fetching and key selection
│       ├── keys.py           # HmacKey, PublicKey, PrivateKey: the key decides the algorithm family
│       ├── lifetime.py       # --expires-in parsing
│       ├── timestamps.py     # Human-readable time claims
│       ├── verifier.py       # The one signature and claims pipeline for verify and audit
│       └── wordlist.py       # Streaming wordlist reader and candidate expansion
├── scripts/                  # Package smoke test and cliprobe runner (dev only, not shipped in the wheel)
├── tests/                    # Pytest suite mirroring the source layout
│   ├── conftest.py           # Shared fixtures (keys, tokens, tmp wordlists)
│   ├── helpers.py            # Test helpers
│   ├── test_cmd_*.py         # CLI-level tests (invoke commands via Click runner)
│   ├── test_interop.py       # RFC examples and PyJWT cross-checks
│   ├── test_properties.py    # Hypothesis property tests for hostile input
│   ├── test_*.py             # Core-level unit tests
│   └── vectors/              # RFC JWS examples, with their sources
├── wordlists/                # Bundled wordlist resources
├── assets/                   # README images and demo assets
├── .github/
│   ├── ISSUE_TEMPLATE/       # Issue forms (bug, feature, docs, accessibility)
│   ├── workflows/            # CI, release (release-please + PyPI) and PR-title workflows
│   ├── dependabot.yml        # Dependency update config
│   └── PULL_REQUEST_TEMPLATE.md
├── pyproject.toml            # Build, dependencies, ruff, mypy, pytest, bandit config
├── Makefile                  # Developer command shortcuts
├── uv.lock                   # Locked dependency tree (managed by uv)
├── CHANGELOG.md              # Written by release-please
├── ACCESSIBILITY.md          # Accessibility statement
├── CODE_OF_CONDUCT.md        # Contributor Covenant 2.1
├── SECURITY.md               # Supported versions and private vulnerability reporting
└── README.md
```

### Layering rules

The package is split into three layers and dependencies must flow downward:

```
commands  -->  cli (rendering)  -->  core (logic)
```

- `core/` must not import from `cli/` or `commands/`. It contains the pure JWT logic and is meant to be testable without any CLI plumbing.
- `cli/` may import from `core/` and provides Rich-based rendering helpers.
- `commands/` wires Click flags to `core/` operations and uses `cli/` to render results.

If you find yourself wanting `core/` to know about Rich, colors, or Click, stop and rethink. Pass plain data structures out of `core/` and let the command layer format them.

## Development setup

You need Python 3.13 or newer and [uv](https://docs.astral.sh/uv/). The Makefile assumes `uv` is on your PATH.

```bash
git clone https://github.com/KhaledSaeed18/jwt-toolkit.git
cd jwt-toolkit
make install
```

`make install` does two things:

1. Syncs the dev dependency group with `uv sync --group dev`.
2. Installs the pre-commit hook so style and lint run on every commit.

Verify the install:

```bash
uv run jwt-toolkit --version
make check
```

`make check` runs the full local CI gate: lint, type checking, tests, security scan, dependency audit, the GitHub Actions security lint, and the installed-package smoke test (`scripts/package_check.py`: builds the wheel and sdist, checks what they contain, installs each into a fresh venv outside the repository, and runs the `jwt-toolkit` entry point). Run this before opening a pull request.

## Common tasks

| Task                                 | Command            |
| ------------------------------------ | ------------------ |
| Show available make targets          | `make` or `make help` |
| Install dev deps and pre-commit hook | `make install`     |
| Auto-format with ruff                | `make fmt`         |
| Lint without modifying files         | `make lint`        |
| Type check with mypy                 | `make typecheck`   |
| Run tests with coverage in parallel  | `make test`        |
| Fast tests, no coverage              | `make test-fast`   |
| Coverage report on stdout            | `make cov`         |
| Static security scan (bandit)        | `make security`    |
| Check deps for known CVEs (pip-audit)| `make audit`       |
| Security-lint workflows (zizmor)     | `make actions`     |
| Smoke-test the built package         | `make smoke`       |
| cliprobe terminal checks (Node 22+)  | `make cliprobe`    |
| Full local CI gate                   | `make check`       |
| Run all pre-commit hooks             | `make pre-commit`  |
| Clean caches and build artifacts     | `make clean`       |

## Branch naming

Use short, hyphen-separated branch names prefixed with the type of change:

```
<type>/<short-description>
```

Allowed types:

- `feat/` for new user-facing functionality
- `fix/` for bug fixes
- `docs/` for documentation only changes
- `refactor/` for internal refactors with no behavior change
- `test/` for changes that only add or adjust tests
- `chore/` for build, CI, dependency, or tooling changes
- `perf/` for performance improvements
- `security/` for hardening fixes that are not vulnerability disclosures

Examples:

```
feat/audit-jku-rule
fix/crack-trailing-whitespace
docs/readme-jwks-example
refactor/decoder-split-base64
chore/bump-cryptography
```

Branch off the latest `main`. Keep one logical change per branch.

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/). The format is:

```
<type>(<scope>): <short summary>

<optional body>

<optional footer>
```

`<type>` must be one of: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`, `security`, `build`, `ci`, `style`, `revert`.

`<scope>` is a short identifier for the area of the codebase. Use a command name, a `core/` module name, or a high-level area:

- Command scopes: `audit`, `crack`, `decode`, `diff`, `verify`, `sign`, `forge`, `generate-secret`, `download-wordlists`
- Core scopes: `core`, `algorithms`, `auditor`, `claims`, `cracker`, `crypto`, `decoder`, `encoding`, `forge`, `jwks`, `keys`, `verifier`, `wordlist`
- Other scopes: `cli`, `readme`, `ci`, `deps`, `release`

The `commit-msg` hook installed by `make install` checks these rules, and CI checks the PR title, because the squash commit on `main` uses it as the message and release-please reads it to decide the next version.

Rules:

- Use the imperative mood: "add" not "added" or "adds".
- Keep the summary line under 72 characters.
- Do not end the summary with a period.
- Describe the change, not the file. "fix(crack): handle empty wordlist" is better than "update crack.py".
- The body explains the why and any non-obvious tradeoffs. Wrap at 72 columns.
- Reference issues in the footer: `Refs #42` or `Closes #42`.
- Mark breaking changes with `!` after the type or a `BREAKING CHANGE:` footer.

Examples:

```
feat(audit): flag jku header pointing to non-https URL
fix(crack): handle wordlists with trailing whitespace
docs(readme): add JWKS verification example
refactor(core)!: split decoder into parser and encoder modules
chore(deps): bump cryptography to 48.0.0
```

## Pull request workflow

1. Open or comment on an issue first if the change is non-trivial. This avoids wasted work on a direction that may not be accepted.
2. Fork the repository and create a feature branch from `main`.
3. Make focused commits that follow the conventions above.
4. Run `make check` and make sure everything passes locally.
5. Push your branch and open a pull request against `main`. Fill in every section of the PR template.
6. The CI workflow runs lint, type check, security checks, and the tests on Linux and Windows with every supported Python, plus macOS. All checks must pass. Actions are pinned to full commit SHAs; keep the version comment when you change one.
7. A maintainer will review. Address review feedback by pushing additional commits to the same branch. Avoid force-pushing during review so reviewers can see incremental changes. Squash-merging is performed by the maintainer at merge time.
8. Once approved and green, a maintainer merges with a squash commit whose message follows the conventional-commits format.

### Dependabot pull requests

Dependabot opens grouped pull requests on Mondays: runtime and dev dependencies (minor and patch), their major updates separately, security updates, and GitHub Actions. It waits seven days before proposing a new version, and updates `uv.lock` only, so the lower bounds in `pyproject.toml` stay low. Titles use `build(deps)`, `build(deps-dev)` and `ci(deps)`, which never cut a release on their own. Merge them with "squash and merge" once CI is green; if CI fails, fix it on the Dependabot branch before merging.

### What makes a good pull request

- Small and focused. One logical change per PR.
- Tests for new behavior and for fixed bugs.
- Documentation updates when user-facing surface changes (README, command help text, examples).
- A clear "How to test" section that a reviewer can paste into a terminal.

## Testing guidelines

- Tests live in `tests/`. CLI-level tests use Click's `CliRunner` and assert on stdout, exit codes, and JSON shapes. Core tests exercise pure functions.
- Mirror the source layout: `core/auditor.py` is tested by `tests/test_auditor.py`, `commands/audit.py` by `tests/test_cmd_audit.py`, and so on.
- Use the fixtures in `tests/conftest.py` for keys, tokens, and temporary wordlists. Do not check in real secrets or production tokens.
- New audit rules require both a positive case (the rule triggers) and a negative case (the rule does not trigger).
- New verification or signing behavior must cover error paths: invalid signature, missing claim, malformed key.
- Signing and verification are checked against the RFC 7515, RFC 8037 and RFC 7520 examples and against PyJWT in both directions (`tests/test_interop.py`). PyJWT is a development dependency only; the package never imports it.
- Code that parses tokens, JSON or JWKs gets property tests in `tests/test_properties.py` (Hypothesis). They assert that hostile input ends in a result or a typed error, never a crash. Keep examples bounded so the suite stays fast.

Run the suite with:

```bash
make test       # parallel, with coverage
make test-fast  # parallel, no coverage, fastest feedback loop
make cov        # full coverage report on stdout
```

## Code style

- Formatting and linting are handled by [ruff](https://docs.astral.sh/ruff/). Run `make fmt` before committing or rely on the pre-commit hook.
- Type checking is enforced with [mypy](https://mypy-lang.org/) on the whole package. New code should be fully typed.
- Prefer explicit, plain-Python code. No clever metaprogramming in the CLI surface.
- Keep comments minimal. Names should make code self-explanatory. Only add a comment when the why is non-obvious.
- User-facing strings should be neutral and informative. No emojis, no em or en dashes in output. Match the style of existing panels.
- Errors raised from `core/` should be domain-specific subclasses of the exceptions in `core/errors.py`. The command layer turns them into formatted Rich output.

## Security policy

Do not file public issues for security vulnerabilities. Use the [GitHub Security Advisories](https://github.com/KhaledSaeed18/jwt-toolkit/security/advisories/new) form so we can coordinate disclosure privately.

When working on security-relevant code:

- Reference the CVE, RFC section, or attack writeup in commit messages and tests.
- Make sure new audit rules have clear severity, a concrete recommendation, and a positive and negative test.
- Never commit real secrets, real private keys, or production tokens. Use the fixtures in `tests/conftest.py`.

## Releasing

Releases are maintainer-only and run through [release-please](https://github.com/googleapis/release-please) in `.github/workflows/publish.yml`:

1. Every push to `main` updates an open release PR titled `chore(release): vX.Y.Z`. It bumps the version in `pyproject.toml`, `uv.lock` and `.release-please-manifest.json`, and adds the `CHANGELOG.md` entry built from the commit messages since the last release.
2. The version comes from those messages: `feat` gives a minor release, `fix`, `security`, `perf`, `revert` and `docs` give a patch, and `!` or a `BREAKING CHANGE:` footer gives a major. `build`, `ci`, `chore`, `test`, `refactor` and `style` never cause a release on their own.
3. Leave the release PR open while changes accumulate. Merging it releases: the same workflow run tags the commit, creates the GitHub Release, runs the full CI gate on that commit, builds, and publishes to PyPI with Trusted Publishing.
4. The publish job waits for approval of the `pypi` GitHub environment.

If publishing fails after the tag exists, fix the cause and re-run it for that tag with `gh workflow run publish.yml --ref vX.Y.Z`. A version that reached PyPI can never be uploaded again; ship the next patch instead.

Contributors do not need to do any of this. Maintainers handle releases.

Thank you for contributing.
