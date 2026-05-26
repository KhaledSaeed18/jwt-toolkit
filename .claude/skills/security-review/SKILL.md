---
name: security-review
description: Domain-aware security review of the current diff for jwt-toolkit. Goes beyond generic linters — checks for JWT-specific regressions (alg=none acceptance, algorithm confusion, non-constant-time comparisons), secret leakage in output and exceptions, weakened defaults, public-API breaks (`JSON_SCHEMA_VERSION`, error codes), layering violations (Click/Rich in `core/`), and unsafe I/O. Use before opening a PR that touches `core/`, `commands/`, `crypto`, `auditor`, `forge`, or any error path.
---

# /security-review — diff-aware security review

This is the review pass `bandit` cannot do, because the threat model is domain-specific. Run it after `make check` is green and before requesting human review. Generic correctness has already been checked by then; the questions left are specific to a JWT defensive toolkit published to PyPI.

## Step 1 — Scope the diff

```sh
git fetch origin
git diff --stat origin/main...HEAD
git diff origin/main...HEAD
```

If the branch is `main` (no PR yet), diff against the last tag instead: `git diff $(git describe --tags --abbrev=0)...HEAD`.

Group the changes by area and only run the checks for areas that were touched. **Do not** review areas with no diff — that's noise and gives false confidence.

| Area touched | Checks below |
|---|---|
| `core/crypto.py` | Crypto invariants |
| `core/auditor.py` | Audit rules |
| `core/jwks.py` | Network / JWKS |
| `core/decoder.py`, `core/encoding.py` | Parsing |
| `core/forge.py` | Forge surface |
| `core/errors.py` | Error model |
| `commands/*` | Command layer |
| `cli/*` | CLI plumbing |
| `wordlists/`, `crack.py` | Wordlist handling |
| `pyproject.toml`, `uv.lock` | Dependencies |

## Step 2 — Run the checks

### Crypto invariants (`core/crypto.py`, anything calling it)

- Any `==`, `!=`, `bytes.startswith`, `in` on a signature, MAC, tag, or secret? **Finding.** Must use `hmac.compare_digest` or `cryptography`'s `.verify(...)`.
- Did a `SUPPORTED_ALGORITHMS` / `RSA_ALGORITHMS` / `EC_ALGORITHMS` / `PSS_ALGORITHMS` key get renamed, removed, or reordered? Public API — **breaking change**, call it out.
- Is `alg=none` ever accepted by the verifier (not the forger)? Search for `"none"` and `None` in verifier paths. **Hard rule violation.**
- Algorithm confusion: does the verifier choose the algorithm from the token header rather than from the key material the caller supplied? **Finding.** Algorithm must be authoritatively pinned by the caller's key, not by an attacker-controlled header.
- A new dependency for crypto (pyjwt, python-jose, authlib, jose, jwcrypto, etc.)? **Reject** — `CLAUDE.md` forbids this; the project re-implements JWS visibly on purpose.

### Audit rules (`core/auditor.py`)

- New rule: does it cite a CVE, RFC section, or named attack pattern in the docstring or `details`? Per `CONTRIBUTING.md`, new rules need a security rationale.
- Does the rule's `headline` reflect the **security outcome**, not the technical event? ("Algorithm is symmetric — sender and verifier must share the secret" beats "alg field is HS256".)
- Does the rule emit false positives on benign tokens? Spot-check with a known-good fixture from `tests/conftest.py`.

### Network / JWKS (`core/jwks.py`)

- Is `core/jwks.py` still the **only** module making outbound HTTP requests? Grep the diff for `urllib`, `urlopen`, `httpx`, `requests`, `urllib3`. Anywhere else = **layering violation**.
- Is the URL scheme restricted to `https://` (or `http://` only with an explicit opt-in)? An `http://` JWKS endpoint defeats the trust chain.
- Are redirects followed across hosts? Cross-host redirects on JWKS = SSRF risk; pin the host.
- Are responses size-bounded? An unbounded read on a remote endpoint is a DoS.
- Do tests still avoid the network? Grep new tests for any HTTP call outside the offline fixtures.

### Parsing (`core/decoder.py`, `core/encoding.py`)

- Base64url decoding tolerant of missing padding? Real-world tokens omit it; rejecting padded ≠ unpadded is a usability bug, but accepting non-base64url alphabets (e.g., `+`, `/`) is a strictness bug.
- JSON parsing: does the parser run with bounded depth/size, or could a crafted token cause a memory blow-up? At minimum the diff shouldn't loosen any existing limits.
- Does the decoder raise the typed `core.errors` exceptions, or has someone smuggled in a `ValueError`/`json.JSONDecodeError` that escapes the layer? Untyped exceptions break `--json` consumers.

### Forge surface (`core/forge.py`, `commands/forge.py`)

- New variant: is its purpose clearly defensive (helps an operator audit their own verifier)?
- Does the help text or output explicitly state "for self-audit against systems you own"? The threat-model framing is part of the contract.
- Does the variant accidentally produce a *valid* token (i.e., one a correct verifier would accept)? It must produce an *attack-shaped* token that a correct verifier rejects.

### Error model (`core/errors.py`, anything raising domain errors)

- Did any existing `code` string change? **Breaking change** for `--json` consumers — codes are forever. Add a new code rather than renaming.
- Is any `code` reused across two semantically different errors? Codes must be distinct.
- Do `headline` / `details` / `title` contain any of: the supplied `--secret`, the contents of a private key, the raw signature bytes, the wordlist candidate that was being tried, or any value the user passed via an option that could be sensitive? **Secret leakage finding.**
- Does any error message echo the *value* of a user-supplied secret/key path *contents* (path is fine; contents are not)?

### Command layer (`jwt_toolkit/commands/*`)

- Any `print(` introduced? Must be `console.print(...)` or `click.echo(...)`. `print` bypasses `--quiet`, `--no-color`, the rich theme, and breaks scripted consumers.
- New `--json` field? It's now public API. Confirm `JSON_SCHEMA_VERSION` is bumped if any existing field was renamed/removed/retyped.
- Any secret accepted as a positional argument? Must be `--secret` / `--private-key` (so it doesn't land in shell history / `ps`).
- Error path: does the command raise `click.ClickException(...)` with a user-facing sentence, or does it leak a raw traceback? Tracebacks in normal failure paths leak structural info and confuse users.
- Is `sys.exit(N)` used? Must be `raise click.ClickException(...)` so messaging routes through the project console.
- Is `core/` logic invoked, or did logic creep into the command body? Commands stay thin.

### CLI plumbing (`jwt_toolkit/cli/*`)

- Does the `Commands:` block in `CLI_HELP` still align column-wise after the change? Eyeball it; one drifted line stays visible to every user forever.
- Is `--quiet` / `--no-color` / `--no-banner` still honored on the new path? Run the new command with `JWT_TOOLKIT_QUIET=1 NO_COLOR=1` mentally and confirm output is clean.
- Did `JSON_SCHEMA_VERSION` change? If yes — every command's `--json` shape must remain consistent with the bump (i.e., the bump is justified by a real shape change).

### Wordlist handling (`crack` path)

- Is the wordlist read line-by-line (streaming), or is `read()`/`readlines()`/list comprehension over the file used? Big wordlists exist in the wild — full-load is a DoS on the user's own machine.
- Are candidate secrets logged, printed, or written to disk anywhere outside the success report? `crack` may legitimately print the recovered secret on success — but it must not echo *attempted* candidates.
- Is decoding `utf-8` with `errors="replace"`? A non-UTF-8 line shouldn't crash; it should be tried and discarded.

### Dependencies (`pyproject.toml`, `uv.lock`)

- New runtime dependency? Per `CONTRIBUTING.md`, each must be justified. Note it as a finding requiring user confirmation.
- A dependency pin loosened (e.g., `>=2.0` → `>=1.0`)? Could re-introduce a previously-fixed CVE. Run `make audit` to confirm.
- Lockfile (`uv.lock`) touched without a corresponding `pyproject.toml` change? Confirm with the user — usually that's a `uv lock --upgrade` they meant to do explicitly.

### Tests

- Coverage on the new code ≥ 80%? Run `make test` and check.
- New tests touch the network? **Finding.** Use fixtures.
- New tests mutate global state, change cwd, or read/write outside `tmp_path`? Breaks `-n auto` parallelism.
- An `xfail` was added — what's the linked issue / commit message explaining why? `xfail` without context becomes permanent dead code.

## Step 3 — Report

Group findings by severity:

- **🚨 Block** — secret leakage, `==` on signatures, `alg=none` accepted, network in core, public-API silent break, new offensive dependency. These should not merge.
- **⚠ Fix before merge** — missing `JSON_SCHEMA_VERSION` bump on a shape change, missing CVE/RFC citation on a new audit rule, `print()` instead of `console.print`, positional secret.
- **💡 Consider** — style nits, missing test for an edge case, documentation gaps.

For each finding: quote the line, give `file:line`, and state the rule it violates with a one-line fix. **Don't paraphrase code — quote it verbatim** so the user can grep.

If nothing was touched in an area, say "skipped — no diff" so the user knows it wasn't silently passed. A short, accurate report beats a long one that bluffs.

## Step 4 — Re-check after fixes

If the user makes changes in response, **re-run `/security-review`**, not a partial pass. Findings interact (fixing a `print()` may introduce a secret leak via `console.print`); only the full review catches that.
