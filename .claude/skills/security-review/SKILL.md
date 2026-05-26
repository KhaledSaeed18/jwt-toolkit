---
name: security-review
description: Domain-aware security review of the current diff for jwt-toolkit. Goes beyond bandit/ruff — catches JWT-specific regressions (alg=none acceptance, algorithm confusion, non-constant-time signature/MAC comparison, JWKS SSRF), secret leakage in errors and output, public-API breaks (`JSON_SCHEMA_VERSION` and `core/errors.py` codes), layering violations (Click/Rich/network in `core/`), wordlist DoS shapes, and runtime dependency drift. Use this skill proactively whenever the user asks "is this safe to merge", "did I introduce a security regression", "review the diff", "check for secret leaks", before opening a PR that touches `jwt_toolkit/` source, or after finishing changes to `core/`, `commands/`, `crypto`, `auditor`, `forge`, `jwks`, error handling, or anything affecting `--json` output. Skip if the diff is pure documentation, `.claude/`, or other meta changes with no source touched.
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

**Short-circuit on docs/meta-only diffs.** If `git diff --name-only origin/main...HEAD` returns only paths under `*.md`, `.claude/`, `.github/ISSUE_TEMPLATE/`, `.cspell.json`, `.gitignore`, `assets/`, or `LICENSE`, stop here and report: "No source diff requiring security review — diff is documentation/meta only." Don't walk every area producing "skipped — no diff" 10 times; that's noise and the user is asking the wrong question.

Otherwise, group the touched files by area and run *only* the matching checks. Reviewing untouched areas inflates the report and gives false confidence in coverage.

| Area touched | Checks below |
|---|---|
| `jwt_toolkit/core/crypto.py` | Crypto invariants |
| `jwt_toolkit/core/auditor.py` | Audit rules |
| `jwt_toolkit/core/jwks.py` | Network / JWKS |
| `jwt_toolkit/core/decoder.py`, `jwt_toolkit/core/encoding.py` | Parsing |
| `jwt_toolkit/core/forge.py` | Forge surface |
| `jwt_toolkit/core/errors.py` | Error model |
| `jwt_toolkit/commands/*` | Command layer |
| `jwt_toolkit/cli/*` | CLI plumbing |
| `jwt_toolkit/core/crypto.py`, `jwt_toolkit/commands/crack.py`, `wordlists/` | Wordlist handling |
| `pyproject.toml`, `uv.lock` | Dependencies |
| `tests/**` | Tests |

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

### Network / JWKS (`jwt_toolkit/core/jwks.py`)

- Is `core/jwks.py` still the **only** module making outbound network calls? `git diff origin/main...HEAD -- jwt_toolkit/ ':!jwt_toolkit/core/jwks.py' | grep -E '\b(urllib|urlopen|httpx|requests|urllib3|aiohttp|socket\.)'` — any hit outside `jwks.py` is a **layering violation**.
- Is the URL scheme **restricted to `https://`**? `urllib.request.urlopen` will happily follow `file://`, `ftp://`, `data:` — that's a classic SSRF / local-file-read primitive on a server-side caller. An allowlist of `{"https"}` (or `{"https", "http"}` only with an explicit opt-in) belongs at the URL-validation boundary, not inside the fetch helper.
- Are redirects followed? Cross-host redirects on JWKS = SSRF risk; either disable redirects or pin the original host across the redirect chain.
- Are responses size-bounded? An unbounded `read()` on a remote endpoint is a DoS on the user's machine. Look for `read()` without a size argument.
- Is there a timeout on every network call? A missing timeout hangs the CLI on a slow endpoint forever.
- Do tests still avoid the network? Grep new tests for any HTTP call outside the offline fixtures in `tests/conftest.py` / `tests/helpers.py`.

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

- Any `print(` introduced? `git diff origin/main...HEAD -- jwt_toolkit/commands/ | grep -E '^\+.*\bprint\('` — must be `console.print(...)` or `click.echo(...)`. `print` bypasses `--quiet`, `--no-color`, the rich theme, and breaks scripted consumers.
- New `--json` field? It's now public API. Confirm `JSON_SCHEMA_VERSION` is bumped if any existing field was renamed, removed, or retyped. Adding optional fields is non-breaking.
- Any secret accepted as a positional argument (i.e., `@click.argument("secret")` instead of `@click.option("--secret", ...)`)? Must be an option — positional secrets land in shell history and `ps`.
- New `@click.command(help="...")` string: does it match the existing security-outcome voice ("Verify the signature and standard claims of a JWT.") rather than describing implementation ("Calls cryptography library...")? Voice drift here is visible to every CLI user forever.
- Error path: does the command raise `click.ClickException(...)` with a one-sentence user-facing message, or does it let a raw traceback escape? Tracebacks in normal failure paths leak structural info and confuse users.
- Is `sys.exit(N)` used? Must be `raise click.ClickException(...)` so messaging routes through the project console and exit code routing stays consistent.
- Is `core/` logic invoked, or did logic creep into the command body? Commands stay thin (~60 lines of non-flag-parsing code is the rough ceiling).

### CLI plumbing (`jwt_toolkit/cli/*`)

- Does the `Commands:` block in `CLI_HELP` still align column-wise? Eyeballing is unreliable. Run `awk '/^Commands:/,/^$/' jwt_toolkit/cli/__init__.py | grep -E '^\s+[a-z-]+' | awk '{print length($1), $1}'` — the lengths should cluster (all hit the same column for the description). One outlier = drift.
- Is `--quiet` / `--no-color` / `--no-banner` still honored on the new path? Trace any new output call: if it goes through `console.print` it's fine; if it bypasses `console`, it's not.
- Did `JSON_SCHEMA_VERSION` change? If yes — confirm a `--json` field was actually renamed/removed/retyped. A bump without a real shape change is also a finding (users will re-test their consumers for nothing).

### Wordlist handling (`crack` path)

- Is the wordlist read line-by-line (streaming), or is `read()`/`readlines()`/list comprehension over the file used? Big wordlists exist in the wild — full-load is a DoS on the user's own machine.
- Are candidate secrets logged, printed, or written to disk anywhere outside the success report? `crack` may legitimately print the recovered secret on success — but it must not echo *attempted* candidates.
- Is decoding `utf-8` with `errors="replace"`? A non-UTF-8 line shouldn't crash; it should be tried and discarded.

### Dependencies (`pyproject.toml`, `uv.lock`)

- **New runtime dependency** (added under `[project] dependencies`)? Per `CONTRIBUTING.md`, each runtime dep must be justified — note as a finding requiring user confirmation. **New dev dependency** (`[dependency-groups] dev`) is lower-risk but still worth a one-line "why".
- A version pin loosened (e.g., `>=2.0` → `>=1.0`, or upper bound removed)? Could re-admit a previously-fixed CVE. Run `make audit` to confirm the new range is clean.
- **`uv.lock` touched without a corresponding `pyproject.toml` change**? Usually means `uv lock --upgrade` was run. Confirm intent — a silent lockfile bump still ships in the wheel and can change behavior. Look at which packages moved: `git diff origin/main...HEAD -- uv.lock | grep -E '^[+-]version' | sort -u`.
- Did a transitively-pinned package known to be sensitive (`cryptography`, `urllib3`, anything in the JWS/crypto path) move? That's worth surfacing even if the direct deps didn't change.

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

If an area was untouched, omit it from the report — Step 1's scoping already filtered it out. A short, accurate report beats a long one that pads with "skipped" lines or bluffs findings on code that didn't change.

When the report has **zero findings**, say so in one sentence and stop. Don't manufacture a "consider" finding to look thorough — a clean PR is a clean PR, and noise erodes the user's trust in the next high-severity flag.

## Step 4 — Re-check after fixes

If the user makes changes in response, **re-run `/security-review`**, not a partial pass. Findings interact (fixing a `print()` may introduce a secret leak via `console.print`); only the full review catches that.
