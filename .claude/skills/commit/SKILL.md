---
name: commit
description: Create a Conventional Commits-style commit for jwt-toolkit. Inspects the staged/unstaged diff, drafts a `type(scope): subject` message in the repo's voice, gates source-code changes on `make check`, and commits via a HEREDOC so the message format is preserved. Use when the user asks to commit, save, or check in work — never proactively, only on explicit request.
disable-model-invocation: true
---

# /commit — Conventional Commits with project gates

`$ARGUMENTS` is an optional subject hint or message. If supplied, treat it as the user's intent; you still craft the final message in this repo's style.

## Step 0 — Authorization

**Only run this skill when the user explicitly asks to commit.** Don't auto-commit at the end of a task, don't commit "to save progress", don't infer it from a hand-wave like "wrap this up". If unsure, ask.

## Step 1 — Survey

Run in parallel:

```sh
git status --short
git diff --stat
git diff --cached --stat
git log --pretty=format:'%s' -10
```

The log sample establishes the active voice — Conventional Commits with optional scope:

- `feat(scope): subject` — new user-facing capability
- `fix(scope): subject` — bug fix
- `docs(scope): subject` — README, CONTRIBUTING, CLAUDE.md, comments
- `chore(scope): subject` — meta, deps, tooling, no behavior change
- `refactor(scope): subject` — no behavior change, internal restructure
- `test(scope): subject` — tests only
- `ci(scope): subject` — `.github/workflows/`
- `perf(scope): subject` — measurable perf change
- `chore(release): vX.Y.Z` — release bumps only

Match the existing log's tense and capitalization. Recent commits use lowercase subjects, short, no trailing period.

## Step 2 — Classify the diff

Look at what actually changed (not just file names):

- Any `.py` under `jwt_toolkit/` touched? → source change. Requires `make check` to pass before commit.
- Any test file touched? → still source change for gate purposes.
- Only `.md`, `.claude/`, `.cspell.json`, `.github/ISSUE_TEMPLATE/`, `assets/`? → docs/meta; gate is optional but `make lint` is cheap.
- `pyproject.toml` or `uv.lock` touched? → run `make check` (deps can break tests).
- `Makefile`, `.github/workflows/`, `.pre-commit-config.yaml`? → meta; run `make check` to confirm CI still mirrors local.

If the diff is mixed (e.g., a `feat` plus an unrelated `chore`), **propose splitting** before committing. Mixed commits make `git blame`, `git revert`, and the changelog noisy. Ask: "I see two unrelated changes — A in `commands/`, B in `.github/`. Split into two commits?"

## Step 3 — Pick scope

Look at the touched paths to derive scope. Common scopes for this repo:

- `cli` — anything under `jwt_toolkit/cli/`
- `core` — anything under `jwt_toolkit/core/`
- `audit`, `crack`, `decode`, `forge`, `sign`, `verify`, `generate-secret`, `download-wordlists` — single-command changes
- `readme`, `docs`, `contributing` — documentation
- `ci`, `release` — workflows
- `deps` — `pyproject.toml`/`uv.lock` only

If the change spans multiple scopes, omit the scope (`feat: ...`). Don't invent a scope.

## Step 4 — Gate

For source changes (per Step 2), run `make check` and refuse to commit on failure. Surface the failure exactly as `/check` would. **Don't** offer `git commit --no-verify` — the gate is the contract.

If the working tree contains both staged and unstaged changes, **ask** the user whether to include the unstaged hunks. Don't `git add -A` silently; that can sweep in `.env`, fixtures, or generated files. Stage by explicit file name.

## Step 5 — Draft the message

Body content rules:

- **Subject** ≤ 72 chars, imperative, lowercase, no trailing period.
- **Body** (optional) — wrap at 72 chars. Use it when the *why* isn't obvious from the subject.
- **No marketing language.** "Refactor X to be more readable" is fine; "drastically improve" is not.
- **No "Co-Authored-By" footer.** This repo's history doesn't use one (check `git log` to confirm) — match what's there, don't introduce a new convention.
- **Never** reference Claude, Anthropic, AI, or the agent in the message. The commit speaks for the code, not the author of the keystrokes.
- **Never** include the secret values, signatures, or token payloads that may appear in test fixtures or output in the message body.

Show the drafted message to the user **before committing** and wait for `yes`. If they edit, redraft from their edits, don't re-roll from scratch.

## Step 6 — Commit

Use a HEREDOC so multi-line messages and special characters survive the shell:

```sh
git add <explicit files>
git commit -m "$(cat <<'EOF'
type(scope): subject

Optional body explaining the why, wrapped at 72.
EOF
)"
git status
```

After the commit, run `git status` to confirm the working tree is clean (or shows only files the user intentionally excluded). Surface the final SHA: `git rev-parse --short HEAD`.

## Step 7 — On pre-commit hook failure

The repo runs `pre-commit` automatically on `git commit`. If a hook modifies a file (ruff autofix, end-of-file-fixer, trailing-whitespace):

1. The commit **did not happen** — the working tree now has the hook's edits unstaged.
2. **Never** use `git commit --amend` or `--no-verify` to dodge this. The previous commit (if any) is unrelated.
3. Inspect the hook's edits, `git add` them, and **make a new commit** (or restage and retry — same SHA hadn't been written yet).

If a hook fails with a real error (bandit finding, ruff rule that requires a human decision), fix the underlying issue rather than suppressing it.

## Hard rules

- Never `git commit --no-verify` unless the user explicitly asks.
- Never `git add -A` / `git add .` without showing the list first.
- Never push as part of this skill. Push is a separate decision (use `/pr` or ask).
- Never commit `CLAUDE.local.md`, `.env`, `.venv/`, `__pycache__/`, or files under `/tmp/`. If you see them in the diff, stop and surface them.
- Never edit `CHANGELOG.md` (it doesn't exist; don't create one unsolicited).
- Never bump `pyproject.toml` `version` in a `/commit` flow — that's `/release`.
