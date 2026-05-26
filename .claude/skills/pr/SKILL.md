---
name: pr
description: Open a GitHub pull request for jwt-toolkit. Verifies branch naming, runs `make check`, suggests `/security-review` when source/diff warrants it, drafts the PR body against the repo's `.github/PULL_REQUEST_TEMPLATE.md` (Summary, Type, Related issues, Changes, How to test, Checklist), and creates the PR with `gh pr create`. Use only when the user asks to open a PR.
disable-model-invocation: true
---

# /pr — open a pull request

`$ARGUMENTS` is an optional PR title hint. Final title still derives from the actual diff and the repo's commit-message style.

## Step 0 — Authorization

PRs are visible to the world (or the org), trigger CI, and ping reviewers. **Only proceed when the user explicitly asks to open a PR.** Don't infer it from "let's wrap this up" or "we're done". If unsure, ask.

## Step 1 — Preflight

Run in parallel and abort on any failure:

```sh
git rev-parse --abbrev-ref HEAD      # must not be `main`
git status --short                   # must be empty (everything committed)
git fetch origin
git log origin/main..HEAD --oneline  # commits this PR contains; must not be empty
git diff origin/main...HEAD --stat   # scope of the PR
```

- **Branch name** must match `^(feat|fix|docs|refactor|test|chore|perf|security)/[a-z0-9-]+$` per `CONTRIBUTING.md`. If it doesn't, surface the rule and ask the user to rename the branch (`git branch -m <new-name>`) before continuing. Don't rename it yourself.
- **Branch must not be `main`.** Refuse.
- **Working tree must be clean.** If there are uncommitted changes, ask whether to commit them via `/commit` first.
- **Branch must have commits ahead of `origin/main`.** Empty PRs are noise.

## Step 2 — Gate

Run `make check`. Refuse to open the PR on failure — the checklist explicitly requires it. Don't open a "draft" to dodge the gate.

If the PR touches `jwt_toolkit/` source code, **recommend** running `/security-review` before opening the PR. Phrase it as a suggestion to the user, not a hard block; they may have already run it.

## Step 3 — Classify the PR

From the diff, derive the **Type of change** checkboxes the template lists:

- **Bug fix** — `fix(...)` commits, no new behavior.
- **New feature** — `feat(...)` commits, additive only.
- **Breaking change** — renames/removes a flag, changes `--json` field name/type, changes default behavior, bumps `JSON_SCHEMA_VERSION`. If breaking, the title prefix should be `feat!:` or `fix!:` (or `feat(scope)!:`); call this out to the user and confirm before continuing.
- **Refactor** — no behavior change.
- **Documentation** — `docs(...)` only.
- **Tests only** — `test(...)` only.
- **Build, CI, or tooling** — `chore(...)`, `.github/workflows/`, `Makefile`, `pyproject.toml` tool config only.

A PR may legitimately tick multiple boxes (e.g., a feature plus its tests). Don't force a single tick.

## Step 4 — Draft the body

Use `.github/PULL_REQUEST_TEMPLATE.md` as the source of truth — that's what GitHub auto-populates. Fill each section honestly:

- **Summary** — 1–2 sentences, security-outcome shaped where applicable. Match the voice of the recent commits in `git log`.
- **Type of change** — tick the boxes that apply.
- **Related issues** — search with `gh issue list --search "<keyword>"` if the user hasn't told you. Use `Closes #N` only when the PR actually closes the issue; otherwise use `Refs #N`. If none, leave `Closes #` empty rather than inventing one.
- **Changes** — bullets describing **user-facing impact**. Not file lists. Not "added a function" — say what changed from the user's perspective.
- **How to test** — concrete commands a reviewer can run. Always include `make check`. For CLI changes, include a representative `jwt-toolkit ...` invocation with expected behavior.
- **Checklist** — tick each item only if true:
  - Followed CONTRIBUTING — yes if the branch name + commit messages match.
  - `make check` passes — confirmed in Step 2.
  - Added/updated tests — check the diff for `tests/` changes; if the PR is a behavior change without tests, **flag it** and ask the user before opening.
  - Updated docs — required if user-facing behavior changed (`README.md`, command `help=` strings, `CLAUDE.md`).
  - No new runtime dependencies — confirm `pyproject.toml` `dependencies` didn't grow; if it did, justify each in **Additional notes**.
  - No real secrets — check the diff for anything that looks like a key, token, or password. Refuse to open if found, surface the file:line, and ask the user.

## Step 5 — Confirm

Print the final title and body to the user. Wait for `yes` before calling `gh`. Edits land back in Step 4.

## Step 6 — Create

Push the branch (with `-u` on first push), then create the PR via HEREDOC so multi-line markdown survives the shell:

```sh
git push -u origin "$(git rev-parse --abbrev-ref HEAD)"
gh pr create --title "<title>" --body "$(cat <<'EOF'
## Summary
...

## Type of change
- [x] ...

## Related issues
Closes #...

## Changes
- ...

## How to test
```bash
make check
```

## Checklist
- [x] ...

## Additional notes
...
EOF
)"
```

After creation:

```sh
gh pr view --json url -q .url        # surface the PR URL
gh pr checks                         # show initial CI status
```

## Hard rules

- **Never push to `main` directly.** Refuse if the current branch is `main`.
- **Never `--force-push`** unless the user explicitly authorizes it for *this specific* push.
- **Never mark a PR as "ready" by adding fake checklist ticks.** A checklist item is either true or it's not.
- **Never reference Claude / AI / the agent in the PR body or title.** The PR speaks for the code; authorship metadata belongs in the commit, and this repo's commits don't carry a Co-Authored-By footer (verify with `git log`).
- **Never include real secrets, private keys, or production tokens** in the PR body — even paraphrased. If the user wants to share a token for testing, use a fixture in `tests/` instead.
- **Never `gh pr create --draft`** to dodge the `make check` gate. If the work isn't ready, don't open the PR.
- **Never `gh pr merge`** as part of this skill. Merging is a separate, reviewed decision.

## Failure recovery

- *Branch name fails the regex*: stop, tell the user the rule, suggest a rename. Don't rename for them.
- *`make check` fails*: surface the failure per `/check`'s triage table. Don't open the PR until it's green.
- *`gh pr create` fails because a PR already exists for this branch*: stop. Run `gh pr view` and show the user; ask whether to push new commits to the existing PR or close + reopen.
- *Push fails because the upstream branch diverged*: stop. Don't `--force-push` — investigate first (someone else may have pushed). The user decides.
