---
name: release
description: Cut a new jwt-toolkit release end-to-end — preflight checks, semver guidance, version bump in `pyproject.toml`, commit, signed tag, push, GitHub Release that triggers `publish.yml` (PyPI Trusted Publishing), and post-publish verification. Use only when the user explicitly asks to release/cut/ship a new version.
disable-model-invocation: true
---

# /release — version bump → tag → GitHub Release → PyPI

`$ARGUMENTS`:
- an exact version (e.g., `0.2.0`, `0.1.3`), or
- a semver bump kind: `patch` | `minor` | `major`, or
- `--dry-run` (alone or combined with a version/kind) — runs every check but skips the writes, push, and release creation.

If `$ARGUMENTS` is empty, **ask** what to ship. Don't guess. Tell the user what the current tag is and what the diff since that tag suggests (see Step 2).

## Step 1 — Authorization gate

Releases publish to PyPI, which is **irreversible**. Only proceed if the user has asked, in this turn, to release. Do not infer a release from "let's wrap up" or "ship it later". If unsure, ask explicitly: "Are you asking me to publish to PyPI now?"

## Step 2 — Preflight (read-only)

Run these in parallel; if any fails, stop and report:

1. **Branch & cleanliness.**
   - `git rev-parse --abbrev-ref HEAD` → must be `main`.
   - `git status --short` → must be empty.
2. **Up-to-date with remote.**
   - `git fetch origin && git status -sb` → must show `## main...origin/main` with no `[behind]`.
3. **Current version.** Read `version = "X.Y.Z"` from `pyproject.toml`.
4. **Latest tag.** `git describe --tags --abbrev=0`.
5. **Diff since last tag.** `git log <last-tag>..HEAD --oneline` — read every line.
6. **CI status of `HEAD`.** `gh run list --branch main --limit 1 --json conclusion,status,headSha,event` — must be `conclusion: success` for the most recent CI run on the current SHA.
7. **Full local gate.** Run `make check`. CI passing is necessary but not sufficient — local must also pass with the current working tree.

### Semver guidance from the diff

Skim the commit subjects since the last tag and propose the bump kind to the user:

- Any commit suggesting a CLI grammar change (renamed command/flag, removed flag, changed flag default that changes behavior) → **major**, or **minor with deprecation alias** if pre-1.0.
- Any commit suggesting a `--json` shape change or a `JSON_SCHEMA_VERSION` bump → **major**.
- New command, new flag (additive), new audit rule → **minor**.
- Bug fix, docs, internal refactor with no observable change → **patch**.

Pre-1.0 (`0.x.y`) note: this project is `0.x` and Alpha. Breaking changes go in `minor` bumps (`0.1.x` → `0.2.0`) and must be flagged in the release notes.

## Step 3 — Confirm with the user

Print a one-screen summary and wait for `yes`:

```text
Release plan
  Current:        vX.Y.Z
  Proposed:       vA.B.C   (bump: patch|minor|major)
  Commits since:  N commits (one-line list)
  CI on HEAD:     ✅ passing
  Local check:    ✅ passing
  Dry-run:        yes|no
Proceed?
```

If the user changes their mind on version, restart from Step 2. Do **not** carry forward a stale preflight.

## Step 4 — Execute (skip every write if `--dry-run`)

In order, halting on any failure:

1. **Edit `pyproject.toml`** — bump `version = "..."`. Verify the diff is exactly that one line.
2. **Commit.**
   ```sh
   git add pyproject.toml
   git commit -m "chore(release): vA.B.C"
   ```
   If there is a `CHANGELOG.md`, also stage it. (None exists today — don't create one unsolicited.)
3. **Tag.**
   ```sh
   git tag -a vA.B.C -m "vA.B.C"
   ```
   Annotated, not lightweight — `publish.yml` may depend on tag metadata, and annotated tags carry the author and date.
4. **Push.**
   ```sh
   git push origin main
   git push origin vA.B.C
   ```
   Push the branch first, then the tag, so the tag points at a commit visible on remote.
5. **GitHub Release.**
   ```sh
   gh release create vA.B.C --title "vA.B.C" --generate-notes
   ```
   This triggers `.github/workflows/publish.yml`.

## Step 5 — Walk the publish workflow

1. **Tell the user**: "The `pypi` GitHub Environment requires manual approval before the publish job runs. Open the Actions tab and approve it."
2. Watch the workflow:
   ```sh
   gh run watch
   ```
   If it fails, read the failure (`gh run view --log-failed`) and triage with the user before retrying. **Do not** re-tag the same version; if a publish fails after the tag was pushed but before PyPI got the artifact, you can re-run the workflow from the Actions tab without changing the tag.

## Step 6 — Post-publish verification

After `publish.yml` is green:

1. **PyPI metadata sanity-check** — PyPI's JSON API exposes the released version:
   ```sh
   curl -s https://pypi.org/pypi/jwt-toolkit/json | jq -r '.info.version'
   ```
   Must equal `A.B.C`.
2. **Install from a clean venv** (offer this; don't run it without user okay since it touches the filesystem):
   ```sh
   uvx jwt-toolkit@A.B.C --version
   ```
   Confirms wheel + entrypoint resolve and the banner doesn't crash on a fresh environment.
3. **Surface the release URL.**
   ```sh
   gh release view vA.B.C --json url -q .url
   ```

## Hard rules

- **Never `twine upload` or `uv publish` manually.** Trusted Publishing is the only sanctioned path. Doing it manually breaks the OIDC chain and confuses provenance.
- **Never `--force-push`, never re-tag a published version.** If something went wrong, ship `A.B.(C+1)` as a follow-up rather than rewriting history.
- **Never delete a public tag from `origin`** without explicit user authorization — published releases are referenced by users, badges, and lockfiles.
- **Never skip CI**, `--no-verify`, or comment out a failing test "for the release". The release is the contract; lying in the contract is the worst possible outcome.

## Failure recovery (cheat-sheet)

- *Tag pushed, workflow failed before publish*: fix the cause, re-run the workflow from the Actions tab. Tag stays.
- *Tag pushed, PyPI upload succeeded but workflow timed out*: verify with the curl check in Step 6. If the version is on PyPI, the release is real — don't republish.
- *Wrong version bumped*: if NOT yet pushed → `git reset HEAD~1`, fix `pyproject.toml`, redo. If pushed but tag not pushed → `git revert` the bump commit, fix forward. If tag pushed but not yet published → talk to the user; usually the right answer is to publish anyway and immediately ship the corrected version as a follow-up.
