---
name: release
description: Ship a jwt-toolkit release through release-please — inspect the open `chore(release): vX.Y.Z` PR, preflight it (CI green on main, local `make check`, artifact build + twine check, version and changelog sanity), merge it so `publish.yml` tags, creates the GitHub Release, re-validates and builds, then walk the `pypi` environment approval and verify on PyPI. Also covers a dry run and recovery for a failed publish. Use only when the user explicitly asks to release, cut, ship, or publish to PyPI. Never infer a release from "wrap up" or "we're done".
disable-model-invocation: true
---

# /release — merge the release PR → tag → GitHub Release → PyPI

Releases are automated by release-please in `.github/workflows/publish.yml`. Every push to `main` keeps one release PR (`chore(release): vX.Y.Z`) up to date: it bumps `pyproject.toml`, `uv.lock` and `.release-please-manifest.json` and prepends the `CHANGELOG.md` entry. **Merging that PR is the release.** Never bump the version, tag, or create a GitHub Release by hand.

`$ARGUMENTS`: empty (ship the open release PR), `--dry-run` (preview only), or `recover vX.Y.Z` (re-run publishing for an existing tag).

## Step 1 — Authorization gate

Merging the release PR publishes to PyPI after the `pypi` approval, which is **irreversible**. Proceed only if the user asked, in this session, to release. Batching is the default: user-facing work collects in the release PR until the owner decides to ship. If unsure, ask: "Are you asking me to publish to PyPI now?"

## Step 2 — Find and read the release PR

```sh
gh pr list --search 'chore(release) in:title' --state open --json number,title,headRefName,url
gh pr view <N> --json body,files,mergeable
gh pr diff <N>
```

- No open release PR means nothing user-facing has merged since the last tag (only `build`/`ci`/`chore`/`test`/`refactor`/`style` commits). Say so and stop.
- The diff must touch only `pyproject.toml` (version), `uv.lock` (the `jwt-toolkit` package version), `.release-please-manifest.json`, and `CHANGELOG.md`.
- Read the changelog entry. Check the proposed bump against the commits since the last tag (`git log $(git describe --tags --abbrev=0)..origin/main --oneline`):
  - `JSON_SCHEMA_VERSION` changed: `git diff <last-tag>..origin/main -- jwt_toolkit/cli/decoding.py | grep -E '^[+-].*JSON_SCHEMA_VERSION'` → breaking.
  - An error `code` removed or renamed: `git diff <last-tag>..origin/main -- jwt_toolkit/core/errors.py | grep -E '^-.*code='` → breaking.
  - A CLI grammar change (renamed/removed command or flag, changed default) → breaking.
  A breaking change needs a `!` or `BREAKING CHANGE:` commit so release-please proposes a major. If the proposal is wrong, fix it with a correcting commit on `main` (release-please honors a `Release-As: X.Y.Z` footer), never by editing the release PR by hand.

## Step 3 — Preflight (read-only)

1. CI on `main` HEAD is green: `gh run list --branch main --workflow CI --limit 1 --json conclusion,headSha`.
2. Check out the release PR branch locally and run `make check` (includes the installed-package smoke test).
3. `rm -rf dist && uv build && uvx twine check --strict dist/*` — both PASSED. Then `rm -rf dist`.
4. `uv lock --check` passes on the release branch (release-please updated the lockfile version).

Print a one-screen summary and wait for `yes`:

```text
Release plan
  Last tag:       vX.Y.Z
  Release PR:     #N  chore(release): vA.B.C   (bump: patch|minor|major)
  Commits since:  N (one-line list)
  CI on main:     passing
  Local check:    passing
Proceed?
```

`--dry-run` stops here. It can also preview what release-please would do without a PR:

```sh
npx --yes release-please@17 release-pr --dry-run --repo-url=KhaledSaeed18/jwt-toolkit --token="$(gh auth token)" --target-branch=main
```

## Step 4 — Merge

```sh
gh pr merge <N> --squash --subject "chore(release): vA.B.C (#N)"
```

The push to `main` runs `publish.yml`: release-please tags `vA.B.C` and creates the GitHub Release with the changelog entry, then the run validates that exact commit (the reusable `ci.yml`), checks tag == package version, builds, and waits at the `pypi` environment.

## Step 5 — Walk the publish run

1. Tell the user: "The `pypi` GitHub Environment requires manual approval before the publish job runs. Open the Actions tab and approve it."
2. Watch the run for the merge commit:
   ```sh
   SHA=$(git rev-parse origin/main)
   RUN_ID=$(gh run list --workflow=publish.yml --limit 5 --json databaseId,headSha --jq "[.[] | select(.headSha == \"$SHA\")][0].databaseId")
   gh run watch "$RUN_ID"
   ```
3. On failure, read `gh run view --log-failed "$RUN_ID"` and triage with the user.

## Step 6 — Post-publish verification

1. `curl -s https://pypi.org/pypi/jwt-toolkit/json | jq -r '.info.version'` equals `A.B.C` (allow a minute for the CDN).
2. With the user's okay: `uvx --no-cache jwt-toolkit@A.B.C --version` from a directory outside the repo.
3. Surface the release URL: `gh release view vA.B.C --json url -q .url`.

## Recovery: `recover vX.Y.Z`

The tag and GitHub Release exist but PyPI does not have the version (validation, build, approval timeout, or upload failed):

1. Fix the cause on `main` if it is in the repo; if the fix changes the released code, ship a new patch instead.
2. Re-run publishing for the existing tag: `gh workflow run publish.yml --ref vX.Y.Z`. The run checks out the tag, re-validates it, rebuilds, and waits for approval again.

If PyPI already has the version, the release is real; never republish it. If PyPI rejected the upload (for example "File already exists" or bad metadata), the version is spent: fix forward with the next patch, and delete the doomed GitHub Release only with the user's okay.

## Hard rules

- **Never `twine upload` or `uv publish` manually.** Trusted Publishing from `publish.yml` with the `pypi` environment is the only path; both names are registered on PyPI.
- **Never bump the version, edit `CHANGELOG.md` for a release, tag, or `gh release create` by hand.** release-please owns all four.
- **Never force-push, re-tag a published version, or delete a public tag** without explicit user authorization.
- **Never skip CI** or `--no-verify` for a release.
