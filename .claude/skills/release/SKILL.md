---
name: release
description: Cut a new jwt-toolkit release — bump `version` in `pyproject.toml`, commit, tag, push tag, and create the GitHub Release that triggers PyPI publishing via `publish.yml`. Use only when the user asks to release/cut/ship a new version.
disable-model-invocation: true
---

# /release — version bump + tag + GitHub Release

`$ARGUMENTS` should be either:
- the new version (e.g., `0.2.0`, `0.1.3`), or
- a bump kind: `patch` | `minor` | `major`

If `$ARGUMENTS` is empty, **ask the user** which bump or version they want. Do not guess.

## Preflight (do before touching anything)

1. **Confirm authorization** — releases publish to PyPI. The user must have asked for a release in this turn. Don't infer it.
2. **Branch must be `main` and clean.** Run `git status --short` and `git rev-parse --abbrev-ref HEAD`. Abort with a one-line message if dirty or not on main.
3. **Up to date with origin.** `git fetch origin && git status -sb` — abort if behind.
4. **Run `make check`.** Releasing broken code is the worst outcome. If it fails, stop and report.
5. **Read current version** from `pyproject.toml` (`version = "X.Y.Z"`). Compute the new version from `$ARGUMENTS`.
6. **Confirm with the user**: "About to release X.Y.Z → A.B.C. Proceed?" Wait for their yes.

## Execute

1. Edit `pyproject.toml` to set the new version.
2. `git add pyproject.toml && git commit -m "chore(release): vA.B.C"`
3. `git tag vA.B.C`
4. `git push origin main && git push origin vA.B.C`
5. `gh release create vA.B.C --title "vA.B.C" --generate-notes`

Step 5 triggers `.github/workflows/publish.yml`, which builds with `uv build` and publishes to PyPI via Trusted Publishing (the `pypi` GitHub environment requires manual approval — tell the user to approve it in the GitHub UI).

## After

- Surface the release URL from `gh release view --json url -q .url`.
- Remind the user that publish.yml is gated on manual approval of the `pypi` environment.
- Do **not** run `twine upload` or `uv publish` manually — Trusted Publishing handles it.

## On failure

- If `git push` fails, do not retry with `--force`. Investigate.
- If `gh release create` fails after the tag was pushed, the tag exists remotely — either re-run `gh release create` once the issue is fixed, or `git push --delete origin vA.B.C` (only with user okay) before re-tagging.
