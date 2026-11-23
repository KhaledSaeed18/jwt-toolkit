"""Dependabot updates must never cut a release on their own."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Commit types release-please leaves out of releases (see CONTRIBUTING.md, "Releasing").
NON_RELEASING = {"build", "ci", "chore", "test", "refactor", "style"}


def _config() -> str:
    return (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")


def test_dependabot_commit_prefixes_do_not_release():
    prefixes = set(re.findall(r"^\s+prefix(?:-development)?: (\w+)", _config(), flags=re.M))
    assert prefixes == {"build", "ci"}
    assert prefixes <= NON_RELEASING


def test_dependabot_waits_a_week_for_new_versions():
    assert _config().count("default-days: 7") == 2


def test_runtime_lower_bounds_are_left_alone():
    assert "versioning-strategy: lockfile-only" in _config()
