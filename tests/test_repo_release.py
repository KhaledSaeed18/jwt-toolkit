"""Keep the release automation, the commit rules and the docs in agreement."""

import importlib.util
import json
import re
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Types that must never cut a release on their own.
NON_RELEASING = {"build", "ci", "chore", "test", "refactor", "style"}
# Types that go into the changelog and make the release PR propose a version.
RELEASING = {"feat", "fix", "security", "perf", "revert", "docs"}


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "check_commit_message", ROOT / "scripts" / "check_commit_message.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


def _config() -> dict:
    return json.loads((ROOT / "release-please-config.json").read_text())


def _contributing_types() -> set[str]:
    text = (ROOT / "CONTRIBUTING.md").read_text()
    line = next(line for line in text.splitlines() if "must be one of:" in line)
    return set(re.findall(r"`([a-z]+)`", line.split("must be one of:")[1]))


def test_commit_types_match_contributing_and_release_config():
    sections = {section["type"] for section in _config()["changelog-sections"]}
    assert set(checker.TYPES) == _contributing_types() == sections


def test_only_user_facing_types_release():
    sections = _config()["changelog-sections"]
    hidden = {s["type"] for s in sections if s.get("hidden")}
    visible = {s["type"] for s in sections if not s.get("hidden")}
    assert hidden == NON_RELEASING
    assert visible == RELEASING


def test_manifest_matches_pyproject_version():
    manifest = json.loads((ROOT / ".release-please-manifest.json").read_text())
    with (ROOT / "pyproject.toml").open("rb") as fh:
        version = tomllib.load(fh)["project"]["version"]
    assert manifest == {".": version}


def test_release_please_also_bumps_the_lockfile():
    package = _config()["packages"]["."]
    assert package["package-name"] == "jwt-toolkit"
    lock = [f for f in package["extra-files"] if f["path"] == "uv.lock"]
    assert lock == [
        {
            "type": "toml",
            "path": "uv.lock",
            "jsonpath": "$.package[?(@.name.value=='jwt-toolkit')].version",
        }
    ]


def test_tags_and_titles_follow_the_project_convention():
    config = _config()
    assert config["include-v-in-tag"] is True
    assert config["include-component-in-tag"] is False
    title = config["pull-request-title-pattern"].replace("${version}", "1.2.3")
    assert checker.problems(title) == []


def test_publish_workflow_keeps_the_trusted_publisher_identity():
    workflow = (ROOT / ".github" / "workflows" / "publish.yml").read_text()
    assert "name: pypi" in workflow
    assert "id-token: write" in workflow
    assert "release-please-config.json" in workflow


@pytest.mark.parametrize(
    "message",
    [
        "feat(audit): flag jku header pointing to non-https URL",
        "fix: handle empty wordlist",
        "security(crypto): compare MACs in constant time",
        "refactor(core)!: split decoder into parser and encoder modules",
        "build(deps-dev): bump ruff from 0.17.5 to 0.17.6",
        "chore(release): v1.3.0",
        "docs(readme): add JWKS verification example\n\nLonger body text.\n",
        "Merge pull request #54 from KhaledSaeed18/dependabot/uv/python",
        'Revert "feat: something"',
        "fix(cli): drop styles\n# Please enter the commit message for your changes.\n",
    ],
)
def test_valid_messages(message):
    assert checker.problems(message) == []


@pytest.mark.parametrize(
    ("message", "problem"),
    [
        ("update crack.py", "is not '<type>"),
        ("feature: add thing", "type 'feature'"),
        ("Fix: add thing", "is not '<type>"),
        ("fix(crack) handle empty wordlist", "is not '<type>"),
        ("fix: handle empty wordlist.", "ends with a period"),
        ("fix: " + "x" * 80, "keep it to 72"),
        ("fix: summary\nbody without a blank line", "blank line"),
        ("", "empty"),
    ],
)
def test_invalid_messages(message, problem):
    found = checker.problems(message)
    assert any(problem in item for item in found), found


def test_pr_titles_allow_a_higher_limit():
    title = "build(deps): bump astral-sh/setup-uv from 7.6.0 to 10.4.0 in the github-actions group"
    assert checker.problems(title, max_length=100) == []
    assert checker.problems(title) != []


def test_cli_reads_a_commit_message_file(tmp_path, capsys):
    message = tmp_path / "COMMIT_EDITMSG"
    message.write_text("not conventional\n")
    assert checker.main(["--file", str(message)]) == 1
    assert "CONTRIBUTING.md" in capsys.readouterr().err
    message.write_text("fix(cli): keep styles off under NO_COLOR\n")
    assert checker.main(["--file", str(message)]) == 0
    assert checker.main(["--title", "docs: fix typo"]) == 0
