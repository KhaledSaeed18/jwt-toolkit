"""Community files GitHub's community profile checks for: present and linked."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "name", ["CODE_OF_CONDUCT.md", "ACCESSIBILITY.md", "CONTRIBUTING.md", "SECURITY.md", "LICENSE"]
)
def test_community_file_exists(name):
    assert (ROOT / name).is_file()


@pytest.mark.parametrize("name", ["CODE_OF_CONDUCT.md", "ACCESSIBILITY.md"])
def test_readme_and_contributing_link_the_community_files(name):
    assert name in (ROOT / "README.md").read_text(encoding="utf-8")
    assert name in (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")


def test_accessibility_statement_points_at_its_issue_form():
    statement = (ROOT / "ACCESSIBILITY.md").read_text(encoding="utf-8")
    assert "template=accessibility.yml" in statement
    assert (ROOT / ".github" / "ISSUE_TEMPLATE" / "accessibility.yml").is_file()
