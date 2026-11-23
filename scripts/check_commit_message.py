"""Check a commit message or PR title against the project's Conventional Commits rules.

    python scripts/check_commit_message.py --file .git/COMMIT_EDITMSG   # commit-msg hook
    python scripts/check_commit_message.py --title "fix(crack): ..."     # PR title in CI

Squash merges use the PR title as the commit message, and release-please reads
those messages to decide the next version, so both are checked with one rule set.
The type list must match CONTRIBUTING.md and release-please-config.json; a test
keeps the three in sync.
"""

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

TYPES = (
    "feat",
    "fix",
    "docs",
    "refactor",
    "test",
    "chore",
    "perf",
    "security",
    "build",
    "ci",
    "style",
    "revert",
)

# Hook limit from CONTRIBUTING.md. Bot PR titles (Dependabot) run longer, so the
# PR-title check passes a higher limit.
DEFAULT_MAX_LENGTH = 72

_HEADER = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[a-z0-9][a-z0-9._/-]*)\))?(?P<breaking>!)?: (?P<summary>\S.*)$"
)
# Messages git writes itself; they never reach main through a squash merge.
_GIT_GENERATED = ("Merge ", 'Revert "', "fixup! ", "squash! ", "amend! ")


def problems(message: str, *, max_length: int = DEFAULT_MAX_LENGTH) -> list[str]:
    lines = [line for line in message.splitlines() if not line.startswith("#")]
    header = lines[0].rstrip() if lines else ""
    if header.startswith(_GIT_GENERATED):
        return []
    if not header:
        return ["the message is empty"]
    match = _HEADER.match(header)
    if match is None:
        return [f"'{header}' is not '<type>(<scope>): <summary>' (scope optional)"]
    found = []
    if match["type"] not in TYPES:
        found.append(f"type '{match['type']}' is not one of: {', '.join(TYPES)}")
    if len(header) > max_length:
        found.append(f"the first line is {len(header)} characters; keep it to {max_length}")
    if header.endswith("."):
        found.append("the summary ends with a period")
    if len(lines) > 1 and lines[1].strip():
        found.append("leave a blank line between the summary and the body")
    return found


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path, help="commit message file (commit-msg hook)")
    source.add_argument("--title", help="a PR title")
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    args = parser.parse_args(argv)

    message = args.file.read_text(encoding="utf-8") if args.file else args.title
    found = problems(message, max_length=args.max_length)
    for problem in found:
        print(f"commit message: {problem}", file=sys.stderr)
    if found:
        print("See CONTRIBUTING.md, 'Commit messages'.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
