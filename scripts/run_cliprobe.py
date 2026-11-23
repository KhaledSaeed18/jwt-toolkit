"""Run cliprobe against the jwt-toolkit installed in a venv.

    uv run python scripts/run_cliprobe.py VENV [--strict]

VENV is a venv made by `scripts/package_check.py --keep-venv VENV`. cliprobe
(https://www.npmjs.com/package/cliprobe) checks closed pipes, color in pipes and
under NO_COLOR, escape codes, stdin hangs and terminal restore. It needs Node 22.12+.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

# Pinned so a new cliprobe release cannot turn CI red on its own; bump on purpose.
CLIPROBE = "cliprobe@1.4.2"


def entry_point(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "jwt-toolkit.exe"
    return venv / "bin" / "jwt-toolkit"


def synthetic_token(exe: Path, workdir: Path) -> str:
    secret = workdir / "cliprobe.secret"
    secret.write_text("synthetic-cliprobe-secret-0123456789abcdef")
    result = subprocess.run(
        [
            str(exe),
            "--no-banner",
            "sign",
            "--payload",
            '{"sub":"cliprobe"}',
            "--expires-in",
            "1h",
            "--secret-file",
            str(secret),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("venv", type=Path)
    parser.add_argument("--strict", action="store_true", help="fail on warnings too")
    args = parser.parse_args(argv)

    exe = entry_point(args.venv.resolve())
    npx = shutil.which("npx")
    if not exe.exists():
        print(f"no jwt-toolkit entry point at {exe}", file=sys.stderr)
        return 2
    if npx is None:
        print("npx not found; cliprobe needs Node 22.12 or newer", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="jwt-toolkit-cliprobe-") as tmp:
        token = synthetic_token(exe, Path(tmp))
        cmd = [npx, "--yes", CLIPROBE]
        for probe in (f"decode {token}", f"audit {token}", f"audit --json {token}"):
            cmd += ["--probe", probe]
        if args.strict:
            cmd.append("--strict")
        cmd += ["--", str(exe)]
        return subprocess.run(cmd, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
