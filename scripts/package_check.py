"""Build jwt-toolkit, check both artifacts, and smoke-test them once installed.

    uv run python scripts/package_check.py [--keep-venv DIR]

Steps:
1. Validate pyproject.toml and build the sdist and wheel into a temporary folder.
2. Check what each artifact contains (required files present, private files absent).
3. twine check --strict on both.
4. Install the wheel into a fresh venv outside the repository and run
   scripts/smoke_installed.py with that venv's interpreter in isolated mode.
5. Build a wheel from the sdist alone, install it the same way, and run the quick
   smoke test, which proves the sdist is complete.

--keep-venv puts the wheel's venv at DIR and keeps it, so CI can run more tools
(cliprobe) against the installed entry point.
"""

import argparse
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SMOKE = ROOT / "scripts" / "smoke_installed.py"
WORDLIST = "wordlists/common-secrets.txt"
ENTRY_POINT = "jwt-toolkit = jwt_toolkit.cli:cli"

# Never shipped in either artifact: agent instructions and private planning notes.
PRIVATE_PARTS = {".claude", ".project-planning", ".venv", "__pycache__"}
PRIVATE_NAMES = {"CLAUDE.md", ".env"}
# The sdist keeps tests/ for distro packagers; the wheel only carries the package.
WHEEL_TOP_LEVEL = {"jwt_toolkit"}


class CheckError(Exception):
    pass


def run(cmd: Sequence[str | Path], *, cwd: Path | None = None) -> None:
    printable = " ".join(str(part) for part in cmd)
    print(f"$ {printable}", flush=True)
    result = subprocess.run([str(part) for part in cmd], cwd=cwd, check=False)
    if result.returncode != 0:
        raise CheckError(f"command failed with exit {result.returncode}: {printable}")


def project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        version: str = tomllib.load(fh)["project"]["version"]
    return version


def private_entries(names: Iterable[str]) -> list[str]:
    bad = []
    for name in names:
        parts = PurePosixPath(name).parts
        if PRIVATE_PARTS.intersection(parts) or parts[-1] in PRIVATE_NAMES:
            bad.append(name)
    return bad


def check_wheel(wheel: Path, version: str) -> None:
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        dist_info = f"jwt_toolkit-{version}.dist-info"
        required = [
            f"jwt_toolkit/{WORDLIST}",
            "jwt_toolkit/py.typed",
            "jwt_toolkit/cli/__init__.py",
            f"{dist_info}/entry_points.txt",
            f"{dist_info}/licenses/LICENSE",
        ]
        missing = [name for name in required if name not in names]
        if missing:
            raise CheckError(f"wheel is missing {missing}")
        if ENTRY_POINT not in zf.read(f"{dist_info}/entry_points.txt").decode():
            raise CheckError(f"wheel entry points do not declare '{ENTRY_POINT}'")
        if zf.read(f"jwt_toolkit/{WORDLIST}") != (ROOT / WORDLIST).read_bytes():
            raise CheckError("wheel wordlist differs from wordlists/common-secrets.txt")
    stray = sorted(
        {n.split("/")[0] for n in names} - WHEEL_TOP_LEVEL - {f"jwt_toolkit-{version}.dist-info"}
    )
    if stray:
        raise CheckError(f"wheel has unexpected top-level entries {stray}")
    if bad := private_entries(names):
        raise CheckError(f"wheel contains private files {bad}")
    print(f"ok  wheel contents ({len(names)} entries)")


def check_sdist(sdist: Path, version: str) -> None:
    prefix = f"jwt_toolkit-{version}/"
    with tarfile.open(sdist) as tf:
        names = [m.name.removeprefix(prefix) for m in tf.getmembers() if m.isfile()]
    required = ["pyproject.toml", "PKG-INFO", "LICENSE", "README.md", WORDLIST]
    missing = [name for name in required if name not in names]
    if missing:
        raise CheckError(f"sdist is missing {missing}")
    if not any(name.startswith("jwt_toolkit/") for name in names):
        raise CheckError("sdist has no jwt_toolkit/ package")
    if bad := private_entries(names):
        raise CheckError(f"sdist contains private files {bad}")
    print(f"ok  sdist contents ({len(names)} files)")


def venv_python(venv: Path) -> Path:
    if sys.platform == "win32":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def install_and_smoke(wheel: Path, venv: Path, version: str, *, quick: bool) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise CheckError("uv is not on PATH")
    run([uv, "venv", "--quiet", "--clear", "--python", sys.executable, venv])
    python = venv_python(venv)
    run([uv, "pip", "install", "--quiet", "--python", python, wheel])
    smoke: list[str | Path] = [python, "-I", SMOKE, "--version", version]
    if quick:
        smoke.append("--quick")
    # cwd is the venv, never the repository, so nothing can import the source tree.
    run(smoke, cwd=venv)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-venv", type=Path, help="install the wheel here and keep it")
    args = parser.parse_args(argv)
    version = project_version()

    try:
        with tempfile.TemporaryDirectory(prefix="jwt-toolkit-pkg-") as tmp:
            work = Path(tmp)
            dist = work / "dist"
            run([sys.executable, "-m", "validate_pyproject", ROOT / "pyproject.toml"])
            run(["uv", "build", "--quiet", "--out-dir", dist, ROOT])
            wheel = next(dist.glob("*.whl"))
            sdist = next(dist.glob("*.tar.gz"))
            check_wheel(wheel, version)
            check_sdist(sdist, version)
            run([sys.executable, "-m", "twine", "check", "--strict", wheel, sdist])

            wheel_venv = args.keep_venv.resolve() if args.keep_venv else work / "wheel-env"
            install_and_smoke(wheel, wheel_venv, version, quick=False)

            from_sdist = work / "from-sdist"
            run(["uv", "build", "--quiet", "--wheel", "--out-dir", from_sdist, sdist])
            sdist_wheel = next(from_sdist.glob("*.whl"))
            check_wheel(sdist_wheel, version)
            install_and_smoke(sdist_wheel, work / "sdist-env", version, quick=True)
    except CheckError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print(f"package check passed for jwt-toolkit {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
