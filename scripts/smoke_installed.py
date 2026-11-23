"""Smoke-test an installed jwt-toolkit through its console entry point.

Run with the interpreter of the environment the package was installed into, in
isolated mode so the source tree can never be imported by accident:

    <venv>/bin/python -I scripts/smoke_installed.py --version 1.2.1

Only the standard library and the package's own runtime dependencies are used.
"""

import argparse
import json
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from collections.abc import Sequence
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# The bundled wordlist contains this entry, so a token signed with it can only be
# cracked when the wordlist really shipped inside the package.
BUNDLED_WORD = "password123"


class SmokeError(Exception):
    pass


def find_entry_point() -> str:
    scripts_dir = sysconfig.get_path("scripts")
    exe = shutil.which("jwt-toolkit", path=scripts_dir)
    if exe is None:
        raise SmokeError(f"no jwt-toolkit entry point in {scripts_dir}")
    return exe


class Cli:
    def __init__(self, exe: str, workdir: Path) -> None:
        self.exe = exe
        self.workdir = workdir

    def run(self, args: Sequence[str], *, expect: Sequence[int] = (0,)) -> str:
        cmd = [self.exe, "--no-banner", "--no-color", *args]
        result = subprocess.run(
            cmd,
            cwd=self.workdir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=120,
            check=False,
        )
        # Name the subcommand and its flags only; positional tokens and paths stay out of logs.
        label = " ".join(a for a in args if a.startswith("-") or a == args[0])
        if result.returncode not in expect:
            raise SmokeError(
                f"'{label}' exited {result.returncode}, expected {list(expect)}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        print(f"ok  {label} (exit {result.returncode})")
        return result.stdout


def check_version(cli: Cli, expected: str) -> None:
    out = cli.run(["--version"])
    if expected not in out:
        raise SmokeError(f"--version printed {out.strip()!r}, expected {expected}")


def check_help(cli: Cli) -> None:
    out = cli.run(["--help"])
    for command in ("decode", "audit", "verify", "sign", "crack"):
        if command not in out:
            raise SmokeError(f"--help does not list {command}")


def sign_hmac(cli: Cli, secret_file: Path) -> str:
    token = cli.run(
        ["sign", "--payload", '{"sub":"smoke"}', "--secret-file", str(secret_file)]
    ).strip()
    if token.count(".") != 2:
        raise SmokeError(f"sign did not print a JWT: {token!r}")
    return token


def check_hmac_round_trip(cli: Cli, workdir: Path) -> None:
    secret = workdir / "hs256.secret"
    secret.write_text("synthetic-smoke-secret-0123456789abcdef")
    wrong = workdir / "wrong.secret"
    wrong.write_text("a-different-synthetic-secret-fedcba987654")
    token = sign_hmac(cli, secret)
    cli.run(["verify", token, "--secret-file", str(secret)])
    cli.run(["verify", token, "--secret-file", str(wrong)], expect=(1,))


def check_rsa_round_trip(cli: Cli, workdir: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = workdir / "rsa.pem"
    public_pem = workdir / "rsa.pub.pem"
    private_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_pem.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    token = cli.run(
        ["sign", "--payload", '{"sub":"smoke"}', "--private-key", str(private_pem)]
    ).strip()
    cli.run(["verify", token, "--public-key", str(public_pem)])


def check_audit_json(cli: Cli, workdir: Path) -> None:
    secret = workdir / "audit.secret"
    secret.write_text("synthetic-smoke-secret-0123456789abcdef")
    token = sign_hmac(cli, secret)
    # A token without exp is graded down, so a finding (exit 1) is expected too.
    document = json.loads(cli.run(["audit", "--json", token], expect=(0, 1)))
    if "schema_version" not in document:
        raise SmokeError("audit --json has no schema_version")


def check_bundled_wordlist(cli: Cli, workdir: Path) -> None:
    secret = workdir / "weak.secret"
    secret.write_text(BUNDLED_WORD)
    token = sign_hmac(cli, secret)
    # No WORDLIST argument: crack must fall back to the list bundled in the package.
    # Exit 1 means the secret was found.
    document = json.loads(cli.run(["crack", token, "--json"], expect=(1,)))
    if document.get("found") is not True:
        raise SmokeError("crack did not find a secret from the bundled wordlist")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="version the package must report")
    parser.add_argument(
        "--quick", action="store_true", help="only --version and the bundled wordlist"
    )
    args = parser.parse_args(argv)

    try:
        exe = find_entry_point()
        print(f"entry point: {exe}")
        with tempfile.TemporaryDirectory(prefix="jwt-toolkit-smoke-") as tmp:
            workdir = Path(tmp)
            cli = Cli(exe, workdir)
            check_version(cli, args.version)
            if not args.quick:
                check_help(cli)
                check_hmac_round_trip(cli, workdir)
                check_rsa_round_trip(cli, workdir)
                check_audit_json(cli, workdir)
            check_bundled_wordlist(cli, workdir)
    except SmokeError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    print("installed package smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
