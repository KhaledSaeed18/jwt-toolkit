import jwt_toolkit
from jwt_toolkit.cli import cli


def test_package_exposes_version_used_by_cli(runner):
    result = runner.invoke(cli, ["--version"])
    assert result.output.strip() == f"jwt-toolkit {jwt_toolkit.__version__}"
