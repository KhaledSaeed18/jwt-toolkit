import json

from jwt_toolkit.cli import cli
from jwt_toolkit.core.forge import (
    ALL_VARIANT_NAMES,
    KEY_BASED_VARIANT_NAMES,
    STATIC_VARIANT_NAMES,
)
from tests.helpers import make_token


def invoke(runner, *args):
    return runner.invoke(cli, ["forge", *args])


def _token() -> str:
    return make_token({"sub": "alice", "exp": 9999999999})


# Happy paths


def test_forge_without_key_emits_static_variants_only(runner):
    result = invoke(runner, _token(), "--json")
    assert result.exit_code == 0
    data = json.loads(result.output)
    names = [v["name"] for v in data["variants"]]
    assert names == list(STATIC_VARIANT_NAMES)
    assert data["public_key_supplied"] is False


def test_forge_with_public_key_includes_hs_rs_confusion(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(kp.public_pem)
    result = invoke(runner, _token(), "--public-key", str(pub), "--json")
    assert result.exit_code == 0
    data = json.loads(result.output)
    names = [v["name"] for v in data["variants"]]
    assert names == list(ALL_VARIANT_NAMES)
    assert data["public_key_supplied"] is True
    confusion = next(v for v in data["variants"] if v["name"] == "hs_rs_confusion")
    assert confusion["cve"] == "CVE-2016-10555"


def test_forge_mode_emits_single_variant(runner):
    result = invoke(runner, _token(), "--mode", "alg_none_lower", "--json")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data["variants"]) == 1
    assert data["variants"][0]["name"] == "alg_none_lower"


def test_forge_mode_for_key_based_without_pem_exits_2(runner):
    result = invoke(runner, _token(), "--mode", "hs_rs_confusion")
    assert result.exit_code == 2


def test_forge_mode_for_key_based_with_pem_succeeds(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(kp.public_pem)
    result = invoke(
        runner, _token(), "--mode", "hs_rs_confusion", "--public-key", str(pub), "--json"
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["variants"][0]["name"] == "hs_rs_confusion"


def test_forge_unknown_mode_exits_2(runner):
    # Click validates the --mode value against the registered choices.
    result = invoke(runner, _token(), "--mode", "nope")
    assert result.exit_code == 2


def test_forge_malformed_token_exits_2(runner):
    result = invoke(runner, "not.a.jwt")
    assert result.exit_code == 2


def test_forge_emits_three_part_tokens(runner):
    result = invoke(runner, _token(), "--json")
    data = json.loads(result.output)
    for v in data["variants"]:
        assert v["token"].count(".") == 2


def test_forge_json_metadata_fields_present(runner):
    result = invoke(runner, _token(), "--json")
    data = json.loads(result.output)
    assert data["intent"] == "defensive_test_cases"
    assert "expected_outcome" in data
    assert data["schema_version"] == "0.1"


# Static variant set sanity — every name registered in the core module
# is reachable from the CLI when --mode is used explicitly.


def test_every_registered_variant_is_reachable_via_mode(runner, tmp_path, keypair_for):
    kp = keypair_for("RS256")
    pub = tmp_path / "pub.pem"
    pub.write_bytes(kp.public_pem)
    for name in ALL_VARIANT_NAMES:
        args = [_token(), "--mode", name, "--json"]
        if name in KEY_BASED_VARIANT_NAMES:
            args += ["--public-key", str(pub)]
        result = invoke(runner, *args)
        assert result.exit_code == 0, f"forge --mode {name} failed: {result.output}"
        data = json.loads(result.output)
        assert data["variants"][0]["name"] == name


def test_json_marks_header_only_variants(runner, valid_token):
    result = runner.invoke(cli, ["forge", valid_token, "--json"])
    variants = {v["name"]: v for v in json.loads(result.output)["variants"]}
    assert variants["jwk_embedded"]["header_only"] is True
    assert variants["alg_none_lower"]["header_only"] is False


def test_forge_key_based_mode_without_pem_is_json_under_json_flag(runner):
    result = invoke(runner, _token(), "--mode", "hs_rs_confusion", "--json")
    assert result.exit_code == 2
    assert json.loads(result.stdout)["error"] == "invalid_key_options"


def test_forge_rejects_a_private_key_as_public_key(runner, tmp_path, keypair_for):
    pem = tmp_path / "private.pem"
    pem.write_bytes(keypair_for("RS256").private_pem)
    result = invoke(runner, _token(), "--public-key", str(pem))
    assert result.exit_code == 2
    assert "holds a private key" in result.stderr
    assert "BEGIN" not in result.output
