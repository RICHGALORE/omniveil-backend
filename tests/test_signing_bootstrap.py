import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization

from app.services.crypto_signing import load_private_key, load_public_key
from scripts.generate_production_signing_keys import (
    build_signing_bundle,
    write_signing_bundle,
)


def test_build_signing_bundle_generates_valid_matching_production_pair():
    bundle = build_signing_bundle()

    assert bundle["OV_SIGNING_KEY_ID"].startswith("OV-ROOT-PROD-")
    assert bundle["OV_SIGNING_KEY_ID"] != "OV-ROOT-DEV-001"

    private_key = load_private_key(bundle["OV_SIGNING_PRIVATE_KEY_B64"])
    public_key = load_public_key(bundle["OV_SIGNING_PUBLIC_KEY_B64"])

    derived = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    observed = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert derived == observed


def test_build_signing_bundle_allows_explicit_stable_key_id():
    bundle = build_signing_bundle(key_id="OV-ROOT-PROD-001")
    assert bundle["OV_SIGNING_KEY_ID"] == "OV-ROOT-PROD-001"


@pytest.mark.parametrize("bad_key_id", ["", "   ", "OV-ROOT-DEV-001"])
def test_build_signing_bundle_rejects_invalid_or_development_key_id(bad_key_id):
    with pytest.raises(ValueError):
        build_signing_bundle(key_id=bad_key_id)


def test_write_signing_bundle_uses_private_permissions_and_refuses_accidental_overwrite(tmp_path):
    output = tmp_path / "keys.json"
    first = write_signing_bundle(output)

    assert output.exists()
    assert "OV_SIGNING_PRIVATE_KEY_B64" in output.read_text()

    if os.name == "posix":
        mode = stat.S_IMODE(output.stat().st_mode)
        assert mode == 0o600

    with pytest.raises(FileExistsError):
        write_signing_bundle(output)

    second = write_signing_bundle(output, force=True)
    assert second["OV_SIGNING_PRIVATE_KEY_B64"] != first["OV_SIGNING_PRIVATE_KEY_B64"]
    assert second["OV_SIGNING_PUBLIC_KEY_B64"] != first["OV_SIGNING_PUBLIC_KEY_B64"]
