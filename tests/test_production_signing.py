import pytest

from app.services.crypto_signing import (
    generate_ed25519_keypair,
    get_or_create_dev_trust_keypair,
    get_trust_signing_material,
    sign_certificate,
    verify_certificate_signature,
)


def _set_production(monkeypatch, keys=None, key_id="OV-ROOT-PROD-TEST-001"):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("APP_ENV", raising=False)
    if keys:
        monkeypatch.setenv("OV_SIGNING_PRIVATE_KEY_B64", keys["private_key_b64"])
        monkeypatch.setenv("OV_SIGNING_PUBLIC_KEY_B64", keys["public_key_b64"])
    else:
        monkeypatch.delenv("OV_SIGNING_PRIVATE_KEY_B64", raising=False)
        monkeypatch.delenv("OV_SIGNING_PUBLIC_KEY_B64", raising=False)
    if key_id:
        monkeypatch.setenv("OV_SIGNING_KEY_ID", key_id)
    else:
        monkeypatch.delenv("OV_SIGNING_KEY_ID", raising=False)


def test_production_signing_refuses_missing_key_material(monkeypatch):
    _set_production(monkeypatch, keys=None, key_id=None)

    with pytest.raises(RuntimeError, match="Production certificate signing is not configured"):
        get_trust_signing_material()

    # The historical ingest hook must also fail closed in production rather
    # than creating .secrets/ov_root_dev_keypair.json.
    with pytest.raises(RuntimeError, match="Production certificate signing is not configured"):
        get_or_create_dev_trust_keypair()


def test_production_signing_refuses_mismatched_keypair(monkeypatch):
    first = generate_ed25519_keypair()
    second = generate_ed25519_keypair()
    _set_production(
        monkeypatch,
        keys={
            "private_key_b64": first["private_key_b64"],
            "public_key_b64": second["public_key_b64"],
        },
    )

    with pytest.raises(RuntimeError, match="public/private keys do not match"):
        get_trust_signing_material()


def test_production_signing_uses_configured_root_and_overrides_legacy_dev_id(monkeypatch):
    keys = generate_ed25519_keypair()
    _set_production(monkeypatch, keys=keys, key_id="OV-ROOT-PROD-TEST-001")

    material = get_trust_signing_material()
    assert material["environment"] == "production"
    assert material["public_key_id"] == "OV-ROOT-PROD-TEST-001"

    # Current ingest still calls the historical helper and explicitly passes
    # OV-ROOT-DEV-001. Both compatibility paths must remain production-safe.
    ingest_keys = get_or_create_dev_trust_keypair()
    assert ingest_keys == keys

    metadata = {"omni_id": "OV-PROD-TEST", "sha256": "a" * 64}
    signed = sign_certificate(
        certificate={"omni_id": "OV-PROD-TEST", "issuer": "Omni Veil Trust OS"},
        metadata=metadata,
        private_key_b64=ingest_keys["private_key_b64"],
        public_key_b64=ingest_keys["public_key_b64"],
        public_key_id="OV-ROOT-DEV-001",
    )
    assert signed["public_key_id"] == "OV-ROOT-PROD-TEST-001"
    assert signed["signature_algorithm"] == "Ed25519"
    assert verify_certificate_signature(signed, metadata) is True


def test_nonproduction_signing_keeps_persistent_dev_root(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.delenv("OV_SIGNING_PRIVATE_KEY_B64", raising=False)
    monkeypatch.delenv("OV_SIGNING_PUBLIC_KEY_B64", raising=False)
    monkeypatch.delenv("OV_SIGNING_KEY_ID", raising=False)

    path = tmp_path / "dev-root.json"
    first = get_trust_signing_material(dev_path=str(path))
    second = get_trust_signing_material(dev_path=str(path))

    assert first["public_key_id"] == "OV-ROOT-DEV-001"
    assert first["private_key_b64"] == second["private_key_b64"]
    assert first["public_key_b64"] == second["public_key_b64"]
    assert path.exists()
