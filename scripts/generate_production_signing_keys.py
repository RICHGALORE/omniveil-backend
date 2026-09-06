#!/usr/bin/env python3
"""Generate Omni Veil production Ed25519 Trust Authority signing material.

The private key is written to a local ignored `.secrets` file with restrictive
permissions and is never printed. The resulting JSON uses the exact environment
variable names expected by Render so an operator can transfer the values through
Render's secret/environment UI without committing them to Git.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

from app.services.crypto_signing import (
    generate_ed25519_keypair,
    load_private_key,
    load_public_key,
)

DEFAULT_OUTPUT = Path(".secrets/ov_root_prod_keypair.json")


def _fingerprint(public_key_b64: str) -> str:
    raw = base64.b64decode(public_key_b64, validate=True)
    return hashlib.sha256(raw).hexdigest().upper()


def _default_key_id(public_key_b64: str) -> str:
    return f"OV-ROOT-PROD-{_fingerprint(public_key_b64)[:12]}"


def build_signing_bundle(key_id: str | None = None) -> dict[str, str]:
    keys = generate_ed25519_keypair()
    private_key_b64 = keys["private_key_b64"]
    public_key_b64 = keys["public_key_b64"]

    # Parse both keys and prove they are a matching pair before writing them.
    private_key = load_private_key(private_key_b64)
    load_public_key(public_key_b64)
    derived_public = private_key.public_key().public_bytes_raw()
    if base64.b64encode(derived_public).decode("utf-8") != public_key_b64:
        raise RuntimeError("Generated Ed25519 keypair failed self-validation")

    effective_key_id = (key_id or _default_key_id(public_key_b64)).strip()
    if not effective_key_id or effective_key_id == "OV-ROOT-DEV-001":
        raise ValueError("Production signing key ID must be non-empty and must not use the development key ID")

    return {
        "OV_SIGNING_PRIVATE_KEY_B64": private_key_b64,
        "OV_SIGNING_PUBLIC_KEY_B64": public_key_b64,
        "OV_SIGNING_KEY_ID": effective_key_id,
    }


def write_signing_bundle(
    output: Path,
    *,
    key_id: str | None = None,
    force: bool = False,
) -> dict[str, str]:
    if output.exists() and not force:
        raise FileExistsError(f"Refusing to overwrite existing signing material: {output}")

    output.parent.mkdir(parents=True, exist_ok=True)
    bundle = build_signing_bundle(key_id=key_id)

    # Write through a restrictive descriptor so the private key never spends a
    # moment in a broadly readable file on POSIX systems.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if not force:
        flags |= os.O_EXCL
    fd = os.open(output, flags, 0o600)
    try:
        payload = json.dumps(bundle, indent=2) + "\n"
        os.write(fd, payload.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

    try:
        os.chmod(output, 0o600)
    except OSError:
        # Windows and some mounted filesystems do not implement POSIX modes.
        pass

    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate Omni Veil production Ed25519 Trust Authority signing material without printing the private key."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Secret JSON destination (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--key-id",
        default=None,
        help="Optional stable production key ID. Default is derived from the public-key fingerprint.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rotate/replace an existing local key file. Use only for an intentional Trust Authority rotation.",
    )
    args = parser.parse_args()

    try:
        bundle = write_signing_bundle(args.output, key_id=args.key_id, force=args.force)
    except (FileExistsError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))

    fingerprint = _fingerprint(bundle["OV_SIGNING_PUBLIC_KEY_B64"])
    print(f"Production signing material written securely to: {args.output}")
    print(f"Key ID: {bundle['OV_SIGNING_KEY_ID']}")
    print(f"Public-key SHA-256 fingerprint: {fingerprint}")
    print("Private key was NOT printed. Transfer the three JSON values to Render secrets, then protect the local file as a Trust Authority credential.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
