"""C2PA / Content Credentials interoperability for Omni Veil.

V1 is intentionally read-only: it validates and normalizes an existing C2PA
manifest into an explainable evidence signal. Omni Veil does not reinterpret a
C2PA manifest as proof of authorship or ownership, and does not collapse C2PA
status into the overall Trust Score yet.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ENGINE_NAME = "Omni Veil C2PA Intelligence"
ENGINE_VERSION = "1.0.0"
SDK_PACKAGE = "c2pa-python"
SDK_VERSION = "0.37.7"


def _load_sdk():
    import c2pa

    return c2pa


def _json_object(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _status_items(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    items: list[dict] = []
    for item in value:
        if isinstance(item, str):
            items.append({"code": item})
        elif isinstance(item, dict):
            items.append({
                key: item.get(key)
                for key in ("code", "success", "explanation", "url")
                if item.get(key) is not None
            })
    return items


def _collect_validation_status(store: dict, active: dict) -> list[dict]:
    collected: list[dict] = []
    collected.extend(_status_items(store.get("validation_status")))
    collected.extend(_status_items(active.get("validation_status")))

    for container in (store.get("validation_results"), active.get("validation_results")):
        if not isinstance(container, dict):
            continue
        active_manifest = container.get("activeManifest") or container.get("active_manifest")
        if isinstance(active_manifest, dict):
            collected.extend(_status_items(active_manifest.get("success")))
            collected.extend(_status_items(active_manifest.get("failure")))
            collected.extend(_status_items(active_manifest.get("informational")))
        elif isinstance(active_manifest, list):
            collected.extend(_status_items(active_manifest))

    deduped: list[dict] = []
    seen: set[tuple] = set()
    for item in collected:
        key = (
            item.get("code"),
            item.get("success"),
            item.get("explanation"),
            item.get("url"),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _actions(active: dict) -> list[str]:
    actions: list[str] = []
    assertions = active.get("assertions")
    if not isinstance(assertions, list):
        return actions
    for assertion in assertions:
        if not isinstance(assertion, dict):
            continue
        label = str(assertion.get("label") or "")
        data = assertion.get("data")
        if "actions" not in label.lower() or not isinstance(data, dict):
            continue
        for action in data.get("actions", []):
            if isinstance(action, dict) and action.get("action"):
                actions.append(str(action["action"]))
    return actions


def _manifest_summary(store: dict) -> dict:
    active_label = store.get("active_manifest") or store.get("activeManifest")
    manifests = store.get("manifests")
    active = manifests.get(active_label, {}) if isinstance(manifests, dict) and active_label else {}
    if not isinstance(active, dict):
        active = {}

    statuses = _collect_validation_status(store, active)
    failures = [item for item in statuses if item.get("success") is False]
    # Many SDK reports only emit validation_status entries for problems. Absence
    # of a failure therefore means "no reported validation errors", not an
    # assertion that the signer is legally or personally trustworthy.
    validation_state = "invalid" if failures else "no_reported_errors"

    ingredients = active.get("ingredients")
    assertions = active.get("assertions")

    return {
        "engine": ENGINE_NAME,
        "engine_version": ENGINE_VERSION,
        "sdk": SDK_PACKAGE,
        "sdk_version": SDK_VERSION,
        "manifest_present": True,
        "active_manifest": active_label,
        "claim_generator": active.get("claim_generator") or active.get("claimGenerator"),
        "title": active.get("title"),
        "format": active.get("format"),
        "instance_id": active.get("instance_id") or active.get("instanceId"),
        "ingredient_count": len(ingredients) if isinstance(ingredients, list) else 0,
        "assertion_count": len(assertions) if isinstance(assertions, list) else 0,
        "actions": _actions(active),
        "validation_state": validation_state,
        "validation_status": statuses,
        "validation_error_count": len(failures),
        "evidence_note": (
            "C2PA validates signed provenance/content bindings. Omni Veil treats it as one evidence source, "
            "not standalone proof of human authorship, ownership, or truth of every assertion."
        ),
    }


def read_c2pa_path(path: str | Path) -> dict:
    asset_path = Path(path)
    if not asset_path.exists() or not asset_path.is_file():
        raise FileNotFoundError(str(asset_path))

    try:
        c2pa = _load_sdk()
    except Exception as exc:
        return {
            "engine": ENGINE_NAME,
            "engine_version": ENGINE_VERSION,
            "sdk": SDK_PACKAGE,
            "sdk_version": SDK_VERSION,
            "manifest_present": None,
            "validation_state": "sdk_unavailable",
            "validation_status": [],
            "validation_error_count": 0,
            "error": f"C2PA SDK unavailable: {type(exc).__name__}",
        }

    try:
        reader = c2pa.Reader(str(asset_path))
        store = _json_object(reader.json())
        active_label = store.get("active_manifest") or store.get("activeManifest")
        manifests = store.get("manifests")
        if not active_label or not isinstance(manifests, dict) or active_label not in manifests:
            return {
                "engine": ENGINE_NAME,
                "engine_version": ENGINE_VERSION,
                "sdk": SDK_PACKAGE,
                "sdk_version": SDK_VERSION,
                "manifest_present": False,
                "validation_state": "not_present",
                "validation_status": [],
                "validation_error_count": 0,
            }
        return _manifest_summary(store)
    except Exception as exc:
        message = str(exc)
        if "ManifestNotFound" in message or "manifest not found" in message.lower():
            return {
                "engine": ENGINE_NAME,
                "engine_version": ENGINE_VERSION,
                "sdk": SDK_PACKAGE,
                "sdk_version": SDK_VERSION,
                "manifest_present": False,
                "validation_state": "not_present",
                "validation_status": [],
                "validation_error_count": 0,
            }
        return {
            "engine": ENGINE_NAME,
            "engine_version": ENGINE_VERSION,
            "sdk": SDK_PACKAGE,
            "sdk_version": SDK_VERSION,
            "manifest_present": None,
            "validation_state": "read_error",
            "validation_status": [],
            "validation_error_count": 0,
            "error": f"{type(exc).__name__}: {message[:240]}",
        }
