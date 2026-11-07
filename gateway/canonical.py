"""Canonical form and hash of an MCP tool descriptor.

Two descriptors that differ only in key order, JSON spacing, unicode
normalization form, or surrounding whitespace get the same hash. Any real
change in name, description, or input schema gets a different hash.

A hash change means "changed", never "malicious".
"""

import hashlib
import json
import unicodedata


def _normalize_text(value: str) -> str:
    value = unicodedata.normalize("NFC", value)
    return " ".join(value.split())


def _normalize(obj):
    if isinstance(obj, str):
        return _normalize_text(obj)
    if isinstance(obj, dict):
        return {str(k): _normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize(v) for v in obj]
    return obj


def canonicalize(descriptor: dict) -> str:
    """Return the canonical JSON string for a tool descriptor."""
    core = {
        "name": descriptor.get("name", ""),
        "description": descriptor.get("description", ""),
        "inputSchema": descriptor.get("inputSchema", {}),
    }
    return json.dumps(_normalize(core), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def descriptor_hash(descriptor: dict) -> str:
    """SHA-256 hex digest of the canonical descriptor."""
    return hashlib.sha256(canonicalize(descriptor).encode("utf-8")).hexdigest()
