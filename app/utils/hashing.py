"""Stable finding identifiers."""

import hashlib


def stable_fingerprint(*parts: object) -> str:
    normalized = "|".join(str(part or "").strip().lower() for part in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
