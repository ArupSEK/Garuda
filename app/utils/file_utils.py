"""Safe file helpers."""

from pathlib import Path


def safe_child(root: Path, name: str) -> Path:
    root = root.resolve()
    candidate = (root / name).resolve()
    if root != candidate and root not in candidate.parents:
        raise ValueError("Path escapes the configured storage directory")
    return candidate
