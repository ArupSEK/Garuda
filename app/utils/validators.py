"""Small input validators."""

import re

SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")


def require_safe_identifier(value: str) -> str:
    if not SAFE_ID.fullmatch(value):
        raise ValueError("Identifier contains unsupported characters")
    return value
