"""Evidence redaction."""

import re

PATTERNS = [
    (re.compile(r"(?im)^(authorization|proxy-authorization|cookie|set-cookie):\s*.+$"), r"\1: [REDACTED]"),
    (re.compile(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*([^\s,;]+)"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
]


def redact(value: str | None) -> str:
    output = value or ""
    for pattern, replacement in PATTERNS:
        output = pattern.sub(replacement, output)
    return output[:100_000]
