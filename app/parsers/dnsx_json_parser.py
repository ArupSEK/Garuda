"""Parse dnsx JSONL output."""

import json


def parse_dnsx_json(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]
