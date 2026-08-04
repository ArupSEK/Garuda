"""Parse Naabu JSONL output."""

import json


def parse_naabu_json(text: str) -> list[dict]:
    results = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        results.append(
            {"ip": item.get("ip") or item.get("host"), "port": int(item["port"]), "transport": "tcp"}
        )
    return results
