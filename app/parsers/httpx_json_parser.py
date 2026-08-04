"""Parse ProjectDiscovery httpx JSONL output."""

import json


def parse_httpx_json(text: str) -> list[dict]:
    results = []
    for line in text.splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        results.append(
            {
                "ip": item.get("host") or item.get("a", [None])[0],
                "url": item.get("url"),
                "port": item.get("port"),
                "status_code": item.get("status_code"),
                "title": item.get("title"),
                "server": item.get("webserver"),
                "technologies": item.get("tech", []),
                "content_type": item.get("content_type"),
                "content_length": item.get("content_length"),
                "tls": item.get("tls"),
                "cdn": item.get("cdn"),
            }
        )
    return results
