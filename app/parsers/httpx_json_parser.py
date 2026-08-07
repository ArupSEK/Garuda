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
                "cpe": item.get("cpe", []),
                "content_type": item.get("content_type"),
                "content_length": item.get("content_length"),
                "location": item.get("location"),
                "favicon_hash": item.get("favicon"),
                "response_hash": item.get("hash"),
                "response_time": item.get("time"),
                "jarm": item.get("jarm"),
                "tls": item.get("tls"),
                "cdn": item.get("cdn"),
                "cdn_name": item.get("cdn_name"),
                "cname": item.get("cname", []),
                "asn": item.get("asn"),
            }
        )
    return results
