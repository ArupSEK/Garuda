#!/usr/bin/env python3
"""Download and validate the CISA KEV catalog into Garuda's local cache."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx

from app.services.intelligence_service import CISA_KEV_SOURCE, KevEntry


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("data/cisa_kev.json"))
    parser.add_argument("--url", default=CISA_KEV_SOURCE)
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser.parse_args()


def validate_catalog(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("KEV catalog must be a JSON object")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise ValueError("KEV catalog contains no vulnerability records")
    valid = sum(
        1
        for item in vulnerabilities
        if isinstance(item, dict) and KevEntry.from_mapping(item) is not None
    )
    if valid != len(vulnerabilities):
        raise ValueError(f"KEV catalog contains invalid records: valid={valid} total={len(vulnerabilities)}")
    return payload


def main() -> int:
    args = parse_args()
    try:
        response = httpx.get(
            args.url,
            timeout=args.timeout,
            follow_redirects=True,
            headers={"User-Agent": "Garuda-External-VA/1.0"},
        )
        response.raise_for_status()
        payload = validate_catalog(response.json())
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        print(f"KEV synchronization failed: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(args.output)
    print(f"Saved {len(payload['vulnerabilities'])} KEV records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
