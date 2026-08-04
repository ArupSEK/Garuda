"""Parse Nmap XML without resolving external entities."""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def parse_nmap_xml(source: str | Path) -> dict[str, Any]:
    text = Path(source).read_text(encoding="utf-8") if isinstance(source, Path) else source
    root = ET.fromstring(text)
    assets: list[dict[str, Any]] = []
    for host in root.findall("host"):
        address_node = host.find("address[@addrtype='ipv4']")
        if address_node is None:
            continue
        hostname_node = host.find("hostnames/hostname")
        status_node = host.find("status")
        asset = {
            "ip": address_node.get("addr", ""),
            "hostname": hostname_node.get("name") if hostname_node is not None else None,
            "reachability": status_node.get("state", "unknown") if status_node is not None else "unknown",
            "os": None,
            "services": [],
        }
        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            asset["os"] = osmatch.get("name")
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            scripts = {node.get("id", ""): node.get("output", "") for node in port.findall("script")}
            asset["services"].append(
                {
                    "port": int(port.get("portid", "0")),
                    "transport": port.get("protocol", "tcp"),
                    "protocol": service.get("name", "unknown") if service is not None else "unknown",
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "cpe": [node.text for node in port.findall("service/cpe") if node.text],
                    "banner": scripts.get("banner"),
                    "scripts": scripts,
                    "confidence": "high"
                    if service is not None and service.get("method") == "probed"
                    else "potential",
                    "source_scanner": "nmap",
                }
            )
        assets.append(asset)
    return {"assets": assets}
