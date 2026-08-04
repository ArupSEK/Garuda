import json

from app.parsers.httpx_json_parser import parse_httpx_json
from app.parsers.naabu_json_parser import parse_naabu_json
from app.parsers.nmap_xml_parser import parse_nmap_xml
from app.parsers.nuclei_jsonl_parser import parse_nuclei_jsonl
from app.parsers.ssh_audit_parser import parse_ssh_audit
from app.parsers.testssl_json_parser import parse_testssl_json


def test_nmap_xml_parser():
    xml = """<nmaprun><host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/><hostnames><hostname name="dns.google"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="service" version="1"><cpe>cpe:/a:test</cpe></service></port></ports></host></nmaprun>"""
    result = parse_nmap_xml(xml)["assets"][0]
    assert result["ip"] == "8.8.8.8" and result["services"][0]["port"] == 443


def test_json_parsers():
    assert parse_naabu_json('{"ip":"8.8.8.8","port":53}')[0]["port"] == 53
    assert (
        parse_httpx_json('{"host":"8.8.8.8","url":"https://8.8.8.8","status_code":200}')[0]["status_code"]
        == 200
    )
    nuclei = {
        "ip": "8.8.8.8",
        "matched-at": "https://8.8.8.8/",
        "template-id": "safe-check",
        "matcher-status": True,
        "info": {"name": "Safe check", "severity": "low", "classification": {"cve-id": []}},
    }
    assert parse_nuclei_jsonl(json.dumps(nuclei))[0]["confidence"] == "confirmed"


def test_tls_and_ssh_parsers():
    assert (
        parse_testssl_json(json.dumps([{"id": "TLS1_0", "severity": "WARN", "finding": "offered"}]))[0][
            "severity"
        ]
        == "medium"
    )
    assert (
        parse_ssh_audit(json.dumps({"enc": [{"name": "3des-cbc", "fail": ["weak"]}]}))[0]["severity"]
        == "medium"
    )
