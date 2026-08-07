"""Conservative protocol-specific findings derived from confirmed Nmap evidence."""

from __future__ import annotations

from typing import Any


def _finding(
    asset: dict[str, Any],
    service: dict[str, Any],
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    evidence: str,
    remediation: str,
) -> dict[str, Any]:
    """Build a normalized-input finding without inferring an unverified CVE."""
    return {
        "asset_ip": asset["ip"],
        "hostname": asset.get("hostname"),
        "port": service["port"],
        "transport": service.get("transport", "tcp"),
        "protocol": service.get("protocol", "unknown"),
        "service": service.get("product") or service.get("protocol"),
        "service_version": service.get("version"),
        "cpe": service.get("cpe") or [],
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": "confirmed",
        "confidence_reason": "The service or condition was confirmed by an approved Nmap probe.",
        "scanner": "nmap",
        "scanner_rule_id": rule_id,
        "evidence": evidence,
        "remediation": remediation,
    }


def evaluate_protocol_checks(
    nmap_data: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    """Return safe exposure findings and explicit checklist outcomes.

    These checks use only already-collected Nmap service and allowlisted NSE output.
    They never authenticate, brute-force, modify data, or execute exploits.
    """
    findings: list[dict[str, Any]] = []
    checklist: dict[str, dict[str, str]] = {}
    observed = {
        "ftp": False,
        "ssh": False,
        "telnet": False,
        "smtp": False,
        "dns": False,
        "snmp": False,
        "smb": False,
        "rdp": False,
        "ntp": False,
        "database": False,
        "http": False,
    }

    def record(key: str, status: str, detail: str) -> None:
        checklist[key] = {"status": status, "detail": detail}

    for asset in nmap_data.get("assets", []):
        for service in asset.get("services", []):
            ip = str(asset["ip"])
            port = int(service["port"])
            transport = str(service.get("transport", "tcp")).lower()
            protocol = str(service.get("protocol", "unknown")).lower()
            scripts = {str(k): str(v) for k, v in (service.get("scripts") or {}).items()}
            prefix = f"protocol.{ip}.{transport}.{port}"
            endpoint = f"{ip}:{port}/{transport}"

            if protocol in {"ftp", "ftp-data"} or port == 21:
                observed["ftp"] = True
                findings.append(
                    _finding(
                        asset,
                        service,
                        rule_id="protocol.ftp.cleartext-exposure",
                        title="Clear-text FTP service exposed to the internet",
                        description=(
                            "An externally reachable FTP service can expose credentials and data "
                            "to interception when FTPS is not enforced."
                        ),
                        severity="medium",
                        evidence=f"Nmap confirmed FTP on {endpoint}.",
                        remediation=(
                            "Disable FTP or require a securely configured encrypted alternative "
                            "such as SFTP or FTPS."
                        ),
                    )
                )
                record(f"{prefix}.cleartext", "FAIL", "Externally reachable FTP was confirmed.")
                anonymous = scripts.get("ftp-anon")
                if anonymous and "anonymous ftp login allowed" in anonymous.lower():
                    findings.append(
                        _finding(
                            asset,
                            service,
                            rule_id="protocol.ftp.anonymous-access",
                            title="Anonymous FTP access is enabled",
                            description=(
                                "The approved ftp-anon probe confirmed that the service permits "
                                "anonymous access."
                            ),
                            severity="high",
                            evidence=anonymous,
                            remediation=(
                                "Disable anonymous FTP access and review the exposed content and "
                                "permissions."
                            ),
                        )
                    )
                    record(f"{prefix}.anonymous", "FAIL", "Anonymous FTP access was confirmed.")
                elif anonymous:
                    record(
                        f"{prefix}.anonymous",
                        "PASS",
                        "Anonymous login was not accepted by the safe probe.",
                    )
                else:
                    record(
                        f"{prefix}.anonymous",
                        "NOT TESTED",
                        "The ftp-anon NSE check did not return evidence.",
                    )

            if protocol == "telnet" or port == 23:
                observed["telnet"] = True
                findings.append(
                    _finding(
                        asset,
                        service,
                        rule_id="protocol.telnet.cleartext-exposure",
                        title="Clear-text Telnet service exposed to the internet",
                        description=(
                            "Telnet does not protect authentication or session traffic from "
                            "interception."
                        ),
                        severity="high",
                        evidence=f"Nmap confirmed Telnet on {endpoint}.",
                        remediation=(
                            "Disable Telnet and use a hardened SSH service with restricted network "
                            "access."
                        ),
                    )
                )
                record(f"{prefix}.cleartext", "FAIL", "Externally reachable Telnet was confirmed.")

            if protocol == "ssh" or port == 22:
                observed["ssh"] = True
                record(
                    f"{prefix}.cryptography",
                    "INCONCLUSIVE",
                    "SSH was detected; the separate ssh-audit result determines algorithm posture.",
                )

            if protocol in {"smtp", "submission", "smtps"} or port in {25, 465, 587}:
                observed["smtp"] = True
                record(
                    f"{prefix}.starttls",
                    "INCONCLUSIVE",
                    "SMTP was detected; the separate TLS assessment determines STARTTLS posture.",
                )
                record(
                    f"{prefix}.open-relay",
                    "MANUAL TEST REQUIRED",
                    "Automated relay testing is disabled to avoid transmitting mail.",
                )
                record(
                    f"{prefix}.authentication-methods",
                    "NOT TESTED",
                    "No authentication attempt or user enumeration was performed.",
                )

            if protocol in {"domain", "dns"} or port == 53:
                observed["dns"] = True
                recursion = scripts.get("dns-recursion")
                if recursion and "recursion appears to be enabled" in recursion.lower():
                    findings.append(
                        _finding(
                            asset,
                            service,
                            rule_id="protocol.dns.open-recursion",
                            title="DNS recursion is available externally",
                            description=(
                                "The approved DNS recursion check indicates that the server answers "
                                "recursive queries from the assessment source."
                            ),
                            severity="medium",
                            evidence=recursion,
                            remediation=(
                                "Restrict recursive DNS queries to trusted networks and apply "
                                "response-rate limiting."
                            ),
                        )
                    )
                    record(f"{prefix}.recursion", "FAIL", "External DNS recursion was indicated.")
                elif recursion:
                    record(
                        f"{prefix}.recursion",
                        "PASS",
                        "The safe probe did not confirm external recursion.",
                    )
                else:
                    record(
                        f"{prefix}.recursion",
                        "NOT TESTED",
                        "No dns-recursion NSE result was returned.",
                    )

                transfer = scripts.get("dns-zone-transfer")
                failed_markers = ("failed", "refused", "timed out", "no response")
                if transfer and not any(marker in transfer.lower() for marker in failed_markers):
                    findings.append(
                        _finding(
                            asset,
                            service,
                            rule_id="protocol.dns.zone-transfer",
                            title="DNS zone transfer may be permitted externally",
                            description=(
                                "The approved zone-transfer verification returned data rather than "
                                "a clear refusal. Manual confirmation is recommended."
                            ),
                            severity="medium",
                            evidence=transfer,
                            remediation=(
                                "Restrict AXFR and IXFR to explicitly authorized secondary DNS "
                                "servers."
                            ),
                        )
                    )
                    record(
                        f"{prefix}.zone-transfer",
                        "WARNING",
                        "Zone-transfer output requires analyst confirmation.",
                    )
                elif transfer:
                    record(
                        f"{prefix}.zone-transfer",
                        "PASS",
                        "Zone transfer was refused or did not complete.",
                    )
                else:
                    record(
                        f"{prefix}.zone-transfer",
                        "NOT TESTED",
                        "No zone-transfer NSE result was returned.",
                    )

            if protocol == "snmp" or (port == 161 and transport == "udp"):
                observed["snmp"] = True
                findings.append(
                    _finding(
                        asset,
                        service,
                        rule_id="protocol.snmp.external-exposure",
                        title="SNMP service exposed to the internet",
                        description=(
                            "An externally reachable SNMP service can disclose system information "
                            "and may increase amplification risk."
                        ),
                        severity="medium",
                        evidence=(
                            f"Nmap confirmed SNMP on {endpoint}; no community-string brute force "
                            "was performed."
                        ),
                        remediation=(
                            "Restrict SNMP to management networks, prefer SNMPv3, and remove default "
                            "community strings."
                        ),
                    )
                )
                record(f"{prefix}.exposure", "WARNING", "Externally reachable SNMP was confirmed.")
                snmp_info = scripts.get("snmp-info")
                if snmp_info:
                    findings.append(
                        _finding(
                            asset,
                            service,
                            rule_id="protocol.snmp.default-community-disclosure",
                            title="SNMP information was disclosed to the approved default-community probe",
                            description=(
                                "The allowlisted snmp-info check returned system information without "
                                "community-string brute forcing."
                            ),
                            severity="medium",
                            evidence=snmp_info,
                            remediation=(
                                "Remove default communities, restrict source addresses, and migrate "
                                "to authenticated and encrypted SNMPv3."
                            ),
                        )
                    )
                    record(
                        f"{prefix}.default-community",
                        "FAIL",
                        "The approved default-community probe returned SNMP information.",
                    )
                else:
                    record(
                        f"{prefix}.default-community",
                        "NOT TESTED",
                        "The safe snmp-info check did not return evidence; no brute force was used.",
                    )

            if protocol in {"microsoft-ds", "netbios-ssn", "smb"} or port in {139, 445}:
                observed["smb"] = True
                protocols = scripts.get("smb-protocols", "")
                if "smbv1" in protocols.lower() or "nt lm 0.12" in protocols.lower():
                    findings.append(
                        _finding(
                            asset,
                            service,
                            rule_id="protocol.smb.smbv1-enabled",
                            title="SMBv1 is enabled on an internet-exposed service",
                            description=(
                                "The approved protocol enumeration identified the obsolete SMBv1 "
                                "protocol."
                            ),
                            severity="high",
                            evidence=protocols,
                            remediation=(
                                "Disable SMBv1, require SMBv2 or SMBv3, and restrict SMB at the "
                                "network boundary."
                            ),
                        )
                    )
                    record(f"{prefix}.smbv1", "FAIL", "SMBv1 was identified.")
                elif protocols:
                    record(
                        f"{prefix}.smbv1",
                        "PASS",
                        "SMBv1 was not listed by the protocol check.",
                    )
                else:
                    record(
                        f"{prefix}.smbv1",
                        "NOT TESTED",
                        "No SMB protocol enumeration result was returned.",
                    )
                signing = scripts.get("smb2-security-mode", "")
                if signing and ("not required" in signing.lower() or "disabled" in signing.lower()):
                    findings.append(
                        _finding(
                            asset,
                            service,
                            rule_id="protocol.smb.signing-not-required",
                            title="SMB signing is not required",
                            description=(
                                "The approved SMB security-mode check indicates that message signing "
                                "is not mandatory."
                            ),
                            severity="medium",
                            evidence=signing,
                            remediation=(
                                "Require SMB signing and restrict SMB access to trusted management "
                                "networks."
                            ),
                        )
                    )
                    record(f"{prefix}.signing", "FAIL", "SMB signing is not required.")
                elif signing:
                    record(
                        f"{prefix}.signing",
                        "PASS",
                        "The returned SMB security mode requires signing.",
                    )
                else:
                    record(
                        f"{prefix}.signing",
                        "NOT TESTED",
                        "No SMB signing result was returned.",
                    )
                record(
                    f"{prefix}.guest-access",
                    "NOT TESTED",
                    "No SMB authentication or guest-session attempt was performed.",
                )

            if protocol in {"ms-wbt-server", "rdp"} or port == 3389:
                observed["rdp"] = True
                findings.append(
                    _finding(
                        asset,
                        service,
                        rule_id="protocol.rdp.external-exposure",
                        title="Remote Desktop service exposed to the internet",
                        description=(
                            "Direct internet exposure of RDP increases authentication and "
                            "remote-access risk even when NLA is enabled."
                        ),
                        severity="medium",
                        evidence=f"Nmap confirmed RDP on {endpoint}; no login attempt was made.",
                        remediation=(
                            "Place RDP behind a managed VPN or gateway, require NLA and MFA, and "
                            "restrict source networks."
                        ),
                    )
                )
                record(
                    f"{prefix}.exposure",
                    "WARNING",
                    "Externally reachable RDP was confirmed; NLA requires separate validation.",
                )
                record(
                    f"{prefix}.nla",
                    "MANUAL TEST REQUIRED",
                    "Network Level Authentication was not actively negotiated by Version 1.",
                )

            if protocol == "ntp" or (port == 123 and transport == "udp"):
                observed["ntp"] = True
                record(
                    f"{prefix}.exposure",
                    "WARNING",
                    "Externally reachable NTP was confirmed; review query restrictions.",
                )
                record(
                    f"{prefix}.legacy-query",
                    "INFORMATIONAL" if scripts.get("ntp-info") else "NOT TESTED",
                    "NTP metadata was collected by the approved probe."
                    if scripts.get("ntp-info")
                    else "No approved NTP metadata result was returned.",
                )

            database_ports = {
                1433: "Microsoft SQL Server",
                1521: "Oracle Database",
                2375: "unencrypted Docker API",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis",
                6443: "Kubernetes API",
                9200: "Elasticsearch",
                27017: "MongoDB",
            }
            if port in database_ports:
                observed["database"] = True
                dangerous = port in {2375, 6379, 9200, 27017}
                findings.append(
                    _finding(
                        asset,
                        service,
                        rule_id=f"protocol.service.public-exposure.{port}",
                        title=f"{database_ports[port]} is exposed to the internet",
                        description=(
                            "A sensitive data or management service was confirmed on a public "
                            "interface. Authentication was not attempted."
                        ),
                        severity="high" if dangerous else "medium",
                        evidence=(
                            f"Nmap confirmed {database_ports[port]} on {endpoint}; no login or data "
                            "access was attempted."
                        ),
                        remediation=(
                            "Restrict the service to approved private or management networks and "
                            "enforce encryption and strong authentication."
                        ),
                    )
                )
                record(
                    f"{prefix}.public-exposure",
                    "WARNING",
                    f"{database_ports[port]} is reachable externally.",
                )
                record(
                    f"{prefix}.authentication",
                    "NOT TESTED",
                    "Database authentication was not attempted.",
                )
                record(
                    f"{prefix}.encryption",
                    "INCONCLUSIVE",
                    "Review the Nmap and TLS evidence for supported encryption.",
                )

            methods = scripts.get("http-methods", "")
            if protocol.startswith("http") or port in {80, 443, 8080, 8443}:
                observed["http"] = True
                record(
                    f"{prefix}.security-headers",
                    "INFORMATIONAL" if scripts.get("http-security-headers") else "NOT TESTED",
                    "HTTP security-header evidence was collected."
                    if scripts.get("http-security-headers")
                    else "No HTTP security-header NSE result was returned.",
                )
            risky = [
                method
                for method in ("TRACE", "PUT", "DELETE", "CONNECT")
                if method in methods.upper()
            ]
            if methods and risky:
                findings.append(
                    _finding(
                        asset,
                        service,
                        rule_id="protocol.http.risky-methods",
                        title="Potentially risky HTTP methods are enabled",
                        description=(
                            "The approved HTTP method check advertised methods that commonly require "
                            "additional restriction."
                        ),
                        severity="low",
                        evidence=methods,
                        remediation=(
                            "Disable unnecessary HTTP methods and enforce authorization for any "
                            "methods required by the application."
                        ),
                    )
                )
                record(
                    f"{prefix}.http-methods",
                    "WARNING",
                    f"Advertised methods: {', '.join(risky)}.",
                )

    for protocol, was_observed in observed.items():
        if not was_observed:
            record(
                f"protocol.{protocol}",
                "NOT APPLICABLE",
                f"No confirmed {protocol.upper()} service was in scope.",
            )
    return findings, checklist
