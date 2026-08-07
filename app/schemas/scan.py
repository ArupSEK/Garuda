import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

PORT_SPEC = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")
HOSTNAME = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)


class ScanCreate(BaseModel):
    engagement_id: str
    targets: list[str] = Field(min_length=1)
    profile: Literal["quick", "standard", "full", "custom"] = "quick"
    authorized: bool
    initiated_by: str = Field(min_length=1, max_length=200)
    rate_limit: int = Field(100, ge=1, le=1000)
    timeout: int = Field(1800, ge=10, le=86400)
    enable_udp: bool = False
    enable_tls: bool = True
    enable_ssh: bool = True
    enable_screenshots: bool = False
    nuclei_severity: str = Field("info,low,medium,high,critical", pattern=r"^[a-z,]+$")
    hostnames: dict[str, str] = Field(default_factory=dict)
    tcp_ports: str | None = None
    udp_ports: list[int] = Field(default_factory=list, max_length=64)
    host_timeout: int = Field(900, ge=30, le=3600)
    concurrency: int = Field(2, ge=1, le=20)
    discovery_mode: Literal["assume-up", "icmp", "tcp"] = "assume-up"
    enable_os_detection: bool = False
    enable_snmp_default_community: bool = False

    @field_validator("tcp_ports")
    @classmethod
    def validate_tcp_ports(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        compact = value.replace(" ", "")
        if not PORT_SPEC.fullmatch(compact):
            raise ValueError("TCP ports must be comma-separated ports or ranges")
        for item in compact.split(","):
            bounds = [int(part) for part in item.split("-")]
            if any(port < 1 or port > 65535 for port in bounds) or bounds != sorted(bounds):
                raise ValueError("TCP ports must be between 1 and 65535 with ascending ranges")
        return compact

    @field_validator("udp_ports")
    @classmethod
    def validate_udp_ports(cls, values: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("UDP ports must be between 1 and 65535")
        return sorted(set(values))

    @field_validator("hostnames")
    @classmethod
    def validate_hostnames(cls, values: dict[str, str]) -> dict[str, str]:
        cleaned: dict[str, str] = {}
        for ip, hostname in values.items():
            name = hostname.strip().rstrip(".")
            if not HOSTNAME.fullmatch(name):
                raise ValueError(f"Invalid hostname associated with {ip}")
            cleaned[ip.strip()] = name.lower()
        return cleaned

    @field_validator("nuclei_severity")
    @classmethod
    def validate_nuclei_severity(cls, value: str) -> str:
        allowed = {"info", "low", "medium", "high", "critical"}
        selected = list(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))
        if not selected or not set(selected) <= allowed:
            raise ValueError("Nuclei severity must contain only approved severity names")
        return ",".join(selected)

    @model_validator(mode="after")
    def custom_options_are_bounded(self):
        if self.profile != "custom" and self.tcp_ports is not None:
            raise ValueError("Custom TCP ports are accepted only by the custom profile")
        if self.profile == "quick" and (self.enable_udp or self.udp_ports):
            raise ValueError("Quick Discovery does not support UDP scanning")
        if self.profile == "custom" and self.enable_udp and not self.udp_ports:
            raise ValueError("Custom UDP scanning requires an explicit approved UDP port list")
        return self


class ScanUpdate(BaseModel):
    status: str | None = None
