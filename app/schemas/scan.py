from typing import Literal

from pydantic import BaseModel, Field


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


class ScanUpdate(BaseModel):
    status: str | None = None
