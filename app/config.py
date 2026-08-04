"""Environment-backed application settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated runtime configuration."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = "development"
    database_url: str = "sqlite:///./data/garuda.db"
    secret_key: str = "development-only-change-me"
    access_token_minutes: int = 480
    max_cidr_prefix: int = Field(24, ge=8, le=32)
    max_targets: int = Field(256, ge=1, le=4096)
    scan_concurrency: int = Field(2, ge=1, le=10)
    default_rate_limit: int = Field(100, ge=1, le=1000)
    command_timeout: int = Field(1800, ge=10, le=86400)
    evidence_dir: Path = Path("evidence")
    report_dir: Path = Path("reports")
    log_level: str = "INFO"
    nmap_path: str = "nmap"
    naabu_path: str = "naabu"
    httpx_path: str = "httpx"
    nuclei_path: str = "nuclei"
    testssl_path: str = "testssl.sh"
    ssh_audit_path: str = "ssh-audit"
    dnsx_path: str = "dnsx"
    gowitness_path: str = "gowitness"

    def ensure_directories(self) -> None:
        """Create runtime storage directories."""
        for directory in (Path("data"), self.evidence_dir, self.report_dir, Path("logs")):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
