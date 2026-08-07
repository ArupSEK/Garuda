"""Environment-backed application settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, model_validator
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
    httpx_path: str = "httpx-pd"
    nuclei_path: str = "nuclei"
    nuclei_templates_path: Path = Path("/home/scanner/nuclei-templates")
    testssl_path: str = "testssl.sh"
    ssh_audit_path: str = "ssh-audit"
    dnsx_path: str = "dnsx"
    gowitness_path: str = "gowitness"
    scanner_versions: str = ""
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    cisa_kev_cache_path: Path = Path("data/cisa_kev.json")
    intelligence_refresh_hours: int = Field(24, ge=1, le=168)
    intelligence_timeout: int = Field(15, ge=2, le=60)
    retention_days: int = Field(365, ge=1, le=3650)

    @model_validator(mode="after")
    def production_secret_is_strong(self):
        insecure = {
            "development-only-change-me",
            "replace-with-a-long-random-secret",
        }
        if self.environment.lower() == "production" and (
            self.secret_key in insecure or len(self.secret_key) < 32
        ):
            raise ValueError("Production SECRET_KEY must be a random value of at least 32 characters")
        return self

    def ensure_directories(self) -> None:
        """Create runtime storage directories."""
        for directory in (Path("data"), self.evidence_dir, self.report_dir, Path("logs")):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
