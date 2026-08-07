"""Read-only, non-secret runtime configuration and dependency posture."""

import shutil
from pathlib import Path

import yaml
from fastapi import APIRouter, Depends

from app.config import get_settings
from app.core.security import current_user
from app.models import User

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _available(executable: str) -> bool:
    return bool(shutil.which(executable) or Path(executable).is_file())


@router.get("")
def runtime_settings(_: User = Depends(current_user)) -> dict:
    settings = get_settings()
    nmap_policy = yaml.safe_load(Path("config/nmap_scripts.yaml").read_text(encoding="utf-8"))
    nuclei_policy = yaml.safe_load(Path("config/nuclei_policy.yaml").read_text(encoding="utf-8"))
    tools = {
        "nmap": settings.nmap_path,
        "naabu": settings.naabu_path,
        "httpx": settings.httpx_path,
        "nuclei": settings.nuclei_path,
        "testssl.sh": settings.testssl_path,
        "ssh-audit": settings.ssh_audit_path,
        "dnsx": settings.dnsx_path,
        "gowitness": settings.gowitness_path,
    }
    return {
        "environment": settings.environment,
        "limits": {
            "maximum_cidr": f"/{settings.max_cidr_prefix}",
            "maximum_targets": settings.max_targets,
            "scan_concurrency": settings.scan_concurrency,
            "default_rate_limit": settings.default_rate_limit,
            "command_timeout": settings.command_timeout,
        },
        "paths": {
            "nuclei_templates": str(settings.nuclei_templates_path),
            "evidence": str(settings.evidence_dir),
            "reports": str(settings.report_dir),
        },
        "retention_days": settings.retention_days,
        "logging_level": settings.log_level,
        "tools": {
            name: {"path": path, "available": _available(path)} for name, path in tools.items()
        },
        "approved_nse_scripts": nmap_policy["nmap"]["allowed_scripts"],
        "blocked_nse_categories": nmap_policy["nmap"]["blocked_categories"],
        "nuclei_policy": nuclei_policy["nuclei"],
    }
