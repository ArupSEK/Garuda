"""Regression tests for end-user launchers."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_windows_docker_launcher_repairs_env_before_compose() -> None:
    launcher = (PROJECT_ROOT / "start-docker-windows.bat").read_text()

    assert "scripts\\ensure_env.ps1" in launcher
    assert 'docker compose --env-file ".env" up -d --build' in launcher
    assert "ToHexString" not in launcher


def test_windows_env_helper_supports_legacy_windows_powershell() -> None:
    helper = (PROJECT_ROOT / "scripts" / "ensure_env.ps1").read_text()

    assert "RandomNumberGenerator]::Create()" in helper
    assert "BitConverter]::ToString" in helper
    assert "ToHexString" not in helper
    assert "CurrentSecret.Length -lt 32" in helper


def test_linux_docker_launcher_repairs_invalid_secret() -> None:
    launcher = (PROJECT_ROOT / "start-docker-linux.sh").read_text()

    assert '${#CURRENT_SECRET} -lt 32' in launcher
    assert "SECRET_COUNT" in launcher
    assert "docker compose --env-file .env up -d --build" in launcher
