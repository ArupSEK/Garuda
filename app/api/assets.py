"""Asset inventory, details, findings, and authenticated visual evidence."""

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.security import current_user
from app.database import get_db
from app.models import Asset, Finding, User

router = APIRouter(prefix="/api/assets", tags=["assets"])


def serialize(item: Asset) -> dict:
    return {
        "id": item.id,
        "scan_id": item.scan.public_id,
        "ip": item.ip,
        "hostname": item.hostname,
        "reachability": item.reachability,
        "operating_system": item.operating_system,
        "asn": item.asn,
        "risk_score": item.risk_score,
        "last_scanned": item.last_scanned,
        "services": [
            {
                "port": svc.port,
                "transport": svc.transport,
                "protocol": svc.protocol,
                "product": svc.product,
                "version": svc.version,
                "cpe": svc.cpe,
                "banner": svc.banner,
                "encryption": svc.encryption,
                "confidence": svc.confidence,
                "source_scanner": svc.source_scanner,
                "raw_evidence_location": svc.raw_evidence_location,
            }
            for svc in item.services
        ],
    }


def _screenshot_index(item: Asset) -> list[dict]:
    path = get_settings().evidence_dir / item.scan.public_id / "screenshots-index.json"
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(records, list):
        return []
    return [record for record in records if record.get("asset_ip") == item.ip]


@router.get("")
def assets(db: Session = Depends(get_db), _: User = Depends(current_user)) -> list[dict]:
    result = []
    seen: set[str] = set()
    for item in db.scalars(select(Asset).order_by(Asset.last_scanned.desc())):
        if item.ip in seen:
            continue
        seen.add(item.ip)
        result.append(serialize(item))
    return result


@router.get("/{asset_id}")
def asset_details(
    asset_id: int, db: Session = Depends(get_db), _: User = Depends(current_user)
) -> dict:
    item = db.get(Asset, asset_id)
    if not item:
        raise HTTPException(404, "Asset not found")
    findings = db.scalars(
        select(Finding).where(Finding.scan_id == item.scan_id, Finding.asset_ip == item.ip)
    ).all()
    history = db.scalars(
        select(Asset).where(Asset.ip == item.ip).order_by(Asset.last_scanned.desc())
    ).all()
    return {
        **serialize(item),
        "findings": [
            {
                column.name: getattr(finding, column.name)
                for column in finding.__table__.columns
                if column.name not in {"id", "scan_id"}
            }
            for finding in findings
        ],
        "screenshots": _screenshot_index(item),
        "history": [
            {
                "asset_id": historical.id,
                "scan_id": historical.scan.public_id,
                "last_scanned": historical.last_scanned,
                "risk_score": historical.risk_score,
                "open_services": len(historical.services),
            }
            for historical in history
        ],
    }


@router.get("/{asset_id}/screenshots/{filename}")
def screenshot(
    asset_id: int,
    filename: str,
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
) -> FileResponse:
    item = db.get(Asset, asset_id)
    if not item:
        raise HTTPException(404, "Asset not found")
    allowed = {
        record.get("file_name") for record in _screenshot_index(item) if record.get("file_name")
    }
    if filename not in allowed or Path(filename).name != filename:
        raise HTTPException(404, "Screenshot not found")
    directory = (get_settings().evidence_dir / item.scan.public_id / "screenshots").resolve()
    path = (directory / filename).resolve()
    if path.parent != directory or not path.is_file():
        raise HTTPException(404, "Screenshot not found")
    return FileResponse(path, media_type="image/png", filename=filename)
