"""Authorized scan creation, progress, cancellation, and comparison."""

import secrets
from datetime import date
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.constants import AUTHORIZED_USE_WARNING
from app.core.security import current_user, require_roles
from app.database import get_db
from app.models import Asset, AuditLog, Engagement, Finding, Scan, Service, User
from app.schemas.scan import ScanCreate
from app.services.comparison_engine import compare_scans
from app.services.scan_orchestrator import scan_orchestrator
from app.services.scope_validator import enforce_engagement_scope, expand_targets

router = APIRouter(prefix="/api/scans", tags=["scans"])


def scan_dict(item: Scan) -> dict:
    return {
        column.name: getattr(item, column.name)
        for column in item.__table__.columns
        if column.name not in {"id", "engagement_id", "started_by"}
    }


def snapshot(db: Session, scan: Scan) -> dict:
    services = db.execute(
        select(
            Asset.ip,
            Service.port,
            Service.transport,
            Service.protocol,
            Service.product,
            Service.version,
            Service.cpe,
            Service.encryption,
            Service.confidence,
            Service.source_scanner,
        )
        .join(Service, Service.asset_id == Asset.id)
        .where(Asset.scan_id == scan.id)
    ).all()
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    assets = db.scalars(select(Asset).where(Asset.scan_id == scan.id)).all()
    engagement = scan.engagement
    evidence_directory = get_settings().evidence_dir / scan.public_id
    evidence_manifest = []
    if evidence_directory.is_dir():
        evidence_manifest = [
            {"name": path.name, "size": path.stat().st_size}
            for path in sorted(evidence_directory.iterdir())
            if path.is_file()
        ]
    return {
        "scan": scan_dict(scan),
        "engagement": {
            "public_id": engagement.public_id,
            "name": engagement.name,
            "customer": engagement.customer,
            "authorization_reference": engagement.authorization_reference,
            "start_date": engagement.start_date,
            "expiry_date": engagement.expiry_date,
            "approved_targets": engagement.approved_targets,
            "exclusions": engagement.exclusions,
            "scan_window": engagement.scan_window,
            "emergency_contact": engagement.emergency_contact,
        },
        "assets": [
            {
                "ip": asset.ip,
                "hostname": asset.hostname,
                "reachability": asset.reachability,
                "operating_system": asset.operating_system,
                "asn": asset.asn,
                "risk_score": asset.risk_score,
                "last_scanned": asset.last_scanned,
            }
            for asset in assets
        ],
        "services": [
            {
                "ip": row.ip,
                "port": row.port,
                "transport": row.transport,
                "protocol": row.protocol,
                "product": row.product,
                "version": row.version,
                "cpe": row.cpe,
                "encryption": row.encryption,
                "confidence": row.confidence,
                "source_scanner": row.source_scanner,
            }
            for row in services
        ],
        "findings": [
            {
                **{
                    column.name: getattr(item, column.name)
                    for column in item.__table__.columns
                    if column.name not in {"id", "scan_id"}
                },
                "evidence_items": [
                    {
                        "scanner": evidence.scanner,
                        "evidence_type": evidence.evidence_type,
                        "file_location": evidence.file_location,
                        "redacted_content": evidence.redacted_content,
                        "created_at": evidence.created_at,
                    }
                    for evidence in item.evidence_items
                ],
            }
            for item in findings
        ],
        "evidence_manifest": evidence_manifest,
    }


@router.get("/warning")
def warning() -> dict:
    return {"warning": AUTHORIZED_USE_WARNING}


@router.get("")
def list_scans(db: Session = Depends(get_db), _: User = Depends(current_user)) -> list[dict]:
    return [scan_dict(item) for item in db.scalars(select(Scan).order_by(Scan.id.desc()))]


@router.post("", status_code=202)
async def create_scan(
    payload: ScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    if not payload.authorized:
        raise HTTPException(403, AUTHORIZED_USE_WARNING)
    engagement = db.scalar(select(Engagement).where(Engagement.public_id == payload.engagement_id))
    if not engagement or engagement.closed:
        raise HTTPException(404, "Active engagement not found")
    if not (engagement.start_date <= date.today() <= engagement.expiry_date):
        raise HTTPException(403, "Engagement authorization is not currently valid")
    settings = get_settings()
    try:
        targets = expand_targets(
            payload.targets, max_cidr_prefix=settings.max_cidr_prefix, max_targets=settings.max_targets
        )
        enforce_engagement_scope(
            targets,
            engagement.approved_targets,
            engagement.exclusions,
            max_cidr_prefix=settings.max_cidr_prefix,
        )
        submitted_hostnames: dict[str, str] = {}
        for raw_ip, hostname in payload.hostnames.items():
            hostname_targets = expand_targets(
                [raw_ip],
                max_cidr_prefix=settings.max_cidr_prefix,
                max_targets=1,
            )
            normalized_ip = hostname_targets[0]
            if normalized_ip not in targets:
                raise ValueError(f"Hostname association is outside the submitted target set: {raw_ip}")
            submitted_hostnames[normalized_ip] = hostname
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    public_id = f"SCAN-{date.today():%Y%m%d}-{secrets.token_hex(2).upper()}"
    options = payload.model_dump(
        exclude={"engagement_id", "targets", "profile", "authorized", "initiated_by"}
    )
    if "rate_limit" not in payload.model_fields_set:
        options["rate_limit"] = settings.default_rate_limit
    if "timeout" not in payload.model_fields_set:
        options["timeout"] = settings.command_timeout
    if payload.profile == "quick":
        options.update(enable_udp=False, enable_tls=False, enable_ssh=False, enable_screenshots=False)
    elif payload.profile == "standard":
        options.update(
            enable_udp=True,
            enable_tls=True,
            enable_ssh=True,
            enable_screenshots=False,
            nuclei_severity="info,low,medium,high,critical",
        )
    elif payload.profile == "full":
        options.update(
            enable_udp=True,
            enable_tls=True,
            enable_ssh=True,
            enable_screenshots=True,
            enable_os_detection=True,
            nuclei_severity="info,low,medium,high,critical",
        )
    options["hostnames"] = submitted_hostnames
    scan = Scan(
        public_id=public_id,
        engagement_id=engagement.id,
        profile=payload.profile,
        started_by=user.id,
        targets=targets,
        options=options,
    )
    db.add(scan)
    db.flush()
    db.add(
        AuditLog(
            user_id=user.id,
            action="scan.create",
            target=public_id,
            source_ip=request.client.host if request.client else None,
            result="accepted",
            details={"initiated_by": payload.initiated_by, "targets": targets, "profile": payload.profile},
        )
    )
    db.commit()
    scan_orchestrator.start(public_id)
    return {**scan_dict(scan), "warning": AUTHORIZED_USE_WARNING}


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)) -> dict:
    scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    return snapshot(db, scan)


@router.get("/{scan_id}/evidence/{filename}")
def download_evidence(
    scan_id: str,
    filename: str,
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
) -> FileResponse:
    scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
    if not scan or Path(filename).name != filename:
        raise HTTPException(404, "Evidence file not found")
    directory = (get_settings().evidence_dir / scan.public_id).resolve()
    path = (directory / filename).resolve()
    if path.parent != directory or not path.is_file():
        raise HTTPException(404, "Evidence file not found")
    return FileResponse(path, filename=filename, media_type="application/octet-stream")


@router.post("/{scan_id}/stop")
async def stop_scan(
    scan_id: str, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))
) -> dict:
    stopped = await scan_orchestrator.cancel(scan_id)
    db.add(
        AuditLog(
            user_id=user.id,
            action="scan.stop",
            target=scan_id,
            result="success" if stopped else "not-running",
        )
    )
    db.commit()
    return {"scan_id": scan_id, "stopped": stopped}


@router.get("/{previous_id}/compare/{current_id}")
def compare(
    previous_id: str, current_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)
) -> dict:
    previous = db.scalar(select(Scan).where(Scan.public_id == previous_id))
    current = db.scalar(select(Scan).where(Scan.public_id == current_id))
    if not previous or not current:
        raise HTTPException(404, "One or both scans were not found")
    return compare_scans(snapshot(db, previous), snapshot(db, current))
