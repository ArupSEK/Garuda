"""Finding list, filters, and analyst workflow."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.core.constants import FINDING_STATUSES
from app.core.security import current_user, require_roles
from app.database import get_db
from app.models import AuditLog, Finding, User
from app.schemas.finding import FindingUpdate

router = APIRouter(prefix="/api/findings", tags=["findings"])


def serialize(item: Finding) -> dict:
    return {
        "record_id": item.id,
        **{
            column.name: getattr(item, column.name)
            for column in item.__table__.columns
            if column.name not in {"id", "scan_id"}
        },
    }


@router.get("")
def findings(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    asset_ip: str | None = Query(None),
    hostname: str | None = Query(None),
    priority: str | None = Query(None),
    port: int | None = Query(None, ge=1, le=65535),
    protocol: str | None = Query(None),
    cve: str | None = Query(None),
    cisa_kev: bool | None = Query(None),
    confidence: str | None = Query(None),
    scanner: str | None = Query(None),
    engagement_id: str | None = Query(None),
    scan_id: str | None = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
) -> list[dict]:
    query = select(Finding)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if asset_ip:
        query = query.where(Finding.asset_ip == asset_ip)
    if hostname:
        query = query.where(Finding.hostname == hostname)
    if priority:
        query = query.where(Finding.priority == priority)
    if port:
        query = query.where(Finding.port == port)
    if protocol:
        query = query.where(Finding.protocol == protocol)
    if cisa_kev is not None:
        query = query.where(Finding.cisa_kev == cisa_kev)
    if confidence:
        query = query.where(Finding.confidence == confidence)
    if scanner:
        query = query.where(Finding.scanner == scanner)
    if engagement_id:
        query = query.where(Finding.engagement_public_id == engagement_id)
    if scan_id:
        query = query.where(Finding.scan.has(public_id=scan_id))
    severity_order = case(
        (Finding.severity == "critical", 0),
        (Finding.severity == "high", 1),
        (Finding.severity == "medium", 2),
        (Finding.severity == "low", 3),
        else_=4,
    )
    items = list(db.scalars(query.order_by(severity_order, Finding.asset_ip)))
    if cve:
        normalized_cve = cve.strip().upper()
        items = [item for item in items if normalized_cve in {value.upper() for value in item.cve}]
    return [serialize(item) for item in items]


@router.get("/{finding_id}")
def finding_details(
    finding_id: str,
    record_id: int | None = Query(None),
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
) -> dict:
    query = select(Finding).where(Finding.finding_id == finding_id)
    if record_id is not None:
        query = query.where(Finding.id == record_id)
    item = db.scalar(query.order_by(Finding.last_seen.desc()))
    if not item:
        raise HTTPException(404, "Finding not found")
    history = db.scalars(
        select(AuditLog)
        .where(AuditLog.action == "finding.update", AuditLog.target == finding_id)
        .order_by(AuditLog.timestamp.desc())
    ).all()
    history = [
        entry for entry in history if entry.details.get("record_id") in {None, item.id}
    ]
    return {
        **serialize(item),
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
        "status_history": [
            {
                "timestamp": entry.timestamp,
                "user_id": entry.user_id,
                "result": entry.result,
                "changes": entry.details.get("changes", {}),
                "previous": entry.details.get("previous", {}),
            }
            for entry in history
        ],
    }


@router.patch("/{finding_id}")
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    record_id: int | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    query = select(Finding).where(Finding.finding_id == finding_id)
    if record_id is not None:
        query = query.where(Finding.id == record_id)
    item = db.scalar(query.order_by(Finding.last_seen.desc()))
    if not item:
        raise HTTPException(404, "Finding not found")
    changes = payload.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] not in FINDING_STATUSES:
        raise HTTPException(422, "Unsupported finding status")
    if changes.get("status") == "false positive" and not (
        changes.get("validation_notes") or item.validation_notes
    ):
        raise HTTPException(422, "False-positive status requires a justification in validation notes")
    if changes.get("status") == "accepted risk" and not (
        changes.get("risk_acceptance_expiry") or item.risk_acceptance_expiry
    ):
        raise HTTPException(422, "Accepted-risk status requires a risk-acceptance expiry date")
    previous = {key: getattr(item, key) for key in changes}
    for key, value in changes.items():
        setattr(item, key, value)
    audit_changes = {
        key: value.isoformat() if hasattr(value, "isoformat") else value
        for key, value in changes.items()
    }
    audit_previous = {
        key: value.isoformat() if hasattr(value, "isoformat") else value
        for key, value in previous.items()
    }
    db.add(
        AuditLog(
            user_id=user.id,
            action="finding.update",
            target=finding_id,
            result="success",
            details={
                "record_id": item.id,
                "changes": audit_changes,
                "previous": audit_previous,
            },
        )
    )
    db.commit()
    return serialize(item)
