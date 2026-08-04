"""Finding list, filters, and analyst workflow."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import FINDING_STATUSES
from app.core.security import current_user, require_roles
from app.database import get_db
from app.models import AuditLog, Finding, User
from app.schemas.finding import FindingUpdate

router = APIRouter(prefix="/api/findings", tags=["findings"])


def serialize(item: Finding) -> dict:
    return {
        column.name: getattr(item, column.name)
        for column in item.__table__.columns
        if column.name not in {"id", "scan_id"}
    }


@router.get("")
def findings(
    severity: str | None = Query(None),
    status: str | None = Query(None),
    asset_ip: str | None = Query(None),
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
    return [serialize(item) for item in db.scalars(query.order_by(Finding.severity, Finding.asset_ip))]


@router.patch("/{finding_id}")
def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    item = db.scalar(select(Finding).where(Finding.finding_id == finding_id))
    if not item:
        raise HTTPException(404, "Finding not found")
    changes = payload.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] not in FINDING_STATUSES:
        raise HTTPException(422, "Unsupported finding status")
    for key, value in changes.items():
        setattr(item, key, value)
    db.add(
        AuditLog(
            user_id=user.id,
            action="finding.update",
            target=finding_id,
            result="success",
            details={"fields": list(changes)},
        )
    )
    db.commit()
    return serialize(item)
