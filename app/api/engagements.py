"""Engagement lifecycle endpoints."""

import secrets

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.security import current_user, require_roles
from app.database import get_db
from app.models import AuditLog, Engagement, User
from app.schemas.engagement import EngagementCreate, EngagementUpdate
from app.services.scope_validator import expand_targets, parse_public_network

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


def serialize(item: Engagement) -> dict:
    return {
        column.name: getattr(item, column.name) for column in item.__table__.columns if column.name != "id"
    }


@router.get("")
def list_engagements(db: Session = Depends(get_db), _: User = Depends(current_user)) -> list[dict]:
    return [serialize(item) for item in db.scalars(select(Engagement).order_by(Engagement.created_at.desc()))]


@router.post("", status_code=201)
def create_engagement(
    payload: EngagementCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    settings = get_settings()
    for target in payload.approved_targets:
        expand_targets([target], max_cidr_prefix=settings.max_cidr_prefix, max_targets=settings.max_targets)
    for target in payload.exclusions:
        parse_public_network(target, max_cidr_prefix=settings.max_cidr_prefix)
    item = Engagement(
        public_id=f"ENG-{secrets.token_hex(3).upper()}", created_by=user.id, **payload.model_dump()
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(user_id=user.id, action="engagement.create", target=item.public_id, result="success"))
    db.commit()
    return serialize(item)


@router.patch("/{engagement_id}")
def update_engagement(
    engagement_id: str,
    payload: EngagementUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin", "analyst")),
) -> dict:
    item = db.scalar(select(Engagement).where(Engagement.public_id == engagement_id))
    if not item:
        raise HTTPException(404, "Engagement not found")
    changes = payload.model_dump(exclude_unset=True)
    start_date = changes.get("start_date", item.start_date)
    expiry_date = changes.get("expiry_date", item.expiry_date)
    if expiry_date < start_date:
        raise HTTPException(422, "Authorization expiry must not precede its start date")
    settings = get_settings()
    try:
        for target in changes.get("approved_targets", item.approved_targets):
            expand_targets(
                [target],
                max_cidr_prefix=settings.max_cidr_prefix,
                max_targets=settings.max_targets,
            )
        for target in changes.get("exclusions", item.exclusions):
            parse_public_network(target, max_cidr_prefix=settings.max_cidr_prefix)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    for key, value in changes.items():
        setattr(item, key, value)
    db.add(
        AuditLog(
            user_id=user.id,
            action="engagement.update",
            target=item.public_id,
            result="success",
            details={"fields": sorted(changes)},
        )
    )
    db.commit()
    return serialize(item)


@router.get("/{engagement_id}")
def get_engagement(
    engagement_id: str, db: Session = Depends(get_db), _: User = Depends(current_user)
) -> dict:
    item = db.scalar(select(Engagement).where(Engagement.public_id == engagement_id))
    if not item:
        raise HTTPException(404, "Engagement not found")
    return serialize(item)


@router.post("/{engagement_id}/close")
def close_engagement(
    engagement_id: str, db: Session = Depends(get_db), user: User = Depends(require_roles("admin", "analyst"))
) -> dict:
    item = db.scalar(select(Engagement).where(Engagement.public_id == engagement_id))
    if not item:
        raise HTTPException(404, "Engagement not found")
    item.closed = True
    db.add(AuditLog(user_id=user.id, action="engagement.close", target=item.public_id, result="success"))
    db.commit()
    return {"public_id": item.public_id, "closed": True}
