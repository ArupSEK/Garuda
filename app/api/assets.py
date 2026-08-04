"""Asset inventory endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import current_user
from app.database import get_db
from app.models import Asset, User

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("")
def assets(db: Session = Depends(get_db), _: User = Depends(current_user)) -> list[dict]:
    result = []
    for item in db.scalars(select(Asset).order_by(Asset.last_scanned.desc())):
        result.append(
            {
                "id": item.id,
                "ip": item.ip,
                "hostname": item.hostname,
                "reachability": item.reachability,
                "operating_system": item.operating_system,
                "risk_score": item.risk_score,
                "services": [
                    {
                        "port": svc.port,
                        "transport": svc.transport,
                        "protocol": svc.protocol,
                        "product": svc.product,
                        "version": svc.version,
                    }
                    for svc in item.services
                ],
            }
        )
    return result
