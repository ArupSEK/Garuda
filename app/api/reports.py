"""Report download endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.scans import snapshot
from app.core.security import current_user
from app.database import get_db
from app.models import Scan, User
from app.services.report_generator import report_generator

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{scan_id}.{format}")
def report(
    scan_id: str, format: str, db: Session = Depends(get_db), _: User = Depends(current_user)
) -> Response:
    scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    payload = snapshot(db, scan)
    generators = {
        "json": (report_generator.json, "application/json"),
        "jsonl": (report_generator.jsonl, "application/x-ndjson"),
        "csv": (report_generator.csv, "text/csv"),
        "html": (report_generator.html, "text/html"),
        "pdf": (report_generator.pdf, "application/pdf"),
    }
    if format not in generators:
        raise HTTPException(400, "Supported formats: json, jsonl, csv, html, pdf")
    generator, media_type = generators[format]
    try:
        content = generator(payload)
    except RuntimeError as exc:
        raise HTTPException(501, str(exc)) from exc
    return Response(
        content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{scan_id}.{format}"'},
    )
