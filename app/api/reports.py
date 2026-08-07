"""Report download endpoints."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.scans import snapshot
from app.core.security import current_user
from app.database import get_db
from app.models import Scan, User
from app.services.comparison_engine import compare_scans
from app.services.report_generator import report_generator

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/compare/{previous_id}/{current_id}.{format}")
def comparison_report(
    previous_id: str,
    current_id: str,
    format: Literal["json", "csv", "html", "pdf"],
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
) -> Response:
    previous = db.scalar(select(Scan).where(Scan.public_id == previous_id))
    current = db.scalar(select(Scan).where(Scan.public_id == current_id))
    if not previous or not current:
        raise HTTPException(404, "One or both scans were not found")
    payload = compare_scans(snapshot(db, previous), snapshot(db, current))
    payload["previous_scan_id"] = previous_id
    payload["current_scan_id"] = current_id
    try:
        if format == "json":
            content = report_generator.json(payload)
        elif format == "csv":
            content = report_generator.comparison_csv(payload)
        elif format == "html":
            content = report_generator.comparison_html(payload)
        else:
            content = report_generator.comparison_pdf(payload)
    except RuntimeError as exc:
        raise HTTPException(501, str(exc)) from exc
    media_types = {
        "json": "application/json",
        "csv": "text/csv",
        "html": "text/html",
        "pdf": "application/pdf",
    }
    return Response(
        content,
        media_type=media_types[format],
        headers={
            "Content-Disposition": (
                f'attachment; filename="comparison-{previous_id}-{current_id}.{format}"'
            )
        },
    )


@router.get("/{scan_id}.{format}")
def report(
    scan_id: str,
    format: str,
    report_type: Literal["technical", "executive"] = Query("technical"),
    dataset: Literal["full", "findings", "assets", "services"] = Query("full"),
    db: Session = Depends(get_db),
    _: User = Depends(current_user),
) -> Response:
    scan = db.scalar(select(Scan).where(Scan.public_id == scan_id))
    if not scan:
        raise HTTPException(404, "Scan not found")
    payload = snapshot(db, scan)
    media_types = {
        "json": "application/json",
        "jsonl": "application/x-ndjson",
        "csv": "text/csv",
        "html": "text/html",
        "pdf": "application/pdf",
    }
    if format not in media_types:
        raise HTTPException(400, "Supported formats: json, jsonl, csv, html, pdf")
    try:
        if format == "html":
            content = report_generator.html(payload, executive=report_type == "executive")
        elif format == "pdf":
            content = report_generator.pdf(payload, executive=report_type == "executive")
        elif format == "csv":
            content = report_generator.csv(
                payload,
                dataset="findings" if dataset == "full" else dataset,
            )
        elif format == "jsonl":
            selected_dataset = "findings" if dataset == "full" else dataset
            content = report_generator.jsonl(payload, dataset=selected_dataset)
        elif format == "json" and dataset != "full":
            subset = {"scan": payload["scan"], dataset: payload[dataset]}
            content = report_generator.json(subset)
        else:
            content = getattr(report_generator, format)(payload)
    except RuntimeError as exc:
        raise HTTPException(501, str(exc)) from exc
    return Response(
        content,
        media_type=media_types[format],
        headers={
            "Content-Disposition": f'attachment; filename="{scan_id}-{report_type}.{format}"'
        },
    )
