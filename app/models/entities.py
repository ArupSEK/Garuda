"""SQLAlchemy persistence models."""

from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(30), default="analyst")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    customer: Mapped[str] = mapped_column(String(200))
    authorization_reference: Mapped[str] = mapped_column(String(255))
    start_date: Mapped[date] = mapped_column(Date)
    expiry_date: Mapped[date] = mapped_column(Date)
    approved_targets: Mapped[list[str]] = mapped_column(JSON)
    exclusions: Mapped[list[str]] = mapped_column(JSON, default=list)
    scan_window: Mapped[str | None] = mapped_column(String(255), nullable=True)
    emergency_contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    closed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    scans: Mapped[list["Scan"]] = relationship(back_populates="engagement", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    public_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    engagement_id: Mapped[int] = mapped_column(ForeignKey("engagements.id"), index=True)
    profile: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(30), default="queued")
    started_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    targets: Mapped[list[str]] = mapped_column(JSON)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    current_stage: Mapped[str] = mapped_column(String(100), default="queued")
    scanner_versions: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    engagement: Mapped[Engagement] = relationship(back_populates="scans")
    assets: Mapped[list["Asset"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("scan_id", "ip", name="uq_scan_asset_ip"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reachability: Mapped[str] = mapped_column(String(30), default="unknown")
    operating_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asn: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_scanned: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    scan: Mapped[Scan] = relationship(back_populates="assets")
    services: Mapped[list["Service"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    transport: Mapped[str] = mapped_column(String(8))
    protocol: Mapped[str] = mapped_column(String(50))
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cpe: Mapped[list[str]] = mapped_column(JSON, default=list)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    encryption: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[str] = mapped_column(String(40), default="potential")
    source_scanner: Mapped[str] = mapped_column(String(50), default="nmap")
    raw_evidence_location: Mapped[str | None] = mapped_column(String(500), nullable=True)
    asset: Mapped[Asset] = relationship(back_populates="services")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    engagement_public_id: Mapped[str] = mapped_column(String(32), index=True)
    asset_ip: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    transport: Mapped[str] = mapped_column(String(8), default="tcp")
    protocol: Mapped[str | None] = mapped_column(String(50), nullable=True)
    service: Mapped[str | None] = mapped_column(String(255), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    priority: Mapped[str] = mapped_column(String(20), default="Informational")
    confidence: Mapped[str] = mapped_column(String(50), default="potential")
    confidence_reason: Mapped[str] = mapped_column(Text, default="")
    cve: Mapped[list[str]] = mapped_column(JSON, default=list)
    cwe: Mapped[list[str]] = mapped_column(JSON, default=list)
    cpe: Mapped[list[str]] = mapped_column(JSON, default=list)
    cvss_v31_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v31_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_v40_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v40_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    scanner: Mapped[str] = mapped_column(String(50))
    scanner_rule_id: Mapped[str] = mapped_column(String(255))
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_references: Mapped[list[str]] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(40), default="new")
    validation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_acceptance_expiry: Mapped[date | None] = mapped_column(Date, nullable=True)
    assigned_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_remediation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    scan: Mapped[Scan] = relationship(back_populates="findings")
    evidence_items: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_db_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    scanner: Mapped[str] = mapped_column(String(50))
    evidence_type: Mapped[str] = mapped_column(String(50))
    file_location: Mapped[str | None] = mapped_column(String(500), nullable=True)
    redacted_content: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finding: Mapped[Finding] = relationship(back_populates="evidence_items")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    target: Mapped[str] = mapped_column(String(500))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    result: Mapped[str] = mapped_column(String(50))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
