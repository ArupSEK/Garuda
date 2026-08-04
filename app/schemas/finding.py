from datetime import date

from pydantic import BaseModel, Field


class FindingUpdate(BaseModel):
    status: str | None = None
    validation_notes: str | None = Field(None, max_length=10000)
    remediation_notes: str | None = Field(None, max_length=10000)
    risk_acceptance_expiry: date | None = None
    assigned_owner: str | None = Field(None, max_length=255)
    target_remediation_date: date | None = None
