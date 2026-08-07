from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EngagementCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    customer: str = Field(min_length=2, max_length=200)
    authorization_reference: str = Field(min_length=2, max_length=255)
    start_date: date
    expiry_date: date
    approved_targets: list[str] = Field(min_length=1)
    exclusions: list[str] = Field(default_factory=list)
    scan_window: str | None = None
    emergency_contact: str | None = None

    @model_validator(mode="after")
    def dates_are_valid(self):
        if self.expiry_date < self.start_date:
            raise ValueError("Authorization expiry must not precede its start date")
        return self


class EngagementRead(EngagementCreate):
    model_config = ConfigDict(from_attributes=True)
    public_id: str
    closed: bool
    created_at: datetime


class EngagementUpdate(BaseModel):
    name: str | None = Field(None, min_length=2, max_length=200)
    customer: str | None = Field(None, min_length=2, max_length=200)
    authorization_reference: str | None = Field(None, min_length=2, max_length=255)
    start_date: date | None = None
    expiry_date: date | None = None
    approved_targets: list[str] | None = Field(None, min_length=1)
    exclusions: list[str] | None = None
    scan_window: str | None = None
    emergency_contact: str | None = None
