from pydantic import BaseModel


class AssetRead(BaseModel):
    ip: str
    hostname: str | None
    reachability: str
    operating_system: str | None
    risk_score: float
