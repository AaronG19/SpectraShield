"""Alert-related Pydantic request schemas."""
from pydantic import BaseModel


class AlertAcknowledge(BaseModel):
    comment: str = ""


class AlertResolve(BaseModel):
    resolved_by: str = "admin"
    comment: str = ""


class ThreatLookupRequest(BaseModel):
    value: str
