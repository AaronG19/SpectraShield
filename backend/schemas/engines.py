"""Engine-related Pydantic request schemas (behavioral, risk, ML, response)."""
from pydantic import BaseModel


class BehavioralAnalysisRequest(BaseModel):
    process_name: str = ""
    cmdline: str = ""
    parent_name: str = ""
    file_path: str = ""
    user: str = ""
    os_type: str = "windows"
    event_type: str = "process_execution"


class RiskEventRequest(BaseModel):
    event_type: str = "behavioral_anomaly"
    severity: str = "medium"
    score: float = 0.0
    details: str = "{}"


class ResponseEvaluateRequest(BaseModel):
    event_type: str = ""
    severity: str = "medium"
    details: dict = {}
    agent_id: str = ""


class MLAnalysisRequest(BaseModel):
    features: dict = {}
    agent_id: str = ""


class BaselinerUpdateRequest(BaseModel):
    cpu_usage: float = 0.0
    ram_usage: float = 0.0
    process_count: int = 0
    net_connections: int = 0
    agent_id: str = ""
