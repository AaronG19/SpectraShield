"""Agent-related Pydantic request schemas."""
from pydantic import BaseModel


class AgentRegister(BaseModel):
    hostname: str
    os_type: str
    os_version: str = ""
    cpu_model: str = ""
    cpu_cores: int = 0
    ram_total_gb: int = 0
    disk_total_gb: int = 0
    mac_address: str = ""
    ip_address: str = ""


class DeployRequest(BaseModel):
    agent_type: str = "silent_deploy"


class ScanRequest(BaseModel):
    scan_type: str = "quick"


class QuarantineRequest(BaseModel):
    action: str = "quarantine"

