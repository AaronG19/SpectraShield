"""Policy-related Pydantic request schemas."""
from pydantic import BaseModel


class PolicyUpdate(BaseModel):
    key: str
    value: str


class AppWhitelistAdd(BaseModel):
    name: str
    path: str = ""
    hash: str = ""
    vendor: str = ""


class BlockDevice(BaseModel):
    device_id: str
    device_name: str
    device_type: str = "usb"
    reason: str = ""


class FirewallRuleCreate(BaseModel):
    name: str
    direction: str = "inbound"
    action: str = "allow"
    protocol: str = "TCP"
    local_port: int = 0
    remote_ip: str = "any"
    enabled: bool = True


class CanaryFileCreate(BaseModel):
    file_path: str
    file_name: str = ""

