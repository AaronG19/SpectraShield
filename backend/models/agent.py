"""Agent ORM model."""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from db.base import Base


class Agent(Base):
    __tablename__ = "agents"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String, nullable=False)
    os_type = Column(String, nullable=False)
    os_version = Column(String, default="")
    os_patch_level = Column(String, default="")
    cpu_model = Column(String, default="")
    cpu_cores = Column(Integer, default=0)
    cpu_usage = Column(Float, default=0.0)
    ram_total_gb = Column(Integer, default=0)
    ram_used_gb = Column(Float, default=0.0)
    disk_total_gb = Column(Integer, default=0)
    disk_used_gb = Column(Float, default=0.0)
    mac_address = Column(String, default="")
    ip_address = Column(String, default="")
    status = Column(String, default="online")
    version = Column(String, default="3.5.1")
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    registered_at = Column(DateTime, default=datetime.utcnow)
    tamper_protection = Column(Boolean, default=True)
    self_defense_status = Column(String, default="active")
    low_footprint_mode = Column(Boolean, default=True)
    quarantine = Column(Boolean, default=False)
    bitlocker_enabled = Column(Boolean, default=False)
    firewall_enabled = Column(Boolean, default=True)
    agent_type = Column(String, default="silent_deploy")
    group_name = Column(String, default="")
    one_time_token = Column(String, default="")
    agent_token = Column(String, default="")  # persistent per-agent secret, sent as X-Agent-Token on every report call
    owner_id = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    owner = relationship("User", back_populates="agents")
    alerts = relationship("Alert", back_populates="agent", cascade="all, delete-orphan")
    processes = relationship("Process", back_populates="agent", cascade="all, delete-orphan")
    network_connections = relationship("NetworkConnection", back_populates="agent", cascade="all, delete-orphan")
    applications = relationship("Application", back_populates="agent", cascade="all, delete-orphan")
    file_changes = relationship("FileChange", back_populates="agent", cascade="all, delete-orphan")
    registry_changes = relationship("RegistryChange", back_populates="agent", cascade="all, delete-orphan")
