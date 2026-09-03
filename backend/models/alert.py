"""Alert and PendingAction ORM models."""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from db.base import Base


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    severity = Column(String, default="medium")
    type = Column(String, default="malware")
    status = Column(String, default="open")
    source = Column(String, default="agent")
    mitre_tactic_id = Column(String, default="")
    mitre_tactic_name = Column(String, default="")
    mitre_technique_id = Column(String, default="")
    mitre_technique_name = Column(String, default="")
    score = Column(Float, default=0.0)
    details = Column(Text, default="{}")
    fingerprint = Column(String, default="", index=True)  # identity key used to dedupe repeats of the same condition
    occurrence_count = Column(Integer, default=1)  # how many times this fingerprint has re-fired while open
    last_seen_at = Column(DateTime, default=datetime.utcnow)  # updated each time a duplicate is suppressed
    # NOTE: fingerprint-based dedup is currently wired into port_scan,
    # lateral_movement, and beaconing (the highest-volume repeat offenders).
    # The remaining alert-creation call sites still dedupe only on
    # (agent_id, type, status="open") with no fingerprint, which means two
    # genuinely different incidents of the same type can mask each other.
    # Apply the same fingerprint + occurrence_count/last_seen_at pattern to
    # the rest in a follow-up pass.
    created_at = Column(DateTime, default=datetime.utcnow)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String, default="")
    agent = relationship("Agent", back_populates="alerts")


class PendingAction(Base):
    """Persisted replacement for the old in-memory _pending_actions dict.
    A backend restart no longer drops actions an agent hasn't picked up yet."""
    __tablename__ = "pending_actions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    action = Column(String, nullable=False)
    target = Column(String, default="")
    source = Column(String, default="manual")  # "manual" (analyst) or "policy" (auto-response)
    status = Column(String, default="pending")  # pending -> delivered -> completed/failed
    created_at = Column(DateTime, default=datetime.utcnow)
    delivered_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    result = Column(Text, default="")


class Policy(Base):
    __tablename__ = "policies"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    key = Column(String, unique=True, nullable=False)
    value = Column(Text, nullable=False)
    description = Column(String, default="")
    updated_at = Column(DateTime, default=datetime.utcnow)
