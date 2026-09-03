"""Agentic reasoning ORM models.

Additive-only schema additions for the Agentic Redesign (Phase 1).
These tables store reasoning traces, agent behavioral profiles, learned
attack pattern signatures, execution plans and Working Memory checkpoints.
No existing table is modified.
"""
import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import relationship

from db.base import Base


class ReasoningHistory(Base):
    """Trace of a reasoning evaluation, for auditability and learning."""
    __tablename__ = "reasoning_history"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    event_id = Column(String, default="", index=True)
    verdict = Column(String, default="unknown")  # benign / suspicious / malicious / requires_investigation
    confidence = Column(Float, default=0.0)  # 0.0-1.0
    severity = Column(String, default="info")  # info / low / medium / high / critical
    reasoning_chain = Column(Text, default="[]")  # JSON: list of reasoning steps
    actions_taken = Column(Text, default="[]")  # JSON: actions executed or queued
    outcome = Column(String, default="unknown")  # true_positive / false_positive / unknown
    created_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent")


class AgentBehavioralProfile(Base):
    """Aggregated behavioral fingerprint per agent (one row per agent)."""
    __tablename__ = "agent_behavioral_profiles"
    __table_args__ = (UniqueConstraint("agent_id", name="uq_agent_behavioral_profile_agent_id"),)

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    normal_processes = Column(Text, default="[]")  # JSON: list of normally seen processes
    typical_network_patterns = Column(Text, default="[]")  # JSON: normal destinations/patterns
    baseline_metrics = Column(Text, default="{}")  # JSON: CPU / RAM / process count baselines
    false_positive_patterns = Column(Text, default="[]")  # JSON: patterns marked FP for this agent
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    agent = relationship("Agent")


class AttackPatternSignature(Base):
    """Reusable attack pattern learned from past incidents."""
    __tablename__ = "attack_pattern_signatures"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    pattern_name = Column(String, nullable=False)
    mitre_chain = Column(Text, default="[]")  # JSON: sequence of MITRE tactics/techniques
    event_sequence = Column(Text, default="[]")  # JSON: ordered event types constituting the pattern
    confidence = Column(Float, default=0.0)  # reliability of this pattern
    times_seen = Column(Integer, default=1)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)


class ExecutionPlan(Base):
    """Persisted investigation/response/remediation plan."""
    __tablename__ = "execution_plans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    plan_type = Column(String, nullable=False, default="investigation")  # investigation / response / remediation
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    trigger_event_id = Column(String, default="")
    steps = Column(Text, default="[]")  # JSON: ordered list of plan steps
    status = Column(String, default="planning")  # planning / executing / paused / completed / aborted
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    agent = relationship("Agent")


class AgentContextSnapshot(Base):
    """Periodic Working Memory checkpoint for crash recovery."""
    __tablename__ = "agent_context_snapshots"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False, index=True)
    context_data = Column(Text, default="{}")  # JSON: serialized AgentContext
    snapshot_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent")
