"""Reasoning-layer Pydantic schemas (requests, normalized events, verdicts, DB entities)."""
from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel, ConfigDict


class ReasoningRequest(BaseModel):
    """Input to the reasoning pipeline: a single agent telemetry event plus context."""
    agent_id: str
    event_type: str = ""
    event_id: str = ""
    payload: Dict[str, Any] = {}
    received_at: datetime = None


class NormalizedEvent(BaseModel):
    """Unified event structure produced by the Perception Engine."""
    id: str = ""
    agent_id: str = ""
    event_type: str = ""
    source: str = ""
    timestamp: datetime = None
    severity: str = "info"
    features: Dict[str, Any] = {}
    raw_payload: Dict[str, Any] = {}


class ReasoningVerdict(BaseModel):
    """Output of the Reasoning Engine for a single event."""
    verdict: str = "unknown"  # benign / suspicious / malicious / requires_investigation
    confidence: float = 0.0
    severity: str = "info"  # info / low / medium / high / critical
    score: float = 0.0
    reasoning_chain: List[Dict[str, Any]] = []
    tool_calls: List[Dict[str, Any]] = []
    actions_taken: List[Dict[str, Any]] = []
    suggested_actions: List[Dict[str, Any]] = []


class ReasoningHistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    event_id: str = ""
    verdict: str = "unknown"
    confidence: float = 0.0
    severity: str = "info"
    reasoning_chain: str = "[]"
    actions_taken: str = "[]"
    outcome: str = "unknown"
    created_at: datetime = None


class AgentBehavioralProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    normal_processes: str = "[]"
    typical_network_patterns: str = "[]"
    baseline_metrics: str = "{}"
    false_positive_patterns: str = "[]"
    updated_at: datetime = None


class AttackPatternSignatureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    pattern_name: str
    mitre_chain: str = "[]"
    event_sequence: str = "[]"
    confidence: float = 0.0
    times_seen: int = 1
    first_seen: datetime = None
    last_seen: datetime = None


class ExecutionPlanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    plan_type: str = "investigation"
    agent_id: str
    trigger_event_id: str = ""
    steps: str = "[]"
    status: str = "planning"
    created_at: datetime = None
    completed_at: datetime = None


class AgentContextSnapshotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    context_data: str = "{}"
    snapshot_at: datetime = None


class ShadowReportEntry(BaseModel):
    """Per-event comparison between shadow verdict and historical rule output."""
    event_id: str = ""
    agent_id: str = ""
    event_type: str = ""
    timestamp: datetime = None
    shadow_verdict: str = ""
    shadow_confidence: float = 0.0
    shadow_severity: str = "info"
    actual_alert: bool = False
    actual_alert_id: str = ""
    actual_severity: str = ""


class ShadowReport(BaseModel):
    """Aggregate comparison of agentic decisions vs. rule-matched alerts."""
    total_events: int = 0
    matched: int = 0
    shadow_only: int = 0
    alert_only: int = 0
    agreement_rate: float = 0.0
    entries: List[ShadowReportEntry] = []
