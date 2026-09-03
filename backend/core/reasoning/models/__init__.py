"""Internal dataclasses / domain objects for the reasoning layer."""
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedEvent:
    """Unified representation of any telemetry payload produced by the Perception Engine."""
    event_type: str
    agent_id: str
    source: str = "telemetry"
    event_id: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    severity: str = "info"
    features: Dict[str, Any] = field(default_factory=dict)
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.event_id or f"{self.agent_id}:{self.event_type}:{int(self.timestamp.timestamp() * 1000)}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "source": self.source,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "features": self.features,
            "raw_payload": self.raw_payload,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NormalizedEvent":
        ts = data.get("timestamp")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                ts = None
        return cls(
            event_type=data.get("event_type", ""),
            agent_id=data.get("agent_id", ""),
            source=data.get("source", "telemetry"),
            event_id=data.get("event_id", ""),
            timestamp=ts or datetime.utcnow(),
            severity=data.get("severity", "info"),
            features=data.get("features", {}),
            raw_payload=data.get("raw_payload", {}),
        )


@dataclass
class AgentContext:
    """Per-agent working memory window."""
    agent_id: str
    events: deque = field(default_factory=lambda: deque(maxlen=None))
    last_updated: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        self.last_updated = datetime.utcnow()

    def push(self, event: NormalizedEvent) -> None:
        self.events.append(event)
        self.touch()

    def recent(self, ttl_seconds: Optional[int] = None) -> List[NormalizedEvent]:
        cutoff = datetime.utcnow().timestamp()
        if ttl_seconds:
            cutoff -= ttl_seconds
        kept = [e for e in self.events if e.timestamp.timestamp() >= cutoff]
        if len(kept) != len(self.events):
            self.events = deque(kept, maxlen=self.events.maxlen)
        return kept
