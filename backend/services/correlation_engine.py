from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import json
import uuid

from core.logging import logger


ATTACK_CHAIN_STEPS = [
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

CHAIN_PATTERNS: List[Dict] = [
    {
        "name": "office_macro_to_ransomware",
        "steps": ["initial_access", "execution", "persistence", "impact"],
        "description": "Office document macro leads to ransomware deployment",
        "severity": "critical",
    },
    {
        "name": "phishing_to_credential_theft",
        "steps": ["initial_access", "execution", "credential_access", "exfiltration"],
        "description": "Phishing attack leading to credential theft and data exfiltration",
        "severity": "critical",
    },
    {
        "name": "web_download_to_persistence",
        "steps": ["execution", "persistence", "defense_evasion"],
        "description": "Web-delivered payload establishing persistence",
        "severity": "high",
    },
    {
        "name": "lateral_movement_campaign",
        "steps": ["credential_access", "lateral_movement", "execution"],
        "description": "Credential theft enabling lateral movement across hosts",
        "severity": "critical",
    },
    {
        "name": "recon_to_exploit",
        "steps": ["discovery", "execution", "privilege_escalation", "impact"],
        "description": "Reconnaissance followed by exploitation and impact",
        "severity": "high",
    },
    {
        "name": "c2_beaconing_to_data_theft",
        "steps": ["command_and_control", "execution", "collection", "exfiltration"],
        "description": "C2 beaconing leading to data collection and exfiltration",
        "severity": "critical",
    },
]

EVENT_TYPE_TO_CHAIN_STEP: Dict[str, str] = {
    "phishing": "initial_access",
    "malware": "execution",
    "lolbin": "execution",
    "script_block": "execution",
    "zero_day": "initial_access",
    "exploit": "initial_access",
    "persistence": "persistence",
    "privilege_escalation": "privilege_escalation",
    "tamper": "defense_evasion",
    "misconfiguration": "defense_evasion",
    "fileless_malware": "defense_evasion",
    "credential_dumping": "credential_access",
    "reconnaissance": "discovery",
    "port_scan": "discovery",
    "lateral_movement": "lateral_movement",
    "shadow_it": "collection",
    "c2_beaconing": "command_and_control",
    "beaconing": "command_and_control",
    "c2_dns": "command_and_control",
    "usb_violation": "initial_access",
    "policy_violation": "defense_evasion",
    "ransomware": "impact",
    "network_anomaly": "command_and_control",
    "behavioral_anomaly": "execution",
}


class CorrelatedIncident:
    def __init__(self, incident_id: Optional[str] = None):
        self.incident_id = incident_id or str(uuid.uuid4())
        self.agent_ids: Set[str] = set()
        self.events: List[dict] = []
        self.attack_chain: List[str] = []
        self.matched_patterns: List[dict] = []
        self.severity: str = "low"
        self.score: float = 0.0
        self.first_event_at: Optional[str] = None
        self.last_event_at: Optional[str] = None
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self.description: str = ""
        self.title: str = ""
        self.status: str = "open"

    def add_event(self, event: dict):
        self.events.append(event)
        agent_id = event.get("agent_id")
        if agent_id:
            self.agent_ids.add(agent_id)

        event_time = event.get("detected_at") or event.get("created_at") or event.get("timestamp")
        if event_time:
            if not self.first_event_at or event_time < self.first_event_at:
                self.first_event_at = event_time
            if not self.last_event_at or event_time > self.last_event_at:
                self.last_event_at = event_time

        step = EVENT_TYPE_TO_CHAIN_STEP.get(event.get("event_type", ""), "execution")
        if step not in self.attack_chain:
            self.attack_chain.append(step)

        event_score = event.get("score", 0) or event.get("risk_score", 0)
        self.score = max(self.score, float(event_score))

    def finalize(self):
        self.attack_chain.sort(key=lambda s: ATTACK_CHAIN_STEPS.index(s) if s in ATTACK_CHAIN_STEPS else 99)
        self._match_patterns()

        if self.score >= 85:
            self.severity = "critical"
        elif self.score >= 65:
            self.severity = "high"
        elif self.score >= 40:
            self.severity = "medium"
        else:
            self.severity = "low"

        self.title = f"Correlated Incident: {' -> '.join(self.attack_chain)}" if self.attack_chain else "Correlated Incident"
        self.description = f"Correlated incident with {len(self.events)} events across {len(self.agent_ids)} host(s). Attack chain: {' -> '.join(self.attack_chain)}"

    def _match_patterns(self):
        for pattern in CHAIN_PATTERNS:
            matched_steps = [s for s in pattern["steps"] if s in self.attack_chain]
            if len(matched_steps) >= 2:
                pattern_score = len(matched_steps) / len(pattern["steps"])
                if pattern_score >= 0.5:
                    self.matched_patterns.append({
                        "pattern_name": pattern["name"],
                        "matched_steps": matched_steps,
                        "coverage": round(pattern_score, 2),
                        "description": pattern["description"],
                        "severity": pattern["severity"],
                    })
                    self.score = max(self.score, 50 * pattern_score)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score": round(self.score, 1),
            "status": self.status,
            "agent_ids": list(self.agent_ids),
            "event_count": len(self.events),
            "attack_chain": self.attack_chain,
            "matched_patterns": self.matched_patterns,
            "first_event_at": self.first_event_at,
            "last_event_at": self.last_event_at,
            "created_at": self.created_at,
        }


class CorrelationEngine:
    def __init__(self, time_window_minutes: int = 60):
        self.time_window = timedelta(minutes=time_window_minutes)
        self._incidents: Dict[str, CorrelatedIncident] = {}
        self._recent_events: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )

    def ingest_event(
        self,
        event: dict,
        agent_id: str = "",
        event_type: str = "",
        source: str = "",
    ) -> Optional[CorrelatedIncident]:
        event["agent_id"] = agent_id
        event["event_type"] = event_type
        event["source"] = source
        event["ingested_at"] = datetime.now(timezone.utc).isoformat()

        cache_key = f"{agent_id}:{source}"
        self._recent_events[cache_key].append(event)

        return self._try_correlate(event, agent_id)

    def _try_correlate(self, event: dict, agent_id: str) -> Optional[CorrelatedIncident]:
        step = EVENT_TYPE_TO_CHAIN_STEP.get(event.get("event_type", ""))
        if not step:
            return None

        cache_key = f"{agent_id}:{event.get('source', '')}"
        related = [
            e for e in self._recent_events.get(cache_key, [])
            if self._within_window(event, e)
            and e.get("event_type") != event.get("event_type")
        ]

        if not related:
            return None

        incident = CorrelatedIncident()
        incident.add_event(event)
        for rel_event in related:
            incident.add_event(rel_event)
        incident.finalize()

        existing = self._find_overlapping_incident(incident)
        if existing:
            for e in incident.events:
                existing.add_event(e)
            existing.finalize()
            self._incidents[existing.incident_id] = existing
            return existing

        self._incidents[incident.incident_id] = incident
        return incident

    def _within_window(self, event_a: dict, event_b: dict) -> bool:
        def _parse_time(ev: dict) -> Optional[datetime]:
            for key in ["ingested_at", "detected_at", "created_at", "timestamp"]:
                val = ev.get(key)
                if val:
                    try:
                        if isinstance(val, str):
                            return datetime.fromisoformat(val.replace("Z", "+00:00"))
                        return val
                    except (ValueError, TypeError):
                        continue
            return None

        ta = _parse_time(event_a)
        tb = _parse_time(event_b)
        if ta and tb:
            return abs((ta - tb).total_seconds()) <= self.time_window.total_seconds()
        return False

    def _find_overlapping_incident(self, incident: CorrelatedIncident) -> Optional[CorrelatedIncident]:
        for existing in self._incidents.values():
            if existing.agent_ids & incident.agent_ids:
                shared_steps = set(existing.attack_chain) & set(incident.attack_chain)
                if shared_steps:
                    return existing
        return None

    def get_active_incidents(self) -> List[dict]:
        return [
            inc.to_dict()
            for inc in self._incidents.values()
            if inc.status == "open"
        ]

    def get_incident(self, incident_id: str) -> Optional[dict]:
        inc = self._incidents.get(incident_id)
        return inc.to_dict() if inc else None

    def resolve_incident(self, incident_id: str) -> bool:
        if incident_id in self._incidents:
            self._incidents[incident_id].status = "resolved"
            return True
        return False

    def cleanup_old(self, max_age_hours: int = 24):
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        to_remove = []
        for inc_id, inc in self._incidents.items():
            try:
                created = datetime.fromisoformat(inc.created_at)
                if created < cutoff:
                    to_remove.append(inc_id)
            except (ValueError, TypeError):
                continue
        for inc_id in to_remove:
            del self._incidents[inc_id]
