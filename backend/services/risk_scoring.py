import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.logging import logger


RISK_CATEGORIES = {
    "malware": {"base_score": 60, "weight": 1.5},
    "phishing": {"base_score": 50, "weight": 1.3},
    "c2_beaconing": {"base_score": 85, "weight": 1.8},
    "privilege_escalation": {"base_score": 70, "weight": 1.6},
    "fileless_malware": {"base_score": 80, "weight": 1.7},
    "ransomware": {"base_score": 95, "weight": 2.0},
    "port_scan": {"base_score": 30, "weight": 1.0},
    "misconfiguration": {"base_score": 20, "weight": 0.8},
    "shadow_it": {"base_score": 15, "weight": 0.7},
    "credential_dumping": {"base_score": 85, "weight": 1.9},
    "lateral_movement": {"base_score": 75, "weight": 1.8},
    "tamper": {"base_score": 70, "weight": 1.5},
    "usb_violation": {"base_score": 35, "weight": 1.0},
    "policy_violation": {"base_score": 15, "weight": 0.6},
    "zero_day": {"base_score": 90, "weight": 2.0},
    "lolbin": {"base_score": 60, "weight": 1.4},
    "beaconing": {"base_score": 65, "weight": 1.6},
    "reconnaissance": {"base_score": 25, "weight": 0.9},
    "exploit": {"base_score": 80, "weight": 1.8},
    "behavioral_anomaly": {"base_score": 40, "weight": 1.2},
    "persistence": {"base_score": 60, "weight": 1.5},
    "file_integrity": {"base_score": 30, "weight": 1.0},
    "process_anomaly": {"base_score": 45, "weight": 1.3},
    "network_anomaly": {"base_score": 50, "weight": 1.4},
    "script_block": {"base_score": 55, "weight": 1.4},
    "dns_block": {"base_score": 40, "weight": 1.2},
    "firewall_block": {"base_score": 30, "weight": 1.0},
}

SEVERITY_MULTIPLIERS = {
    "low": 0.5,
    "medium": 1.0,
    "high": 1.5,
    "critical": 2.0,
}

RISK_THRESHOLDS = {
    "low": 20,
    "medium": 40,
    "high": 65,
    "critical": 85,
}


class RiskScore:
    def __init__(
        self,
        base_score: float = 0,
        multiplier: float = 1.0,
        components: Optional[Dict[str, float]] = None,
        agent_id: Optional[str] = None,
        event_id: Optional[str] = None,
        event_type: str = "unknown",
    ):
        self.base_score = base_score
        self.multiplier = multiplier
        self.components = components or {}
        self.agent_id = agent_id
        self.event_id = event_id
        self.event_type = event_type
        self.calculated_at = datetime.now(timezone.utc).isoformat()

    @property
    def total_score(self) -> float:
        raw = self.base_score * self.multiplier
        component_bonus = sum(self.components.values())
        return min(100.0, raw + component_bonus)

    @property
    def severity(self) -> str:
        score = self.total_score
        if score >= RISK_THRESHOLDS["critical"]:
            return "critical"
        elif score >= RISK_THRESHOLDS["high"]:
            return "high"
        elif score >= RISK_THRESHOLDS["medium"]:
            return "medium"
        else:
            return "low"

    def to_dict(self) -> dict:
        return {
            "base_score": self.base_score,
            "multiplier": self.multiplier,
            "components": self.components,
            "total_score": self.total_score,
            "severity": self.severity,
            "event_type": self.event_type,
            "calculated_at": self.calculated_at,
        }


class RiskScoringEngine:
    def __init__(
        self,
        thresholds: Optional[Dict[str, int]] = None,
        time_decay_hours: int = 24,
    ):
        self.thresholds = thresholds or RISK_THRESHOLDS.copy()
        self.time_decay_hours = time_decay_hours
        self._agent_scores: Dict[str, List[dict]] = defaultdict(list)

    def calculate_score(
        self,
        event_type: str,
        severity: str = "medium",
        agent_id: Optional[str] = None,
        event_id: Optional[str] = None,
        additional_components: Optional[Dict[str, float]] = None,
    ) -> RiskScore:
        category = RISK_CATEGORIES.get(event_type, {"base_score": 25, "weight": 1.0})
        base_score = category["base_score"]
        weight = category["weight"]
        sev_mult = SEVERITY_MULTIPLIERS.get(severity, 1.0)
        multiplier = weight * sev_mult

        score = RiskScore(
            base_score=base_score,
            multiplier=multiplier,
            components=additional_components or {},
            agent_id=agent_id,
            event_id=event_id,
            event_type=event_type,
        )

        if agent_id:
            self._record_score(agent_id, score)
            self._apply_recency_bonus(agent_id, score)

        return score

    def calculate_behavioral_score(self, behavioral_result: dict, agent_id: Optional[str] = None) -> RiskScore:
        max_risk = behavioral_result.get("max_risk_score", 0)
        finding_count = behavioral_result.get("total_findings", 0)
        detection_types = behavioral_result.get("detection_types", [])

        components = {
            "max_finding_risk": max_risk * 0.5,
            "finding_count_bonus": min(finding_count * 5, 25),
        }

        return self.calculate_score(
            event_type="behavioral_anomaly",
            severity="high" if max_risk >= 50 else "medium" if max_risk >= 20 else "low",
            agent_id=agent_id,
            additional_components=components,
        )

    def check_threshold(self, score: RiskScore) -> Optional[dict]:
        total = score.total_score
        if total >= self.thresholds.get("critical", 85):
            return {"level": "critical", "message": f"Critical risk threshold exceeded: {total:.1f}", "triggered": True}
        elif total >= self.thresholds.get("high", 65):
            return {"level": "high", "message": f"High risk threshold exceeded: {total:.1f}", "triggered": True}
        elif total >= self.thresholds.get("medium", 40):
            return {"level": "medium", "message": f"Medium risk threshold reached: {total:.1f}", "triggered": True}
        return {"level": "low", "message": "Risk score below thresholds", "triggered": False}

    def get_agent_risk_summary(self, agent_id: str) -> dict:
        scores = self._agent_scores.get(agent_id, [])
        if not scores:
            return {"agent_id": agent_id, "total_events": 0, "current_risk": 0, "severity": "none", "history": []}

        recent = [s for s in scores if self._is_recent(s)]
        current = max(s["total_score"] for s in recent) if recent else 0

        return {
            "agent_id": agent_id,
            "total_events": len(scores),
            "recent_events": len(recent),
            "current_risk": round(current, 1),
            "severity": self._score_to_severity(current),
            "history": sorted(scores, key=lambda x: x["calculated_at"], reverse=True)[:50],
        }

    def _record_score(self, agent_id: str, score: RiskScore):
        self._agent_scores[agent_id].append(score.to_dict())

    def _apply_recency_bonus(self, agent_id: str, score: RiskScore):
        recent = [s for s in self._agent_scores.get(agent_id, []) if self._is_recent(s)]
        if len(recent) >= 3:
            score.components["recency_bonus"] = min(len(recent) * 2, 15)

    def _is_recent(self, score_dict: dict) -> bool:
        try:
            ts = score_dict.get("calculated_at", "")
            if isinstance(ts, str):
                dt = datetime.fromisoformat(ts)
            else:
                dt = ts
            delta = datetime.now(timezone.utc) - dt
            return delta.total_seconds() < self.time_decay_hours * 3600
        except Exception:
            return True

    def _score_to_severity(self, score: float) -> str:
        if score >= self.thresholds.get("critical", 85):
            return "critical"
        elif score >= self.thresholds.get("high", 65):
            return "high"
        elif score >= self.thresholds.get("medium", 40):
            return "medium"
        return "low"
