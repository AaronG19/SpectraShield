import time
from typing import Dict, List, Optional


EVENT_TYPES = {
    "process_created": "Process Created",
    "network_connection": "Network Connection",
    "file_created": "File Created",
    "file_executed": "File Executed",
    "persistence_added": "Persistence Added",
    "threat_intel_match": "Threat Intel Match",
    "behavioral_alert": "Behavioral Alert",
    "beaconing_detected": "Beaconing Detected",
    "lolbin_detected": "LOLBin Detected",
    "credential_dumping": "Credential Dumping",
    "correlated_threat": "Correlated Threat",
    "suspicious_service": "Suspicious Service",
    "scheduled_task": "Suspicious Scheduled Task",
    "office_macro": "Office Macro Execution",
}


class InvestigationTimeline:
    def __init__(self, max_events: int = 1000):
        self._events: List[dict] = []
        self._max_events = max_events

    def add_event(
        self,
        event_type: str,
        description: str,
        severity: str = "INFO",
        details: Optional[dict] = None,
    ):
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "event_label": EVENT_TYPES.get(event_type, event_type),
            "description": description,
            "severity": severity.upper(),
            "details": details or {},
        }
        self._events.append(event)
        # Trim oldest
        if len(self._events) > self._max_events:
            self._events[:] = self._events[-self._max_events:]

    def add_alert_event(self, alert: dict):
        event_type = alert.get("rule", "behavioral_alert")
        if event_type == "c2_beaconing":
            event_type = "beaconing_detected"
        elif event_type in ("lolbin_abuse",):
            event_type = "lolbin_detected"
        elif event_type == "credential_dumping":
            event_type = "credential_dumping"
        elif event_type in ("suspicious_service",):
            event_type = "suspicious_service"
        elif event_type == "scheduled_task":
            event_type = "scheduled_task"
        elif event_type == "office_macro_execution":
            event_type = "office_macro"
        self.add_event(
            event_type=event_type,
            description=alert.get("description", ""),
            severity=alert.get("severity", "MEDIUM"),
            details=alert,
        )

    def get_timeline(
        self,
        since: Optional[float] = None,
        limit: int = 100,
        min_severity: str = "INFO",
    ) -> List[dict]:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        min_order = severity_order.get(min_severity.upper(), 4)
        filtered = [
            e for e in self._events
            if severity_order.get(e["severity"], 4) <= min_order
            and (since is None or e["timestamp"] >= since)
        ]
        filtered.sort(key=lambda e: e["timestamp"], reverse=True)
        return filtered[:limit]

    def get_timeline_since(self, seconds: float = 3600) -> List[dict]:
        return self.get_timeline(since=time.time() - seconds)

    def get_summary(self) -> dict:
        counts = {}
        for e in self._events:
            et = e["event_type"]
            counts[et] = counts.get(et, 0) + 1
        return {
            "total_events": len(self._events),
            "event_counts": counts,
            "alert_count": sum(
                1 for e in self._events
                if e["severity"] in ("CRITICAL", "HIGH", "MEDIUM")
            ),
        }
