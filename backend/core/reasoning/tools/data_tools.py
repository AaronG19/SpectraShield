"""Data tools — safe DB query primitives for the Reasoning Engine.

Each tool opens its own short-lived session via SessionLocal, so reasoning
never borrows a request-scoped DB session. Queries are read-only.
"""
import json

from core.reasoning.tool_executor import ReasoningTool


def _session():
    from db.base import SessionLocal
    return SessionLocal()


class QueryRecentAlertsTool(ReasoningTool):
    name = "query_recent_alerts"
    description = "Fetch recent alerts for an agent (optionally filtered by status)."
    category = "data"

    def run(self, agent_id: str = "", status: str = "", limit: int = 20) -> dict:
        from models.alert import Alert
        db = _session()
        try:
            query = db.query(Alert).order_by(Alert.created_at.desc())
            if agent_id:
                query = query.filter(Alert.agent_id == agent_id)
            if status:
                query = query.filter(Alert.status == status)
            rows = query.limit(limit).all()
            return self._result([
                {
                    "id": a.id, "agent_id": a.agent_id, "title": a.title,
                    "severity": a.severity, "type": a.type, "status": a.status,
                    "score": a.score, "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in rows
            ])
        finally:
            db.close()


class QueryAlertCountsTool(ReasoningTool):
    name = "query_alert_counts"
    description = "Count open alerts for an agent grouped by severity."
    category = "data"

    def run(self, agent_id: str = "") -> dict:
        from sqlalchemy import func
        from models.alert import Alert
        db = _session()
        try:
            query = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
            if agent_id:
                query = query.filter(Alert.agent_id == agent_id)
            counts = {sev: cnt for sev, cnt in query.all()}
            return self._result(counts)
        finally:
            db.close()


class QueryReasoningHistoryTool(ReasoningTool):
    name = "query_reasoning_history"
    description = "Fetch prior reasoning traces for an agent (long-term memory)."
    category = "data"

    def run(self, agent_id: str = "", limit: int = 20) -> dict:
        from models.reasoning import ReasoningHistory
        db = _session()
        try:
            query = db.query(ReasoningHistory).order_by(ReasoningHistory.created_at.desc())
            if agent_id:
                query = query.filter(ReasoningHistory.agent_id == agent_id)
            rows = query.limit(limit).all()
            return self._result([
                {
                    "id": r.id, "agent_id": r.agent_id, "event_id": r.event_id,
                    "verdict": r.verdict, "confidence": r.confidence, "severity": r.severity,
                    "outcome": r.outcome, "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ])
        finally:
            db.close()


class QueryAgentProfileTool(ReasoningTool):
    name = "query_agent_profile"
    description = "Fetch the learned behavioral profile for an agent (long-term memory)."
    category = "data"

    def run(self, agent_id: str = "") -> dict:
        from models.reasoning import AgentBehavioralProfile
        db = _session()
        try:
            profile = db.query(AgentBehavioralProfile).filter(
                AgentBehavioralProfile.agent_id == agent_id
            ).first()
            if profile is None:
                return self._result(None)
            return self._result({
                "id": profile.id, "agent_id": profile.agent_id,
                "normal_processes": json.loads(profile.normal_processes or "[]"),
                "typical_network_patterns": json.loads(profile.typical_network_patterns or "[]"),
                "baseline_metrics": json.loads(profile.baseline_metrics or "{}"),
                "false_positive_patterns": json.loads(profile.false_positive_patterns or "[]"),
                "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
            })
        finally:
            db.close()


class QueryAgentActivityTool(ReasoningTool):
    name = "query_agent_activity"
    description = "Summarize recent security-relevant activity for an agent across event tables."
    category = "data"

    def run(self, agent_id: str = "", limit: int = 20) -> dict:
        db = _session()
        try:
            from models.events import (
                ProcessExecutionEvent, RegistryChange, LateralMovementEvent,
                PortScanEvent, C2BeaconingEvent,
            )
            summary = {}
            tables = {
                "process_executions": ProcessExecutionEvent,
                "registry_changes": RegistryChange,
                "lateral_movement": LateralMovementEvent,
                "port_scans": PortScanEvent,
                "c2_beaconing": C2BeaconingEvent,
            }
            for key, model in tables.items():
                try:
                    summary[key] = db.query(model).filter(model.agent_id == agent_id).count()
                except Exception:
                    summary[key] = 0
            return self._result(summary)
        finally:
            db.close()
