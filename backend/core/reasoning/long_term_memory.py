"""Long-Term Memory — persistence for reasoning traces, profiles and patterns."""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional


class LongTermMemory:
    """Read/write access to the reasoning DB tables.

    Every method takes an explicit ``db`` session; the caller owns commit/close.
    """

    # --- reasoning history ---------------------------------------------------

    def log_reasoning(self, db, agent_id: str, event_id: str, verdict: str,
                      confidence: float, severity: str, reasoning_chain: List[dict],
                      actions_taken: Optional[List[dict]] = None,
                      outcome: str = "unknown") -> Optional[str]:
        try:
            from models.reasoning import ReasoningHistory
            row = ReasoningHistory(
                agent_id=agent_id,
                event_id=event_id,
                verdict=verdict,
                confidence=min(max(float(confidence), 0.0), 1.0),
                severity=severity,
                reasoning_chain=json.dumps(reasoning_chain, default=str),
                actions_taken=json.dumps(actions_taken or [], default=str),
                outcome=outcome,
            )
            db.add(row)
            db.commit()
            return row.id
        except Exception:
            db.rollback()
            return None

    def fetch_recent_reasoning(self, db, agent_id: str = "", limit: int = 20) -> List[dict]:
        try:
            from models.reasoning import ReasoningHistory
            query = db.query(ReasoningHistory).order_by(ReasoningHistory.created_at.desc())
            if agent_id:
                query = query.filter(ReasoningHistory.agent_id == agent_id)
            rows = query.limit(limit).all()
            return [
                {
                    "id": r.id, "agent_id": r.agent_id, "event_id": r.event_id,
                    "verdict": r.verdict, "confidence": r.confidence, "severity": r.severity,
                    "reasoning_chain": json.loads(r.reasoning_chain or "[]"),
                    "actions_taken": json.loads(r.actions_taken or "[]"),
                    "outcome": r.outcome,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ]
        except Exception:
            return []

    # --- agent behavioral profiles -------------------------------------------

    def upsert_profile(self, db, agent_id: str, normal_processes: Optional[List[str]] = None,
                       typical_network_patterns: Optional[List[str]] = None,
                       baseline_metrics: Optional[Dict[str, Any]] = None,
                       false_positive_patterns: Optional[List[str]] = None) -> None:
        try:
            from models.reasoning import AgentBehavioralProfile
            profile = db.query(AgentBehavioralProfile).filter(
                AgentBehavioralProfile.agent_id == agent_id
            ).first()
            if profile is None:
                profile = AgentBehavioralProfile(agent_id=agent_id)
                db.add(profile)
            if normal_processes is not None:
                profile.normal_processes = json.dumps(normal_processes)
            if typical_network_patterns is not None:
                profile.typical_network_patterns = json.dumps(typical_network_patterns)
            if baseline_metrics is not None:
                profile.baseline_metrics = json.dumps(baseline_metrics)
            if false_positive_patterns is not None:
                profile.false_positive_patterns = json.dumps(false_positive_patterns)
            profile.updated_at = datetime.utcnow()
            db.commit()
        except Exception:
            db.rollback()

    def fetch_profile(self, db, agent_id: str) -> Optional[dict]:
        try:
            from models.reasoning import AgentBehavioralProfile
            profile = db.query(AgentBehavioralProfile).filter(
                AgentBehavioralProfile.agent_id == agent_id
            ).first()
            if profile is None:
                return None
            return {
                "id": profile.id, "agent_id": profile.agent_id,
                "normal_processes": json.loads(profile.normal_processes or "[]"),
                "typical_network_patterns": json.loads(profile.typical_network_patterns or "[]"),
                "baseline_metrics": json.loads(profile.baseline_metrics or "{}"),
                "false_positive_patterns": json.loads(profile.false_positive_patterns or "[]"),
                "updated_at": profile.updated_at.isoformat() if profile.updated_at else None,
            }
        except Exception:
            return None

    # --- attack pattern signatures --------------------------------------------

    def record_pattern(self, db, pattern_name: str, mitre_chain: List[str],
                       event_sequence: List[str], confidence: float = 0.7) -> None:
        try:
            from models.reasoning import AttackPatternSignature
            pattern = db.query(AttackPatternSignature).filter(
                AttackPatternSignature.pattern_name == pattern_name
            ).first()
            now = datetime.utcnow()
            if pattern is None:
                pattern = AttackPatternSignature(
                    pattern_name=pattern_name,
                    mitre_chain=json.dumps(mitre_chain),
                    event_sequence=json.dumps(event_sequence),
                    confidence=confidence,
                    times_seen=1,
                    first_seen=now,
                )
                db.add(pattern)
            else:
                pattern.times_seen = (pattern.times_seen or 0) + 1
                pattern.confidence = min(1.0, (pattern.confidence or 0.0) + 0.05)
            pattern.last_seen = now
            db.commit()
        except Exception:
            db.rollback()

    def fetch_patterns(self, db, limit: int = 50) -> List[dict]:
        try:
            from models.reasoning import AttackPatternSignature
            rows = db.query(AttackPatternSignature).order_by(
                AttackPatternSignature.times_seen.desc()
            ).limit(limit).all()
            return [
                {
                    "id": p.id, "pattern_name": p.pattern_name,
                    "mitre_chain": json.loads(p.mitre_chain or "[]"),
                    "event_sequence": json.loads(p.event_sequence or "[]"),
                    "confidence": p.confidence, "times_seen": p.times_seen,
                    "first_seen": p.first_seen.isoformat() if p.first_seen else None,
                    "last_seen": p.last_seen.isoformat() if p.last_seen else None,
                }
                for p in rows
            ]
        except Exception:
            return []


long_term_memory = LongTermMemory()
