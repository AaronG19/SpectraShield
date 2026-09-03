"""Planning Engine — HTN-style investigation / response / remediation plans.

Plans are composed from step recipes, persisted in ``execution_plans`` and
executed through the Tool Executor. High-impact response steps require analyst
approval; the plan pauses until ``approve_step`` resumes it.
"""
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.logging import logger

MAX_STEPS = 20

# Plan step statuses
PENDING = "pending"
RUNNING = "running"
AWAITING_APPROVAL = "awaiting_approval"
COMPLETED = "completed"
FAILED = "failed"
SKIPPED = "skipped"

# Plan statuses
PLAN_PLANNING = "planning"
PLAN_EXECUTING = "executing"
PLAN_PAUSED = "paused"
PLAN_COMPLETED = "completed"
PLAN_ABORTED = "aborted"


def _step(step_type: str, tool: str, args: Dict[str, Any], description: str = "",
          depends_on: Optional[List[str]] = None, approval_required: bool = False,
          timeout_seconds: int = 30) -> dict:
    return {
        "id": f"{step_type}_{tool}",
        "type": step_type,
        "tool": tool,
        "args": args,
        "description": description,
        "depends_on": depends_on or [],
        "approval_required": approval_required,
        "status": PENDING,
        "result": None,
        "timeout_seconds": timeout_seconds,
    }


class PlanningEngine:
    """Builds and orchestrates multi-step plans backed by the Tool Executor."""

    def __init__(self, max_steps: Optional[int] = None):
        self._max_steps = max_steps or MAX_STEPS

    # --- recipe builders ------------------------------------------------------

    def investigation_steps(self, agent_id: str, event_type: str = "", verdict: str = "") -> List[dict]:
        return [
            _step("investigate", "query_agent_activity",
                  {"agent_id": agent_id, "limit": 50},
                  f"Gather recent activity for agent {agent_id}"),
            _step("investigate", "query_recent_alerts",
                  {"agent_id": agent_id, "status": "open", "limit": 20},
                  "Check open alerts for context"),
            _step("investigate", "query_reasoning_history",
                  {"agent_id": agent_id, "limit": 10},
                  "Recall prior reasoning traces"),
            _step("correlate", "correlate_event",
                  {"event": {"event_type": event_type, "severity": verdict}, "agent_id": agent_id,
                   "event_type": event_type, "source": "reasoning_plan"},
                  "Correlate with active incidents"),
        ]

    def response_steps(self, agent_id: str, suggested_actions: List[Dict[str, Any]]) -> List[dict]:
        steps = []
        for action in suggested_actions or []:
            action_name = action.get("action", "alert_only")
            if action_name == "alert_only":
                continue
            steps.append(_step(
                "response", "execute_response",
                {"action": action_name, "target": action.get("target", ""), "agent_id": agent_id},
                f"Execute {action_name} on {action.get('target') or agent_id}",
                approval_required=False,
            ))
        return steps

    def remediation_steps(self, agent_id: str) -> List[dict]:
        return [
            _step("remediate", "update_baseline",
                  {"agent_id": agent_id, "metrics": {}},
                  "Refresh behavioral baseline after investigation"),
        ]

    def build_plan_steps(self, verdict: str, severity: str, agent_id: str,
                         event_type: str = "", suggested_actions: Optional[List[dict]] = None) -> List[dict]:
        steps: List[dict] = []
        steps.extend(self.investigation_steps(agent_id, event_type, verdict))
        if verdict == "malicious" or severity in ("high", "critical"):
            steps.extend(self.response_steps(agent_id, suggested_actions or []))
        if verdict in ("malicious", "suspicious"):
            steps.extend(self.remediation_steps(agent_id))
        return steps[: self._max_steps]

    # --- persistence ----------------------------------------------------------

    def create_plan(self, db, plan_type: str, agent_id: str, trigger_event_id: str = "",
                    verdict: str = "", severity: str = "info", event_type: str = "",
                    suggested_actions: Optional[List[dict]] = None) -> Optional[dict]:
        try:
            from models.reasoning import ExecutionPlan
            steps = self.build_plan_steps(verdict, severity, agent_id, event_type, suggested_actions)
            row = ExecutionPlan(
                plan_type=plan_type,
                agent_id=agent_id,
                trigger_event_id=trigger_event_id,
                steps=json.dumps(steps),
                status=PLAN_PLANNING,
            )
            db.add(row)
            db.commit()
            logger.info("Plan created", plan_id=row.id, plan_type=plan_type, agent_id=agent_id, steps=len(steps))
            try:
                from core.reasoning.notifications import broadcast_plan_update
                broadcast_plan_update(row.id, agent_id, PLAN_PLANNING, plan_type)
            except Exception:
                pass
            return {"id": row.id, "plan_type": plan_type, "agent_id": agent_id,
                    "trigger_event_id": trigger_event_id, "steps": steps, "status": PLAN_PLANNING}
        except Exception:
            db.rollback()
            return None

    def get_plan(self, db, plan_id: str) -> Optional[dict]:
        from models.reasoning import ExecutionPlan
        row = db.query(ExecutionPlan).filter(ExecutionPlan.id == plan_id).first()
        if row is None:
            return None
        return self._plan_to_dict(row)

    def list_plans(self, db, agent_id: str = "", status: str = "") -> List[dict]:
        from models.reasoning import ExecutionPlan
        query = db.query(ExecutionPlan).order_by(ExecutionPlan.created_at.desc())
        if agent_id:
            query = query.filter(ExecutionPlan.agent_id == agent_id)
        if status:
            query = query.filter(ExecutionPlan.status == status)
        return [self._plan_to_dict(row) for row in query.all()]

    def _plan_to_dict(self, row) -> dict:
        return {
            "id": row.id, "plan_type": row.plan_type, "agent_id": row.agent_id,
            "trigger_event_id": row.trigger_event_id,
            "steps": json.loads(row.steps or "[]"),
            "status": row.status,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        }

    # --- orchestration ----------------------------------------------------------

    async def run_plan(self, db, plan_id: str) -> dict:
        from models.reasoning import ExecutionPlan
        from core.reasoning.tool_executor import get_tool_executor
        executor = get_tool_executor()

        row = db.query(ExecutionPlan).filter(ExecutionPlan.id == plan_id).first()
        if row is None:
            return {"error": "plan not found"}
        if row.status in (PLAN_COMPLETED, PLAN_ABORTED):
            return self._plan_to_dict(row)

        steps = json.loads(row.steps or "[]")
        row.status = PLAN_EXECUTING
        db.commit()

        completed_map = {s["id"]: s for s in steps if s["status"] in (COMPLETED, SKIPPED)}
        for step in steps:
            if step["status"] in (COMPLETED, FAILED, SKIPPED, AWAITING_APPROVAL):
                continue
            deps = [completed_map.get(d) for d in step.get("depends_on", [])]
            if any(d is None or d["status"] != COMPLETED for d in deps):
                continue
            if step.get("approval_required"):
                step["status"] = AWAITING_APPROVAL
                row.status = PLAN_PAUSED
                self._save_steps(db, row, steps)
                logger.info("Plan paused for approval", plan_id=plan_id, step=step["id"])
                try:
                    from core.reasoning.notifications import broadcast_plan_update
                    broadcast_plan_update(plan_id, row.agent_id, PLAN_PAUSED, row.plan_type, awaiting_approval=True)
                except Exception:
                    pass
                return self._plan_to_dict(row)

            step["status"] = RUNNING
            self._save_steps(db, row, steps)
            try:
                result = await executor.execute(step["tool"], **step.get("args", {}))
                step["status"] = COMPLETED if result.get("status") == "success" else FAILED
                step["result"] = result
            except Exception as exc:
                step["status"] = FAILED
                step["result"] = {"status": "error", "error": str(exc)}
            completed_map[step["id"]] = step
            self._save_steps(db, row, steps)

        if all(s["status"] in (COMPLETED, FAILED, SKIPPED) for s in steps):
            row.status = PLAN_COMPLETED
            row.completed_at = datetime.utcnow()
            db.commit()
            try:
                from core.reasoning.notifications import broadcast_plan_update
                broadcast_plan_update(plan_id, row.agent_id, PLAN_COMPLETED, row.plan_type)
            except Exception:
                pass
        return self._plan_to_dict(row)

    async def approve_step(self, db, plan_row, tool_executor=None) -> dict:
        """Analyst approval for paused plans: resume execution."""
        from core.reasoning.tool_executor import get_tool_executor
        executor = tool_executor or get_tool_executor()

        steps = json.loads(plan_row.steps or "[]")
        for step in steps:
            if step["status"] == AWAITING_APPROVAL:
                step["status"] = PENDING
        plan_row.steps = json.dumps(steps)
        db.commit()
        return await self.run_plan(db, plan_row.id)

    def _save_steps(self, db, row, steps: List[dict]) -> None:
        row.steps = json.dumps(steps)
        db.commit()


planning_engine = PlanningEngine()
