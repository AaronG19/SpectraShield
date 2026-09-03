"""Reasoning router — shadow-report, history, tools and (later) plans endpoints.

Route protection follows the existing conventions (get_owned_agent / get_db).
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.agent import Agent
from models.alert import Alert
from models.reasoning import ExecutionPlan, ReasoningHistory
from authentication.dependencies import get_owned_agent
from schemas.reasoning import (
    ExecutionPlanOut, ReasoningHistoryOut, ShadowReport, ShadowReportEntry,
)

router = APIRouter(tags=["reasoning"])


def _get_reasoning():
    from main import (
        reasoning_engine, perception_engine, working_memory,
        planning_engine, tool_executor,
    )
    return (reasoning_engine, perception_engine, working_memory, planning_engine, tool_executor)


@router.get("/reasoning/tools")
async def list_reasoning_tools():
    _reasoning_engine, _perception, _working_memory, _planning, executor = _get_reasoning()
    return {"tools": executor.available_tools(), "count": len(executor.available_tools())}


@router.get("/reasoning/memory")
async def get_reasoning_memory(agent_id: str = Query("", alias="agent_id")):
    _reasoning_engine, _perception, working_memory, _planning, _executor = _get_reasoning()
    if agent_id:
        events = working_memory.get_recent_events(agent_id)
        return {"agent_id": agent_id, "events": [e.to_dict() for e in events], "count": len(events)}
    return {"agents": working_memory.sizes(), "total_events": working_memory.event_count()}


@router.get("/reasoning/shadow-report", response_model=ShadowReport)
async def get_shadow_report(
    agent_id: str = Query("", alias="agent_id"),
    limit: int = Query(200, ge=1, le=2000),
    db: DBSession = Depends(get_db),
):
    """Compare shadow verdicts against actual rule-matched alerts."""
    query = db.query(ReasoningHistory).order_by(ReasoningHistory.created_at.desc())
    if agent_id:
        query = query.filter(ReasoningHistory.agent_id == agent_id)
    history = query.limit(limit).all()

    entries = []
    matched = 0
    shadow_only = 0
    for h in history:
        actual = db.query(Alert).filter(Alert.agent_id == h.agent_id).order_by(
            Alert.created_at.desc()
        ).first()
        shadow_detected = h.verdict in ("suspicious", "malicious", "requires_investigation")
        actual_detected = actual is not None and actual.status == "open"
        if shadow_detected and actual_detected:
            matched += 1
        elif shadow_detected and not actual_detected:
            shadow_only += 1
        entries.append(ShadowReportEntry(
            event_id=h.event_id, agent_id=h.agent_id, event_type="", timestamp=h.created_at,
            shadow_verdict=h.verdict, shadow_confidence=h.confidence, shadow_severity=h.severity,
            actual_alert=actual_detected, actual_alert_id=actual.id if actual else "",
            actual_severity=actual.severity if actual else "",
        ))

    total = len(entries)
    agreement = round((matched / total) * 100, 2) if total else 0.0
    return ShadowReport(
        total_events=total, matched=matched,
        shadow_only=shadow_only,
        alert_only=0,
        agreement_rate=agreement,
        entries=entries,
    )


@router.get("/reasoning/history/{agent_id}", response_model=list[ReasoningHistoryOut])
async def get_reasoning_history(
    agent_id: str,
    limit: int = Query(50, ge=1, le=500),
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    rows = db.query(ReasoningHistory).filter(
        ReasoningHistory.agent_id == agent_id
    ).order_by(ReasoningHistory.created_at.desc()).limit(limit).all()
    return rows


@router.get("/reasoning/plans/{agent_id}", response_model=list[ExecutionPlanOut])
async def get_agent_plans(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    rows = db.query(ExecutionPlan).filter(
        ExecutionPlan.agent_id == agent_id
    ).order_by(ExecutionPlan.created_at.desc()).all()
    return rows


@router.post("/reasoning/plans/{plan_id}/approve")
async def approve_plan(
    plan_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    plan = db.query(ExecutionPlan).filter(ExecutionPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    _reasoning_engine, _perception, _working_memory, planning_engine, _executor = _get_reasoning()
    await planning_engine.approve_step(db, plan)
    return {"status": "approved", "plan_id": plan_id, "plan_status": plan.status}


@router.post("/reasoning/plans/{plan_id}/run")
async def run_plan(
    plan_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    plan = db.query(ExecutionPlan).filter(ExecutionPlan.id == plan_id).first()
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")
    _reasoning_engine, _perception, _working_memory, planning_engine, _executor = _get_reasoning()
    return await planning_engine.run_plan(db, plan_id)
