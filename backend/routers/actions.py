"""Agent response action routes (pending actions, block, isolate, kill-process, etc.)."""
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.agent import Agent
from models.alert import PendingAction
from authentication.dependencies import get_owned_agent, verify_agent_self

router = APIRouter(tags=["actions"])


@router.get("/agents/{agent_id}/pending-actions")
async def get_pending_actions(
    agent_id: str,
    agent: Agent = Depends(verify_agent_self),
    db: DBSession = Depends(get_db),
):
    rows = db.query(PendingAction).filter(PendingAction.agent_id == agent_id, PendingAction.status == "pending").all()
    actions = []
    for r in rows:
        actions.append({"action": r.action, "target": r.target, "source": r.source, "created_at": r.created_at.isoformat()})
        r.status = "delivered"
        r.delivered_at = datetime.utcnow()
    db.commit()
    return {"agent_id": agent_id, "actions": actions}


@router.post("/agents/{agent_id}/block")
async def block_agent_target(
    agent_id: str,
    target: str = Query(...),
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    action = PendingAction(agent_id=agent_id, action="network_block", target=target, source="manual")
    db.add(action)
    db.commit()
    return {"status": "queued", "action": {"action": action.action, "target": action.target, "source": action.source, "created_at": action.created_at.isoformat()}}


@router.post("/agents/{agent_id}/isolate")
async def isolate_agent(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    action = PendingAction(agent_id=agent_id, action="host_isolate", target="", source="manual")
    db.add(action)
    db.commit()
    return {"status": "queued", "action": {"action": action.action, "target": action.target, "source": action.source, "created_at": action.created_at.isoformat()}}


@router.post("/agents/{agent_id}/kill-process")
async def kill_agent_process(
    agent_id: str,
    pid: int = Query(...),
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    action = PendingAction(agent_id=agent_id, action="process_terminate", target=str(pid), source="manual")
    db.add(action)
    db.commit()
    return {"status": "queued", "action": {"action": action.action, "target": action.target, "source": action.source, "created_at": action.created_at.isoformat()}}


@router.post("/agents/{agent_id}/quarantine-file")
async def quarantine_agent_file(
    agent_id: str,
    file_path: str = Query(...),
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    action = PendingAction(agent_id=agent_id, action="quarantine_file", target=file_path, source="manual")
    db.add(action)
    db.commit()
    return {"status": "queued", "action": {"action": action.action, "target": action.target, "source": action.source, "created_at": action.created_at.isoformat()}}


@router.post("/agents/{agent_id}/dns-block")
async def dns_block_agent(
    agent_id: str,
    domain: str = Query(...),
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    action = PendingAction(agent_id=agent_id, action="dns_block", target=domain, source="manual")
    db.add(action)
    db.commit()
    return {"status": "queued", "action": {"action": action.action, "target": action.target, "source": action.source, "created_at": action.created_at.isoformat()}}
