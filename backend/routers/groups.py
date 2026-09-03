"""Agent grouping routes."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.agent import Agent
from authentication.dependencies import get_owned_agent

router = APIRouter(tags=["groups"])


@router.patch("/agents/{agent_id}/group")
async def set_agent_group(
    agent_id: str,
    group: str = Query(...),
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.group_name = group
    db.commit()
    return {"agent_id": agent_id, "group": group}


@router.get("/agents/groups")
async def list_groups(db: DBSession = Depends(get_db)):
    groups = (
        db.query(Agent.group_name, func.count(Agent.id))
        .filter(Agent.group_name != "")
        .group_by(Agent.group_name)
        .all()
    )
    return {g: c for g, c in groups}
