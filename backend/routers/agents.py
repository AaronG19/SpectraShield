"""Agent core CRUD and lifecycle routes."""
import json
import secrets
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.user import User
from models.agent import Agent
from models.alert import Alert, PendingAction
from models.events import Application, Process, NetworkConnection
from schemas.agent import AgentRegister, DeployRequest, ScanRequest, QuarantineRequest
from authentication.dependencies import get_current_user, get_owned_agent, calculate_security_score
from helpers.generators import generate_mac

router = APIRouter(tags=["agents"])


@router.get("/agents")
async def list_agents(
    current_user: User = Depends(get_current_user),
    status: Optional[str] = Query(None),
    os_type: Optional[str] = Query(None),
    db: DBSession = Depends(get_db),
):
    query = db.query(Agent).filter(Agent.owner_id == current_user.id)
    if status:
        query = query.filter(Agent.status == status)
    if os_type:
        query = query.filter(Agent.os_type == os_type)
    agents = query.order_by(Agent.hostname).all()
    return [
        {
            "id": a.id, "hostname": a.hostname, "os_type": a.os_type, "os_version": a.os_version,
            "cpu_model": a.cpu_model, "cpu_cores": a.cpu_cores, "cpu_usage": a.cpu_usage,
            "ram_total_gb": a.ram_total_gb, "ram_used_gb": a.ram_used_gb,
            "disk_total_gb": a.disk_total_gb, "disk_used_gb": a.disk_used_gb,
            "mac_address": a.mac_address, "ip_address": a.ip_address, "status": a.status,
            "version": a.version, "last_heartbeat": a.last_heartbeat.isoformat(),
            "registered_at": a.registered_at.isoformat(),
            "tamper_protection": a.tamper_protection, "self_defense_status": a.self_defense_status,
            "low_footprint_mode": a.low_footprint_mode, "quarantine": a.quarantine,
            "bitlocker_enabled": a.bitlocker_enabled, "firewall_enabled": a.firewall_enabled,
            "agent_type": a.agent_type,
            "alert_count": db.query(func.count(Alert.id)).filter(Alert.agent_id == a.id).scalar() or 0,
        }
        for a in agents
    ]


@router.post("/agents/register")
async def register_agent(data: AgentRegister, db: DBSession = Depends(get_db)):
    agent_id = str(uuid.uuid4())
    one_time_token = secrets.token_hex(32)
    agent_token = secrets.token_hex(32)  # long-lived secret; sent as X-Agent-Token on every report call
    agent = Agent(
        id=agent_id, hostname=data.hostname, os_type=data.os_type, os_version=data.os_version,
        cpu_model=data.cpu_model, cpu_cores=data.cpu_cores, cpu_usage=0.0,
        ram_total_gb=data.ram_total_gb, ram_used_gb=0.0, disk_total_gb=data.disk_total_gb, disk_used_gb=0.0,
        mac_address=data.mac_address or generate_mac(), ip_address=data.ip_address,
        status="online", version="3.5.1", last_heartbeat=datetime.utcnow(),
        registered_at=datetime.utcnow(), tamper_protection=True, self_defense_status="active",
        low_footprint_mode=True, firewall_enabled=True,
        one_time_token=one_time_token, agent_token=agent_token,
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return {
        "id": agent.id, "hostname": agent.hostname, "status": agent.status,
        "one_time_token": agent.one_time_token, "agent_token": agent.agent_token,
        "message": (
            "Agent registered successfully. Store agent_token securely — it is "
            "only returned once and must be sent as the X-Agent-Token header on every "
            "subsequent report call."
        ),
    }


@router.get("/agents/{agent_id}")
async def get_agent(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "id": agent.id, "hostname": agent.hostname, "os_type": agent.os_type, "os_version": agent.os_version,
        "os_patch_level": agent.os_patch_level, "cpu_model": agent.cpu_model, "cpu_cores": agent.cpu_cores,
        "cpu_usage": agent.cpu_usage, "ram_total_gb": agent.ram_total_gb, "ram_used_gb": agent.ram_used_gb,
        "disk_total_gb": agent.disk_total_gb, "disk_used_gb": agent.disk_used_gb,
        "mac_address": agent.mac_address, "ip_address": agent.ip_address, "status": agent.status,
        "version": agent.version, "last_heartbeat": agent.last_heartbeat.isoformat(),
        "registered_at": agent.registered_at.isoformat(),
        "tamper_protection": agent.tamper_protection, "self_defense_status": agent.self_defense_status,
        "low_footprint_mode": agent.low_footprint_mode, "quarantine": agent.quarantine,
        "bitlocker_enabled": agent.bitlocker_enabled, "firewall_enabled": agent.firewall_enabled,
        "agent_type": agent.agent_type,
        "applications_count": db.query(func.count(Application.id)).filter(Application.agent_id == agent.id).scalar() or 0,
        "processes_count": db.query(func.count(Process.id)).filter(Process.agent_id == agent.id).scalar() or 0,
        "connections_count": db.query(func.count(NetworkConnection.id)).filter(NetworkConnection.agent_id == agent.id).scalar() or 0,
        "alerts_count": db.query(func.count(Alert.id)).filter(Alert.agent_id == agent.id).scalar() or 0,
    }


@router.delete("/agents/{agent_id}")
async def remove_agent(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        db.delete(agent)
        db.commit()
    except Exception:
        db.rollback()
        agent.owner_id = None
        import secrets
        agent.one_time_token = secrets.token_hex(32)
        db.commit()
    return {"message": f"Agent {agent_id} removed successfully"}


@router.post("/agents/{agent_id}/deploy")
async def deploy_agent(
    agent_id: str,
    data: DeployRequest,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.agent_type = data.agent_type
    db.commit()
    return {"message": f"Agent {agent_id} deploy configuration updated", "agent_type": data.agent_type}


@router.post("/agents/{agent_id}/scan")
async def scan_agent(
    agent_id: str,
    data: ScanRequest,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Queue the scan action for the agent
    db.add(PendingAction(agent_id=agent_id, action="run_scan", target=data.scan_type, source="manual"))
    db.commit()
    return {"message": f"Scan {data.scan_type} initiated for agent {agent_id}", "agent_id": agent_id, "scan_type": data.scan_type, "status": "queued"}


@router.post("/agents/{agent_id}/quarantine")
async def quarantine_agent(
    agent_id: str,
    data: QuarantineRequest,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    is_quarantine = (data.action == "quarantine")
    agent.quarantine = is_quarantine
    
    # Queue the corresponding firewall action for the agent
    action_type = "host_isolate" if is_quarantine else "host_unisolate"
    db.add(PendingAction(agent_id=agent_id, action=action_type, target="", source="manual"))
    
    db.commit()
    return {"message": f"Agent {agent_id} quarantine={agent.quarantine}", "quarantine": agent.quarantine}


@router.get("/agents/{agent_id}/alerts")
async def get_agent_alerts(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    alerts = db.query(Alert).filter(Alert.agent_id == agent_id).order_by(Alert.created_at.desc()).limit(100).all()
    return [
        {
            "id": a.id, "title": a.title, "severity": a.severity, "type": a.type, "status": a.status,
            "score": a.score, "created_at": a.created_at.isoformat(),
        }
        for a in alerts
    ]


@router.get("/agents/{agent_id}/processes")
async def get_agent_processes(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    processes = db.query(Process).filter(Process.agent_id == agent_id).order_by(Process.cpu_percent.desc()).limit(50).all()
    return [
        {
            "pid": p.pid, "name": p.name, "path": p.path, "user": p.user, "cpu_percent": p.cpu_percent,
            "memory_mb": p.memory_mb, "is_suspicious": p.is_suspicious, "cmdline": p.cmdline, "hash": p.hash,
        }
        for p in processes
    ]


@router.get("/agents/{agent_id}/network")
async def get_agent_network(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    conns = db.query(NetworkConnection).filter(NetworkConnection.agent_id == agent_id).order_by(NetworkConnection.created_at.desc()).limit(100).all()
    return [
        {
            "local_ip": c.local_ip, "local_port": c.local_port, "remote_ip": c.remote_ip,
            "remote_port": c.remote_port, "protocol": c.protocol, "state": c.state,
            "process_name": c.process_name, "is_suspicious": c.is_suspicious,
        }
        for c in conns
    ]


@router.get("/agents/{agent_id}/security-score")
async def get_agent_security_score(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    score = calculate_security_score(db, agent=agent)
    return {"agent_id": agent_id, "hostname": agent.hostname, "security_score": score}
