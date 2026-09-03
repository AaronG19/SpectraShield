"""Dashboard summary, recent alerts, and alert trend routes."""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.user import User
from models.agent import Agent
from models.alert import Alert
from models.events import NetworkConnection
from authentication.dependencies import get_current_user, calculate_security_score

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/summary")
async def dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    total_agents = db.query(func.count(Agent.id)).filter(*base).scalar() or 0
    online_agents = db.query(func.count(Agent.id)).filter(*base, Agent.status == "online").scalar() or 0
    offline_agents = total_agents - online_agents
    total_alerts = db.query(func.count(Alert.id)).join(Agent).filter(*base).scalar() or 0
    open_alerts = db.query(func.count(Alert.id)).join(Agent).filter(*base, Alert.status == "open").scalar() or 0
    critical_alerts = db.query(func.count(Alert.id)).join(Agent).filter(*base, Alert.severity == "critical").scalar() or 0
    high_alerts = db.query(func.count(Alert.id)).join(Agent).filter(*base, Alert.severity == "high").scalar() or 0
    threats_blocked = db.query(func.count(Alert.id)).join(Agent).filter(*base, Alert.status == "resolved").scalar() or 0
    total_suspicious = db.query(func.count(NetworkConnection.id)).join(Agent).filter(*base, NetworkConnection.is_suspicious == True).scalar() or 0
    quarantined = db.query(func.count(Agent.id)).filter(*base, Agent.quarantine == True).scalar() or 0
    security_score = calculate_security_score(db, user=current_user)
    return {
        "total_agents": total_agents, "online_agents": online_agents, "offline_agents": offline_agents,
        "total_alerts": total_alerts, "open_alerts": open_alerts, "critical_alerts": critical_alerts,
        "high_alerts": high_alerts, "threats_blocked": threats_blocked,
        "suspicious_connections": total_suspicious, "quarantined_agents": quarantined,
        "security_score": security_score, "scan_coverage": f"{online_agents}/{total_agents}",
        "last_updated": datetime.utcnow().isoformat(),
    }


@router.get("/dashboard/recent-alerts")
async def dashboard_recent_alerts(
    current_user: User = Depends(get_current_user),
    limit: int = Query(10, le=50),
    db: DBSession = Depends(get_db),
):
    alerts = (
        db.query(Alert)
        .join(Agent)
        .filter(Agent.owner_id == current_user.id)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": a.id, "title": a.title, "severity": a.severity, "type": a.type, "status": a.status,
            "agent_id": a.agent_id, "mitre_tactic_name": a.mitre_tactic_name,
            "mitre_technique_name": a.mitre_technique_name, "score": a.score,
            "created_at": a.created_at.isoformat(),
            "agent_hostname": db.query(Agent.hostname).filter(Agent.id == a.agent_id).scalar() or "Unknown",
        }
        for a in alerts
    ]


@router.get("/dashboard/alert-trend")
async def dashboard_alert_trend(
    current_user: User = Depends(get_current_user),
    hours: int = Query(24, le=168),
    db: DBSession = Depends(get_db),
):
    now = datetime.utcnow()
    base = [Agent.owner_id == current_user.id]
    data = []
    for i in range(hours, 0, -1):
        start = now - timedelta(hours=i)
        end = now - timedelta(hours=i - 1)
        count = db.query(func.count(Alert.id)).join(Agent).filter(*base, and_(Alert.created_at >= start, Alert.created_at < end)).scalar() or 0
        critical_count = db.query(func.count(Alert.id)).join(Agent).filter(*base, and_(Alert.created_at >= start, Alert.created_at < end, Alert.severity == "critical")).scalar() or 0
        high_count = db.query(func.count(Alert.id)).join(Agent).filter(*base, and_(Alert.created_at >= start, Alert.created_at < end, Alert.severity == "high")).scalar() or 0
        data.append({"timestamp": start.isoformat(), "total": count, "critical": critical_count, "high": high_count})
    return data
