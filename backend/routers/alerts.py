"""Alert management routes."""
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.user import User
from models.agent import Agent
from models.alert import Alert
from constants.mitre import MITRE_TACTICS, MITRE_TECHNIQUES, MITRE_ATTACK_MAP
from authentication.dependencies import get_current_user
from schemas.alert import AlertAcknowledge, AlertResolve

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
async def list_alerts(
    current_user: User = Depends(get_current_user),
    severity: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None, alias="type"),
    status: Optional[str] = Query(None),
    mitre_tactic: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    query = db.query(Alert).join(Agent).filter(*base)
    if severity:
        query = query.filter(Alert.severity == severity)
    if alert_type:
        query = query.filter(Alert.type == alert_type)
    if status:
        query = query.filter(Alert.status == status)
    if mitre_tactic:
        query = query.filter(Alert.mitre_tactic_id == mitre_tactic)
    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "alerts": [
            {
                "id": a.id, "agent_id": a.agent_id, "title": a.title, "description": a.description,
                "severity": a.severity, "type": a.type, "status": a.status, "source": a.source,
                "mitre_tactic_id": a.mitre_tactic_id, "mitre_tactic_name": a.mitre_tactic_name,
                "mitre_technique_id": a.mitre_technique_id, "mitre_technique_name": a.mitre_technique_name,
                "score": a.score, "details": json.loads(a.details) if a.details else {},
                "created_at": a.created_at.isoformat(),
                "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "agent_hostname": db.query(Agent.hostname).filter(Agent.id == a.agent_id).scalar() or "Unknown",
            }
            for a in alerts
        ],
    }


@router.get("/alerts/mitre-matrix")
async def get_mitre_matrix(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    matrix = []
    for tactic_id, tactic_data in MITRE_TACTICS.items():
        techniques = []
        for tech_id, tech_data in MITRE_TECHNIQUES.items():
            if tech_data["tactic"] == tactic_id:
                alert_count = db.query(func.count(Alert.id)).join(Agent).filter(*base, Alert.mitre_technique_id == tech_id).scalar() or 0
                if alert_count > 0:
                    techniques.append({"id": tech_id, "name": tech_data["name"], "alert_count": alert_count})
        matrix.append({"tactic_id": tactic_id, "tactic_name": tactic_data["name"], "order": tactic_data["order"], "techniques": techniques})
    return sorted(matrix, key=lambda x: x["order"])


@router.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    alert = db.query(Alert).join(Agent).filter(Agent.owner_id == current_user.id, Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {
        "id": alert.id, "agent_id": alert.agent_id, "title": alert.title, "description": alert.description,
        "severity": alert.severity, "type": alert.type, "status": alert.status, "source": alert.source,
        "mitre_tactic_id": alert.mitre_tactic_id, "mitre_tactic_name": alert.mitre_tactic_name,
        "mitre_technique_id": alert.mitre_technique_id, "mitre_technique_name": alert.mitre_technique_name,
        "score": alert.score, "details": json.loads(alert.details) if alert.details else {},
        "created_at": alert.created_at.isoformat(),
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "resolved_by": alert.resolved_by,
        "agent_hostname": db.query(Agent.hostname).filter(Agent.id == alert.agent_id).scalar() or "Unknown",
    }


@router.post("/alerts/resolve-all")
async def resolve_all_alerts(
    current_user: User = Depends(get_current_user),
    data: Optional[AlertResolve] = Body(default=None),
    db: DBSession = Depends(get_db),
):
    alerts = db.query(Alert).join(Agent).filter(
        Agent.owner_id == current_user.id,
        Alert.status.in_(["open", "acknowledged"])
    ).all()
    count = 0
    now = datetime.utcnow()
    resolved_by = data.resolved_by if data else "admin"
    for alert in alerts:
        alert.status = "resolved"
        alert.resolved_at = now
        alert.resolved_by = resolved_by
        count += 1
    db.commit()
    return {"message": f"Successfully resolved {count} alert(s)", "resolved_count": count}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    data: Optional[AlertAcknowledge] = Body(default=None),
    db: DBSession = Depends(get_db),
):
    alert = db.query(Alert).join(Agent).filter(Agent.owner_id == current_user.id, Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.utcnow()
    db.commit()
    return {"message": f"Alert {alert_id} acknowledged", "alert_id": alert_id, "status": alert.status}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    data: Optional[AlertResolve] = Body(default=None),
    db: DBSession = Depends(get_db),
):
    alert = db.query(Alert).join(Agent).filter(Agent.owner_id == current_user.id, Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "resolved"
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = data.resolved_by if data else "admin"
    db.commit()
    return {"message": f"Alert {alert_id} resolved by {alert.resolved_by}", "alert_id": alert_id, "status": alert.status}


@router.get("/mitre-attack-mapping")
async def get_mitre_attack_mapping():
    return {
        "mapping_version": "1.0",
        "total_mapped_features": len(MITRE_ATTACK_MAP),
        "mitre_map": MITRE_ATTACK_MAP,
        "tactics": {k: v["name"] for k, v in MITRE_TACTICS.items()},
        "techniques": {k: v["name"] for k, v in MITRE_TECHNIQUES.items()},
    }
