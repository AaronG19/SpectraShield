"""Analytics routes."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.user import User
from models.agent import Agent
from models.alert import Alert
from models.events import (
    Application, BehavioralSnapshot, OSPatchInfo, MisconfigurationCheck,
    WatchdogEvent, AgentMonitorLog,
)
from authentication.dependencies import get_current_user

router = APIRouter(tags=["analytics"])


@router.get("/analytics/attack-vector-distribution")
async def attack_vector_distribution(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    types = (
        db.query(Alert.type, func.count(Alert.id).label("count"))
        .join(Agent)
        .filter(Agent.owner_id == current_user.id)
        .group_by(Alert.type)
        .all()
    )
    total = sum(t.count for t in types) or 1
    return [{"name": t.type, "value": t.count, "percentage": round(t.count / total * 100, 1)} for t in types]


@router.get("/analytics/top-mitre-techniques")
async def top_mitre_techniques(
    current_user: User = Depends(get_current_user),
    limit: int = Query(10, le=50),
    db: DBSession = Depends(get_db),
):
    techniques = (
        db.query(Alert.mitre_technique_id, Alert.mitre_technique_name, func.count(Alert.id).label("count"))
        .join(Agent)
        .filter(Agent.owner_id == current_user.id)
        .group_by(Alert.mitre_technique_id, Alert.mitre_technique_name)
        .order_by(func.count(Alert.id).desc())
        .limit(limit)
        .all()
    )
    total = sum(t.count for t in techniques) or 1
    return [{"technique_id": t.mitre_technique_id, "technique_name": t.mitre_technique_name, "count": t.count, "percentage": round(t.count / total * 100, 1)} for t in techniques]


@router.get("/analytics/agent-health")
async def agent_health_distribution(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    statuses = (
        db.query(Agent.status, func.count(Agent.id).label("count"))
        .filter(Agent.owner_id == current_user.id)
        .group_by(Agent.status)
        .all()
    )
    total = sum(s.count for s in statuses) or 1
    return [{"status": s.status, "count": s.count, "percentage": round(s.count / total * 100, 1)} for s in statuses]


@router.get("/analytics/behavioral-overview")
async def behavioral_overview(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    total_anomalies = db.query(func.count(BehavioralSnapshot.id)).join(Agent).filter(*base, BehavioralSnapshot.is_anomaly == True).scalar() or 0
    total_snapshots = db.query(func.count(BehavioralSnapshot.id)).join(Agent).filter(*base).scalar() or 0
    avg_anomaly_score = db.query(func.avg(BehavioralSnapshot.anomaly_score)).join(Agent).filter(*base).scalar() or 0.0
    agents_with_anomalies = db.query(BehavioralSnapshot.agent_id).join(Agent).filter(*base, BehavioralSnapshot.is_anomaly == True).distinct().count()
    return {
        "total_anomalies": total_anomalies, "total_snapshots": total_snapshots,
        "avg_anomaly_score": round(float(avg_anomaly_score), 4),
        "agents_with_anomalies": agents_with_anomalies,
        "anomaly_rate": round(total_anomalies / max(total_snapshots, 1) * 100, 1),
    }


@router.get("/analytics/patch-compliance")
async def patch_compliance(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    total_agents = db.query(func.count(Agent.id)).filter(*base).scalar() or 0
    agents_with_patches = db.query(func.count(OSPatchInfo.agent_id.distinct())).join(Agent).filter(*base, OSPatchInfo.count > 0).scalar() or 0
    total_missing = db.query(func.sum(OSPatchInfo.count)).join(Agent).filter(*base).scalar() or 0
    high_severity = db.query(func.count(OSPatchInfo.id)).join(Agent).filter(*base, OSPatchInfo.severity == "high").scalar() or 0
    return {
        "total_agents": total_agents, "agents_with_missing_patches": agents_with_patches,
        "total_missing_patches": total_missing, "high_severity_reports": high_severity,
        "compliance_rate": round((total_agents - agents_with_patches) / max(total_agents, 1) * 100, 1),
    }


@router.get("/analytics/misconfiguration-summary")
async def misconfiguration_summary(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    total_checks = db.query(func.count(MisconfigurationCheck.id)).join(Agent).filter(*base).scalar() or 0
    rdp_open_count = db.query(func.count(MisconfigurationCheck.id)).join(Agent).filter(*base, MisconfigurationCheck.rdp_open == True).scalar() or 0
    firewall_off_count = db.query(func.count(MisconfigurationCheck.id)).join(Agent).filter(*base, MisconfigurationCheck.firewall_off == True).scalar() or 0
    guest_account_count = db.query(func.count(MisconfigurationCheck.id)).join(Agent).filter(*base, MisconfigurationCheck.guest_account == True).scalar() or 0
    weak_password_count = db.query(func.count(MisconfigurationCheck.id)).join(Agent).filter(*base, MisconfigurationCheck.weak_password_policy == True).scalar() or 0
    return {
        "total_checks": total_checks, "rdp_open": rdp_open_count, "firewall_off": firewall_off_count,
        "guest_account": guest_account_count, "weak_password_policy": weak_password_count,
        "total_issues": rdp_open_count + firewall_off_count + guest_account_count + weak_password_count,
    }


@router.get("/analytics/software-summary")
async def software_summary(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    total_apps = db.query(func.count(Application.id)).join(Agent).filter(*base).scalar() or 0
    unapproved = db.query(func.count(Application.id)).join(Agent).filter(*base, Application.is_approved == False).scalar() or 0
    top_apps = (
        db.query(Application.name, func.count(Application.id).label("count"))
        .join(Agent)
        .filter(*base)
        .group_by(Application.name)
        .order_by(func.count(Application.id).desc())
        .limit(10)
        .all()
    )
    return {
        "total_apps": total_apps, "unapproved_apps": unapproved,
        "approval_rate": round((total_apps - unapproved) / max(total_apps, 1) * 100, 1),
        "top_applications": [{"name": a.name, "count": a.count} for a in top_apps],
    }


@router.get("/analytics/asset-overview")
async def asset_overview(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    total = db.query(func.count(Agent.id)).filter(*base).scalar() or 0
    os_breakdown = db.query(Agent.os_type, func.count(Agent.id).label("count")).filter(*base).group_by(Agent.os_type).all()
    avg_ram = db.query(func.avg(Agent.ram_total_gb)).filter(*base).scalar() or 0
    avg_cpu_cores = db.query(func.avg(Agent.cpu_cores)).filter(*base).scalar() or 0
    return {
        "total_assets": total, "os_breakdown": {o.os_type: o.count for o in os_breakdown},
        "avg_ram_gb": round(float(avg_ram), 1), "avg_cpu_cores": round(float(avg_cpu_cores), 1),
        "total_disk_tb": round((db.query(func.sum(Agent.disk_total_gb)).filter(*base).scalar() or 0) / 1024, 2),
    }


@router.get("/analytics/watchdog-summary")
async def watchdog_summary(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    total_events = db.query(func.count(WatchdogEvent.id)).join(Agent).filter(*base).scalar() or 0
    tamper_events = db.query(func.count(WatchdogEvent.id)).join(Agent).filter(*base, WatchdogEvent.tamper_detected == True).scalar() or 0
    total_restarts = db.query(func.sum(WatchdogEvent.restart_count)).join(Agent).filter(*base).scalar() or 0
    agents_with_tamper = db.query(WatchdogEvent.agent_id).join(Agent).filter(*base, WatchdogEvent.tamper_detected == True).distinct().count()
    protected = db.query(func.count(Agent.id)).filter(*base, Agent.tamper_protection == True, Agent.self_defense_status == "active").scalar() or 0
    total_agents = db.query(func.count(Agent.id)).filter(*base).scalar() or 1
    return {
        "total_events": total_events, "tamper_events": tamper_events, "total_restarts": total_restarts,
        "agents_with_tamper": agents_with_tamper, "protected_ratio": round(protected / total_agents * 100, 1),
    }


@router.get("/analytics/monitoring-overview")
async def monitoring_overview(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    base = [Agent.owner_id == current_user.id]
    total_logs = db.query(func.count(AgentMonitorLog.id)).join(Agent).filter(*base).scalar() or 0
    avg_cpu = db.query(func.avg(AgentMonitorLog.cpu_percent)).join(Agent).filter(*base).scalar() or 0
    avg_ram = db.query(func.avg(AgentMonitorLog.ram_percent)).join(Agent).filter(*base).scalar() or 0
    agents_reporting = db.query(AgentMonitorLog.agent_id).join(Agent).filter(*base).distinct().count()
    return {
        "total_logs": total_logs,
        "avg_cpu_percent": round(float(avg_cpu), 1),
        "avg_ram_percent": round(float(avg_ram), 1),
        "agents_reporting": agents_reporting,
    }
