"""Engine routes: behavioral, risk scoring, correlation, response, ML, patterns."""
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.agent import Agent
from models.alert import Alert
from schemas.engines import (
    BehavioralAnalysisRequest, RiskEventRequest, ResponseEvaluateRequest,
    MLAnalysisRequest, BaselinerUpdateRequest,
)
from authentication.dependencies import get_owned_agent

router = APIRouter(tags=["engines"])


def _get_engines():
    """Lazy import to avoid circular deps at module load."""
    from main import (
        behavioral_engine, risk_scoring_engine, correlation_engine,
        response_engine, iforest_detector, svm_detector, behavioral_baseliner,
        ML_ENABLED, platform_abstraction,
    )
    return (behavioral_engine, risk_scoring_engine, correlation_engine,
            response_engine, iforest_detector, svm_detector, behavioral_baseliner,
            ML_ENABLED, platform_abstraction)


@router.post("/agents/{agent_id}/behavioral/analyze")
async def analyze_behavioral(
    agent_id: str,
    data: BehavioralAnalysisRequest,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    agent_obj = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent_obj:
        raise HTTPException(status_code=404, detail="Agent not found")
    behavioral_engine, risk_scoring_engine, correlation_engine, response_engine, *_ = _get_engines()
    result = behavioral_engine.analyze_process(
        process_name=data.process_name, cmdline=data.cmdline, parent_name=data.parent_name,
        file_path=data.file_path, user=data.user, os_type=data.os_type, agent_id=agent_id,
    )
    risk_score = risk_scoring_engine.calculate_behavioral_score(result.to_dict(), agent_id)
    threshold_check = risk_scoring_engine.check_threshold(risk_score)
    incident = correlation_engine.ingest_event(
        event={"event_type": "behavioral_anomaly", "severity": risk_score.severity,
               "score": risk_score.total_score, "details": result.to_dict()},
        agent_id=agent_id, event_type="behavioral_anomaly", source="behavioral_engine",
    )
    if threshold_check.get("triggered"):
        response_engine.evaluate_event({
            "event_type": "behavioral_anomaly", "severity": risk_score.severity,
            "score": risk_score.total_score,
        }, agent_id)
        alert = Alert(
            agent_id=agent_id,
            title=f"Behavioral Detection: {', '.join(result.detection_types)[:100]}" if result.detection_types else "Behavioral Anomaly",
            description=threshold_check["message"], severity=risk_score.severity,
            type="behavioral_anomaly", score=risk_score.total_score,
            details=json.dumps({"findings": result.findings, "risk_score": risk_score.to_dict()}),
        )
        db.add(alert)
        db.commit()
    return {
        "agent_id": agent_id, "behavioral": result.to_dict(),
        "risk_score": risk_score.to_dict(), "threshold_check": threshold_check,
        "incident_id": incident.incident_id if incident else None,
    }


@router.get("/agents/{agent_id}/risk-score")
async def get_agent_risk_score(
    agent_id: str,
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    _, risk_scoring_engine, *_ = _get_engines()
    return risk_scoring_engine.get_agent_risk_summary(agent_id)


@router.post("/risk-score/event")
async def record_risk_event(data: RiskEventRequest):
    _, risk_scoring_engine, *_ = _get_engines()
    score = risk_scoring_engine.calculate_score(event_type=data.event_type, severity=data.severity, agent_id="system")
    threshold_check = risk_scoring_engine.check_threshold(score)
    return {"risk_score": score.to_dict(), "threshold_check": threshold_check}


@router.get("/risk-score/thresholds")
async def get_risk_thresholds():
    _, risk_scoring_engine, *_ = _get_engines()
    return risk_scoring_engine.thresholds


@router.get("/correlation/incidents")
async def list_incidents(status: Optional[str] = None):
    _, _, correlation_engine, *_ = _get_engines()
    return correlation_engine.get_active_incidents()


@router.get("/correlation/incidents/{incident_id}")
async def get_incident(incident_id: str):
    _, _, correlation_engine, *_ = _get_engines()
    incident = correlation_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/correlation/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: str):
    _, _, correlation_engine, *_ = _get_engines()
    success = correlation_engine.resolve_incident(incident_id)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"status": "resolved", "incident_id": incident_id}


@router.post("/response/evaluate")
async def evaluate_response(data: ResponseEvaluateRequest):
    _, _, _, response_engine, *_ = _get_engines()
    event = {"event_type": data.event_type, "severity": data.severity, **(data.details or {})}
    triggered = response_engine.evaluate_event(event, data.agent_id)
    return {"triggered_actions": triggered, "policy_count": len(response_engine.policies)}


@router.get("/response/history")
async def get_response_history(limit: int = Query(50, ge=1, le=500)):
    _, _, _, response_engine, *_ = _get_engines()
    return response_engine.get_action_history(limit)


@router.post("/response/execute")
async def execute_response_action(
    action: str = Query(...),
    target: str = Query(...),
    agent_id: str = Query(...),
    agent: Agent = Depends(get_owned_agent),
    db: DBSession = Depends(get_db),
):
    from services.response_engine import ResponseAction
    _, _, _, response_engine, *_ = _get_engines()
    agent_obj = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent_obj:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        resp_action = ResponseAction(action)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid action: {action}")
    return response_engine.execute_action(resp_action, target, agent_id)


@router.post("/ml/analyze")
async def ml_analyze(data: MLAnalysisRequest):
    _, _, _, _, iforest_detector, svm_detector, behavioral_baseliner, ML_ENABLED, _ = _get_engines()
    if not ML_ENABLED:
        return {"status": "ml_disabled", "message": "ML detection is disabled."}
    results = {}
    try:
        if data.features:
            iforest_result = iforest_detector.predict(data.features)
            results["isolation_forest"] = {"is_anomaly": bool(iforest_result[0]), "score": iforest_result[1]}
            svm_result = svm_detector.predict(data.features)
            results["one_class_svm"] = {"is_anomaly": bool(svm_result[0]), "score": svm_result[1]}
        if data.agent_id and behavioral_baseliner:
            results["baseline"] = behavioral_baseliner.get_agent_status(data.agent_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return results


@router.post("/ml/baseline/update")
async def update_baseline(data: BaselinerUpdateRequest, db: DBSession = Depends(get_db)):
    _, _, _, _, _, _, behavioral_baseliner, ML_ENABLED, _ = _get_engines()
    if not ML_ENABLED or not behavioral_baseliner:
        return {"status": "ml_disabled"}
    metrics = {"cpu_usage": data.cpu_usage, "ram_usage": data.ram_usage,
               "process_count": data.process_count, "net_connections": data.net_connections}
    behavioral_baseliner.update(data.agent_id, metrics)
    is_anomaly, details = behavioral_baseliner.is_anomalous(data.agent_id, metrics)
    if is_anomaly:
        alert = Alert(agent_id=data.agent_id, title="Behavioral Baseline Anomaly",
                      description="Deviation from established baseline detected",
                      severity="medium", type="behavioral_anomaly", score=50.0,
                      details=json.dumps(details))
        db.add(alert)
        db.commit()
    return {"status": "updated", "is_anomalous": is_anomaly, "details": details}


@router.get("/behavioral/patterns")
async def list_behavioral_patterns():
    from detector.patterns import LOLBINS, SUSPICIOUS_CMD_PATTERNS
    from detector.persistence import REGISTRY_AUTORUN_KEYS, SCHEDULED_TASK_PATTERNS, WMI_ABUSE_PATTERNS
    from detector.lateral_movement import LATERAL_MOVEMENT_PATTERNS
    return {
        "lolbins": {k: {"risk": v["risk"], "description": v["description"]} for k, v in LOLBINS.items()},
        "suspicious_commands": [{"type": p[0], "risk_score": p[2]} for p in SUSPICIOUS_CMD_PATTERNS],
        "registry_autorun_keys": [k["key"] for k in REGISTRY_AUTORUN_KEYS],
        "scheduled_task_patterns": SCHEDULED_TASK_PATTERNS,
        "wmi_abuse_patterns": WMI_ABUSE_PATTERNS,
        "lateral_movement_patterns": LATERAL_MOVEMENT_PATTERNS,
        "total_patterns": len(LOLBINS) + len(SUSPICIOUS_CMD_PATTERNS) + len(REGISTRY_AUTORUN_KEYS) + len(SCHEDULED_TASK_PATTERNS) + len(WMI_ABUSE_PATTERNS) + len(LATERAL_MOVEMENT_PATTERNS),
    }


@router.get("/engine/status")
async def engine_status():
    behavioral_engine, risk_scoring_engine, correlation_engine, response_engine, iforest_detector, svm_detector, behavioral_baseliner, ML_ENABLED, platform_abstraction = _get_engines()
    return {
        "behavioral_engine": {"enabled": behavioral_engine.enabled},
        "risk_scoring_engine": {"thresholds": risk_scoring_engine.thresholds},
        "correlation_engine": {"active_incidents": len(correlation_engine.get_active_incidents())},
        "response_engine": {"enabled": response_engine.enabled, "policies": len(response_engine.policies)},
        "ml_detection": {"enabled": ML_ENABLED, "iforest": iforest_detector.is_available(), "svm": svm_detector.is_available(), "baseliner": behavioral_baseliner is not None},
        "platform": {"type": platform_abstraction.detect_os()},
    }
