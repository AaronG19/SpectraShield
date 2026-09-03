"""Threat intelligence routes."""
import csv
import io
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.user import User
from models.agent import Agent
from models.alert import Alert
from models.events import ThreatIntel, NetworkConnection
from schemas.alert import ThreatLookupRequest
from authentication.dependencies import get_current_user
from helpers.generators import (
    _detect_ioc_type, _check_dnsbl, _extract_malware_family, _extract_what_it_does,
    _impact_on_victim, _compute_confidence, _compute_reputation_label, _generate_mitre,
    _recommended_actions,
)

# threat_intel_service is a module-level singleton initialized in main.py and injected via dependency
def _get_threat_intel_service():
    from main import threat_intel_service
    return threat_intel_service


router = APIRouter(tags=["threats"])


@router.get("/threats/summary")
async def threat_summary(
    current_user: User = Depends(get_current_user),
    db: DBSession = Depends(get_db),
):
    total_iocs = db.query(func.count(ThreatIntel.id)).filter(ThreatIntel.is_active == True).scalar() or 0
    ip_iocs = db.query(func.count(ThreatIntel.id)).filter(ThreatIntel.indicator_type == "ip", ThreatIntel.is_active == True).scalar() or 0
    hash_iocs = db.query(func.count(ThreatIntel.id)).filter(ThreatIntel.indicator_type == "hash", ThreatIntel.is_active == True).scalar() or 0
    domain_iocs = db.query(func.count(ThreatIntel.id)).filter(ThreatIntel.indicator_type == "domain", ThreatIntel.is_active == True).scalar() or 0
    matched_connections = (
        db.query(func.count(NetworkConnection.id))
        .join(Agent)
        .filter(Agent.owner_id == current_user.id, NetworkConnection.threat_intel_match == True)
        .scalar() or 0
    )
    return {
        "total_iocs": total_iocs, "ip_iocs": ip_iocs, "hash_iocs": hash_iocs,
        "domain_iocs": domain_iocs, "matched_connections": matched_connections,
        "last_sync": datetime.utcnow().isoformat(),
        "feed_sources": ["AlienVault OTX", "VirusTotal", "Abuse.ch", "Spamhaus"],
    }



@router.post("/threats/lookup")
async def lookup_threat(data: ThreatLookupRequest, db: DBSession = Depends(get_db)):
    val = data.value.strip().lower()
    ioc_type = _detect_ioc_type(val)
    base = {"value": val, "indicator_type": ioc_type}
    dnsbl = _check_dnsbl(val) if ioc_type == "ip" else None
    vt_result = None
    ioc = db.query(ThreatIntel).filter(ThreatIntel.value == val, ThreatIntel.is_active == True).first()
    found = False
    source = ""
    confidence = ""
    severity = ""
    description = ""
    mitre_mapping = None
    if ioc:
        found = True
        source = ioc.source
        confidence = ioc.confidence
        severity = ioc.severity
        description = ioc.description
        mitre_mapping = ioc.mitre_mapping
    if not found and dnsbl and dnsbl["hits"]:
        cats = [h.get("category", h["list"]) for h in dnsbl["hits"]]
        found = True
        source = "dnsbl"
        confidence = "medium"
        severity = "medium"
        description = f"DNSBL: {', '.join(cats)}"
    malware_family = _extract_malware_family(vt_result)
    what_it_does = _extract_what_it_does(vt_result, ioc_type)
    impacts = _impact_on_victim(vt_result, ioc_type)
    rep_score = _compute_confidence(vt_result, dnsbl)
    actions = _recommended_actions(ioc_type, severity if severity else "low")
    mitre = mitre_mapping if mitre_mapping else _generate_mitre(vt_result if vt_result else {}, ioc_type)
    result = base | {
        "found": found, "source": source,
        "confidence": confidence or _compute_reputation_label(rep_score),
        "severity": severity or _compute_reputation_label(rep_score),
        "description": description, "dnsbl": dnsbl, "malware_family": malware_family,
        "what_it_does": what_it_does, "impact": impacts, "reputation_score": rep_score,
        "reputation_label": _compute_reputation_label(rep_score), "mitre_attck": mitre,
        "recommended_actions": actions,
    }
    if ioc:
        result["first_seen"] = ioc.first_seen.isoformat()
        result["last_seen"] = ioc.last_seen.isoformat()
    return result


@router.get("/threat-intel/lookup")
async def threat_intel_lookup(indicator: str = Query(..., description="IP, hash, or domain")):
    from main import threat_intel_service
    val = indicator.strip().lower()
    result = threat_intel_service.lookup(val)
    if "error" in result:
        result["value"] = val
        result["indicator_type"] = result.get("type", "unknown")
        result["found"] = False
    else:
        result["value"] = val
        result["indicator_type"] = result.get("type", "unknown")
        result["found"] = result.get("found", False)
        result["description"] = "; ".join(result.get("why_malicious", []))
        result["virustotal"] = result.get("providers", {}).get("virustotal", {})
        result["dnsbl"] = result.get("providers", {}).get("dnsbl", {})
        result["source"] = result.get("primary_source", "")
        result["what_it_does"] = result.get("why_malicious", [])
        result["reputation_score"] = result.get("reputation_score", 0)
        result["reputation_label"] = result.get("reputation", "unknown")
        result["severity"] = result.get("reputation", "unknown")
        result["confidence"] = result.get("reputation", "unknown")
        result["recommended_actions"] = result.get("recommendations", [])
        result["mitre_attck"] = result.get("mitre", [])
        if result.get("providers"):
            for pname, pdata in result["providers"].items():
                if isinstance(pdata, dict) and pdata.get("first_seen"):
                    result["first_seen"] = pdata["first_seen"]
                if isinstance(pdata, dict) and pdata.get("last_seen"):
                    result["last_seen"] = pdata["last_seen"]
    return result


@router.get("/threats/intel")
async def get_threat_intel(
    indicator_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: DBSession = Depends(get_db),
):
    query = db.query(ThreatIntel).filter(ThreatIntel.is_active == True)
    if indicator_type:
        query = query.filter(ThreatIntel.indicator_type == indicator_type)
    if severity:
        query = query.filter(ThreatIntel.severity == severity)
    intel = query.order_by(ThreatIntel.last_seen.desc()).limit(limit).all()
    return [
        {
            "id": i.id, "indicator_type": i.indicator_type, "value": i.value, "confidence": i.confidence,
            "severity": i.severity, "source": i.source, "description": i.description,
            "first_seen": i.first_seen.isoformat(), "last_seen": i.last_seen.isoformat(),
            "is_active": i.is_active, "mitre_mapping": i.mitre_mapping,
        }
        for i in intel
    ]
