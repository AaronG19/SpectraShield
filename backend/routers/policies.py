"""Policy management routes."""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.alert import Policy
from models.events import FirewallRule, CanaryFile
from schemas.policy import PolicyUpdate, AppWhitelistAdd, BlockDevice, FirewallRuleCreate, CanaryFileCreate

router = APIRouter(tags=["policies"])


@router.get("/policies")
async def get_policies(db: DBSession = Depends(get_db)):
    policies = db.query(Policy).all()
    result = {}
    for p in policies:
        try:
            result[p.key] = json.loads(p.value)
        except Exception:
            result[p.key] = p.value
    return result


@router.post("/policies")
async def update_policies(data: PolicyUpdate, db: DBSession = Depends(get_db)):
    existing = db.query(Policy).filter(Policy.key == data.key).first()
    if existing:
        existing.value = data.value
        existing.updated_at = datetime.utcnow()
    else:
        db.add(Policy(key=data.key, value=data.value))
    db.commit()
    return {"message": f"Policy '{data.key}' updated", "key": data.key, "value": data.value}


@router.get("/policies/app-whitelist")
async def get_app_whitelist(db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.key == "approved_apps").first()
    if not policy:
        return {"whitelist": [], "enabled": True, "total": 0}
    try:
        apps = json.loads(policy.value)
    except Exception:
        apps = []
    return {"whitelist": apps, "enabled": True, "total": len(apps)}


@router.post("/policies/app-whitelist")
async def add_app_whitelist(data: AppWhitelistAdd, db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.key == "approved_apps").first()
    if policy:
        try:
            apps = json.loads(policy.value)
        except Exception:
            apps = []
    else:
        apps = []
        policy = Policy(key="approved_apps", value="[]")
        db.add(policy)
    if data.name not in apps:
        apps.append(data.name)
    policy.value = json.dumps(apps)
    policy.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"'{data.name}' added to whitelist", "whitelist": apps}


@router.get("/policies/blocked-devices")
async def get_blocked_devices(db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.key == "blocked_usb_devices").first()
    if not policy:
        return {"devices": [], "total": 0}
    try:
        devices = json.loads(policy.value)
    except Exception:
        devices = []
    return {"devices": devices, "total": len(devices)}


@router.post("/policies/blocked-devices")
async def block_device(data: BlockDevice, db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.key == "blocked_usb_devices").first()
    if policy:
        try:
            devices = json.loads(policy.value)
        except Exception:
            devices = []
    else:
        devices = []
        policy = Policy(key="blocked_usb_devices", value="[]")
        db.add(policy)
    entry = {
        "device_id": data.device_id, "device_name": data.device_name,
        "device_type": data.device_type, "reason": data.reason or "Blocked by admin",
        "blocked_at": datetime.utcnow().isoformat(),
    }
    exists = any(d.get("device_id") == data.device_id for d in devices)
    if not exists:
        devices.append(entry)
    policy.value = json.dumps(devices)
    policy.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"'{data.device_name}' blocked", "devices": devices}


@router.post("/policies/blocked-devices/{device_id}/unblock")
async def unblock_device(device_id: str, db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.key == "blocked_usb_devices").first()
    if not policy:
        raise HTTPException(status_code=404, detail="No blocked devices policy")
    try:
        devices = json.loads(policy.value)
    except Exception:
        devices = []
    filtered = [d for d in devices if d.get("device_id") != device_id]
    if len(filtered) == len(devices):
        raise HTTPException(status_code=404, detail="Device not found")
    policy.value = json.dumps(filtered)
    policy.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"Device {device_id} unblocked", "devices": filtered}


@router.delete("/policies/app-whitelist/{app_name}")
async def remove_app_whitelist(app_name: str, db: DBSession = Depends(get_db)):
    policy = db.query(Policy).filter(Policy.key == "approved_apps").first()
    if not policy:
        raise HTTPException(status_code=404, detail="No whitelist policy found")
    try:
        apps = json.loads(policy.value)
    except Exception:
        apps = []
    if app_name not in apps:
        raise HTTPException(status_code=404, detail=f"'{app_name}' not found in whitelist")
    apps.remove(app_name)
    policy.value = json.dumps(apps)
    policy.updated_at = datetime.utcnow()
    db.commit()
    return {"message": f"'{app_name}' removed from whitelist", "whitelist": apps}


@router.get("/policies/firewall-rules")
async def get_firewall_rules(db: DBSession = Depends(get_db)):
    rules = db.query(FirewallRule).order_by(FirewallRule.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "direction": r.direction,
            "action": r.action,
            "protocol": r.protocol,
            "local_port": r.local_port,
            "remote_ip": r.remote_ip,
            "enabled": r.enabled,
            "created_at": r.created_at.isoformat()
        }
        for r in rules
    ]


@router.post("/policies/firewall-rules")
async def add_firewall_rule(data: FirewallRuleCreate, db: DBSession = Depends(get_db)):
    rule = FirewallRule(
        name=data.name,
        direction=data.direction,
        action=data.action,
        protocol=data.protocol,
        local_port=data.local_port,
        remote_ip=data.remote_ip,
        enabled=data.enabled
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return {
        "id": rule.id,
        "name": rule.name,
        "direction": rule.direction,
        "action": rule.action,
        "protocol": rule.protocol,
        "local_port": rule.local_port,
        "remote_ip": rule.remote_ip,
        "enabled": rule.enabled
    }


@router.delete("/policies/firewall-rules/{rule_id}")
async def delete_firewall_rule(rule_id: str, db: DBSession = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    db.delete(rule)
    db.commit()
    return {"message": f"Firewall rule '{rule_id}' deleted"}


@router.get("/policies/canary-files")
async def get_canary_files(db: DBSession = Depends(get_db)):
    files = db.query(CanaryFile).order_by(CanaryFile.created_at.desc()).all()
    return [
        {
            "id": f.id,
            "file_path": f.file_path,
            "file_name": f.file_name,
            "is_triggered": f.is_triggered,
            "triggered_at": f.triggered_at.isoformat() if f.triggered_at else None,
            "created_at": f.created_at.isoformat()
        }
        for f in files
    ]


@router.post("/policies/canary-files")
async def add_canary_file(data: CanaryFileCreate, db: DBSession = Depends(get_db)):
    file_name = data.file_name
    if not file_name:
        import os
        file_name = os.path.basename(data.file_path.replace("\\", "/"))
        if not file_name:
            file_name = "canary_file"
    
    canary = CanaryFile(
        file_path=data.file_path,
        file_name=file_name,
        is_triggered=False
    )
    db.add(canary)
    db.commit()
    db.refresh(canary)
    return {
        "id": canary.id,
        "file_path": canary.file_path,
        "file_name": canary.file_name,
        "is_triggered": canary.is_triggered
    }


@router.delete("/policies/canary-files/{canary_id}")
async def delete_canary_file(canary_id: str, db: DBSession = Depends(get_db)):
    canary = db.query(CanaryFile).filter(CanaryFile.id == canary_id).first()
    if not canary:
        raise HTTPException(status_code=404, detail="Canary file not found")
    db.delete(canary)
    db.commit()
    return {"message": f"Canary file '{canary_id}' deleted"}
