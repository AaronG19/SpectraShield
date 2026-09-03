"""Agent telemetry detection report endpoints (37 feature routes)."""
import json
import random
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DBSession

from db.base import get_db
from models.agent import Agent
from models.alert import Alert, PendingAction
from models.events import (
    OSPatchInfo, BehavioralSnapshot, FileIntegrityCheck, MisconfigurationCheck,
    Application, WatchdogEvent, AgentMonitorLog, ProcessExecutionEvent, RegistryChange,
    ZeroDayFinding, FilelessDetectionEvent, MemoryScanEvent, UsbDiskEvent,
    C2BeaconingEvent, LiveThreatIntelResult, OfflineScanEvent, VulnerabilityFinding,
    ProcessTreeFinding, ShadowITFinding, ExploitMitigationEvent, InstallationVisibilityEvent,
    NetworkDPIEvent, PrivilegeEscalationEvent, SilentDeploymentEvent, LateralMovementEvent,
    PortScanEvent, HostFirewallEvent, WebDNSFilterEvent, ScriptMonitorEvent,
    RansomwareCanaryEvent, CredentialDumpingEvent, NextGenAVEvent, UserBehaviourEvent,
    Process, NetworkConnection,
)
from constants.mitre import MITRE_ATTACK_MAP, get_mitre_tactic_name, get_mitre_technique_name
from authentication.dependencies import get_owned_agent, verify_agent_self
from helpers.generators import (
    generate_patch_findings, generate_behavioral_findings, generate_file_integrity_findings,
    generate_software_inventory, generate_asset_discovery, generate_watchdog_status,
    generate_monitoring_stats, generate_execution_prevention_stats, generate_zero_day_stats,
    generate_registry_monitoring_stats, generate_fileless_stats, generate_memory_scan_stats,
    generate_usb_disk_stats, generate_c2_stats, generate_threat_intel_stats,
    generate_offline_scan_stats, generate_vuln_scan_stats, generate_process_tree_stats,
    generate_shadow_it_stats, generate_exploit_mitigation_stats,
    generate_installation_visibility_stats, generate_network_dpi_stats,
    generate_privilege_escalation_stats, generate_silent_deployment_stats,
    generate_lateral_movement_stats, generate_port_scan_stats, generate_host_firewall_stats,
    generate_web_dns_filter_stats, generate_script_monitor_stats, generate_ransomware_canary_stats,
    generate_credential_dumping_stats, generate_next_gen_av_stats, generate_user_behaviour_stats,
    _detect_ioc_type, _auto_scan_and_alert,
)
from schemas.reports import (
    PatchReport, BehavioralReport, FileIntegrityReport, MisconfigReport,
    SoftwareInventoryReport, AssetDiscoveryReport, WatchdogStatusReport, AgentMonitorReport,
    TelemetryReport, PreExecEventReport, RegistryChangeReport, ZeroDayReport, BufferPolishReport,
    FilelessDetectionEventReport, MemoryScanEventReport, UsbDiskEventReport,
    C2BeaconingReport, LiveThreatIntelReport, OfflineScanReport, VulnerabilityScanReport,
    ProcessTreeReport, ShadowITReport, ExploitMitigationReport, InstallationVisibilityReport,
    NetworkDPIReport, PrivilegeEscalationReport, SilentDeploymentReport, LateralMovementReport,
    PortScanReport, HostFirewallReport, WebDNSFilterReport, ScriptMonitorReport,
    RansomwareCanaryReport, CredentialDumpingReport, NextGenAVReport, UserBehaviourReport,
    ProcessesReport, NetworkConnectionsReport,
)

router = APIRouter(tags=["detections"])


def _get_ml():
    """Lazy import to avoid circular deps."""
    from main import ML_ENABLED, behavioral_baseliner
    return ML_ENABLED, behavioral_baseliner


# ---- Patch Monitoring -------------------------------------------------------

@router.get("/agents/{agent_id}/patch-monitoring")
async def get_agent_patch_monitoring(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_patch_findings(db, agent)}


@router.post("/agents/{agent_id}/patch-monitoring/report")
async def report_agent_patches(agent_id: str, data: PatchReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(OSPatchInfo(agent_id=agent_id, missing_patches=json.dumps(data.missing_patches), count=data.count, oldest_missing_days=data.oldest_missing_days, severity=data.severity))
    if data.severity == "high" and data.count > 0:
        alert = Alert(agent_id=agent_id, title=f"Missing OS Patches ({data.count} pending)", description=f"Agent has {data.count} missing patches, oldest from {data.oldest_missing_days} days ago", severity="high", type="misconfiguration", mitre_tactic_id=MITRE_ATTACK_MAP["os_patch_monitoring"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["os_patch_monitoring"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["os_patch_monitoring"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["os_patch_monitoring"]["technique_name"], score=min(70 + data.count * 5, 95), details=json.dumps({"missing_patches": data.missing_patches, "oldest_missing_days": data.oldest_missing_days}))
        db.add(alert)
    db.commit()
    return {"message": "Patch report recorded", "agent_id": agent_id, "patch_count": data.count, "severity": data.severity}


# ---- Behavioral Heuristics -------------------------------------------------

@router.get("/agents/{agent_id}/behavioral-heuristics")
async def get_agent_behavioral(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_behavioral_findings(db, agent)}


@router.post("/agents/{agent_id}/behavioral-heuristics/report")
async def report_agent_behavioral(agent_id: str, data: BehavioralReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(BehavioralSnapshot(agent_id=agent_id, cpu_usage=data.cpu_usage, ram_usage=data.ram_usage, process_count=data.process_count, net_connections=data.net_connections, is_anomaly=data.is_anomaly, anomaly_score=data.anomaly_score, ml_active=data.ml_active, history_size=data.history_size, details=data.details))
    if data.is_anomaly:
        existing_open = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "behavioral_anomaly", Alert.status == "open").first()
        if not existing_open:
            db.add(Alert(agent_id=agent_id, title="Behavioral Anomaly Detected", description=f"Agent behavior deviates from baseline (score: {data.anomaly_score}). Possible compromise or malware activity.", severity="high", type="behavioral_anomaly", mitre_tactic_id=MITRE_ATTACK_MAP["behavioral_heuristics"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["behavioral_heuristics"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["behavioral_heuristics"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["behavioral_heuristics"]["technique_name"], score=round(abs(data.anomaly_score) * 20 + 60, 1), details=json.dumps({"cpu_usage": data.cpu_usage, "ram_usage": data.ram_usage, "process_count": data.process_count, "net_connections": data.net_connections, "anomaly_score": data.anomaly_score, "ml_active": data.ml_active})))
    db.commit()
    return {"message": "Behavioral snapshot recorded", "agent_id": agent_id, "is_anomaly": data.is_anomaly, "anomaly_score": data.anomaly_score}


# ---- File Integrity --------------------------------------------------------

@router.get("/agents/{agent_id}/file-integrity")
async def get_agent_file_integrity(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_file_integrity_findings(db, agent)}


@router.post("/agents/{agent_id}/file-integrity/report")
async def report_agent_file_integrity(agent_id: str, data: FileIntegrityReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(FileIntegrityCheck(agent_id=agent_id, monitored_files=json.dumps(data.monitored_files), changes_detected=data.changes_detected, changed_files=json.dumps(data.changed_files), severity=data.severity))
    if data.changes_detected:
        db.add(Alert(agent_id=agent_id, title="File Integrity Alert: Critical File Changed", description=f"Sensitive files modified: {', '.join(data.changed_files)}", severity=data.severity, type="file_integrity", mitre_tactic_id=MITRE_ATTACK_MAP["file_integrity_monitoring"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["file_integrity_monitoring"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["file_integrity_monitoring"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["file_integrity_monitoring"]["technique_name"], score=85.0, details=json.dumps({"changed_files": data.changed_files, "monitored_files": data.monitored_files})))
    db.commit()
    return {"message": "File integrity check recorded", "agent_id": agent_id, "changes_detected": data.changes_detected}


# ---- Misconfigurations -----------------------------------------------------

@router.get("/agents/{agent_id}/misconfigurations")
async def get_agent_misconfigurations(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    misconfig = db.query(MisconfigurationCheck).filter(MisconfigurationCheck.agent_id == agent_id).order_by(MisconfigurationCheck.checked_at.desc()).first()
    result = {"agent_id": agent_id, "hostname": agent.hostname, "rdp_open": False, "firewall_off": False, "guest_account": False, "weak_password_policy": False, "severity": "info", "last_checked": None}
    if misconfig:
        result.update({"rdp_open": misconfig.rdp_open, "firewall_off": misconfig.firewall_off, "guest_account": misconfig.guest_account, "weak_password_policy": misconfig.weak_password_policy, "severity": misconfig.severity, "last_checked": misconfig.checked_at.isoformat()})
    else:
        result.update({"rdp_open": not agent.firewall_enabled if agent.os_type == "Windows" else False, "firewall_off": not agent.firewall_enabled, "guest_account": False, "weak_password_policy": False, "severity": "high" if not agent.firewall_enabled else "info"})
    return result


@router.post("/agents/{agent_id}/misconfigurations/report")
async def report_agent_misconfigurations(agent_id: str, data: MisconfigReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(MisconfigurationCheck(agent_id=agent_id, rdp_open=data.rdp_open, firewall_off=data.firewall_off, guest_account=data.guest_account, weak_password_policy=data.weak_password_policy, severity=data.severity))
    if data.severity == "high":
        issues = []
        if data.rdp_open: issues.append("RDP exposed")
        if data.firewall_off: issues.append("Firewall disabled")
        if data.guest_account: issues.append("Guest account active")
        if data.weak_password_policy: issues.append("Weak password policy")
        existing_open = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "misconfiguration", Alert.status == "open").first()
        if not existing_open and issues:
            db.add(Alert(agent_id=agent_id, title="Security Misconfigurations Detected", description=f"Issues found: {', '.join(issues)}", severity="high", type="misconfiguration", mitre_tactic_id=MITRE_ATTACK_MAP["misconfiguration_detection"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["misconfiguration_detection"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["misconfiguration_detection"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["misconfiguration_detection"]["technique_name"], score=75.0, details=json.dumps({"issues": issues, "rdp_open": data.rdp_open, "firewall_off": data.firewall_off, "guest_account": data.guest_account, "weak_password_policy": data.weak_password_policy})))
    db.commit()
    return {"message": "Misconfiguration check recorded", "agent_id": agent_id, "has_issues": data.rdp_open or data.firewall_off or data.guest_account or data.weak_password_policy}


# ---- Software Inventory ----------------------------------------------------

@router.get("/agents/{agent_id}/software-inventory")
async def get_agent_software_inventory(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    inventory = generate_software_inventory(db, agent)
    return {"agent_id": agent_id, "hostname": agent.hostname, "total_apps": len(inventory), "approved_count": sum(1 for a in inventory if a["is_approved"]), "unapproved_count": sum(1 for a in inventory if not a["is_approved"]), "software": inventory}


@router.post("/agents/{agent_id}/software-inventory/report")
async def report_agent_software_inventory(agent_id: str, data: SoftwareInventoryReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.query(Application).filter(Application.agent_id == agent_id).delete()
    unapproved_count = 0
    for item in data.software:
        risk = 0.0
        if not item.is_approved:
            risk = random.uniform(20, 60)
            unapproved_count += 1
        db.add(Application(agent_id=agent_id, name=item.name, version=item.version, vendor=item.vendor, install_date=datetime.utcnow(), is_approved=item.is_approved, is_running=True, risk_score=risk, cve_list="[]"))
    if unapproved_count > 0:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "shadow_it", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Shadow IT: {unapproved_count} Unapproved Applications", description=f"Software inventory scan found {unapproved_count} unapproved applications on {agent.hostname}", severity="low", type="shadow_it", mitre_tactic_id="TA0003", mitre_tactic_name=get_mitre_tactic_name("TA0003"), mitre_technique_id="T1078", mitre_technique_name=get_mitre_technique_name("T1078"), score=random.uniform(10, 30), details=json.dumps({"unapproved_count": unapproved_count, "source": "software_inventory_report"})))
    db.commit()
    return {"message": "Software inventory recorded", "agent_id": agent_id, "total_apps": len(data.software), "unapproved": unapproved_count}


# ---- Asset Discovery -------------------------------------------------------

@router.get("/agents/{agent_id}/asset-discovery")
async def get_agent_asset_discovery(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, **generate_asset_discovery(agent)}


@router.post("/agents/{agent_id}/asset-discovery/report")
async def report_agent_asset_discovery(agent_id: str, data: AssetDiscoveryReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    if data.hostname: agent.hostname = data.hostname
    if data.os_type: agent.os_type = data.os_type
    if data.os_version: agent.os_version = data.os_version
    if data.processor: agent.cpu_model = data.processor
    if data.cpu_cores: agent.cpu_cores = data.cpu_cores
    if data.ram_gb: agent.ram_total_gb = int(data.ram_gb)
    if data.disk_total_gb: agent.disk_total_gb = int(data.disk_total_gb)
    if data.disk_used_gb: agent.disk_used_gb = float(data.disk_used_gb)
    if data.mac_address: agent.mac_address = data.mac_address
    if data.ip_address: agent.ip_address = data.ip_address
    agent.last_heartbeat = datetime.utcnow()
    agent.status = "online"
    db.commit()
    return {"message": "Asset discovery info updated", "agent_id": agent_id, "hostname": agent.hostname}


# ---- Watchdog Status -------------------------------------------------------

@router.get("/agents/{agent_id}/watchdog-status")
async def get_agent_watchdog(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_watchdog_status(db, agent)}


@router.post("/agents/{agent_id}/watchdog-status/report")
async def report_agent_watchdog(agent_id: str, data: WatchdogStatusReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(WatchdogEvent(agent_id=agent_id, agent_running=data.agent_running, tamper_detected=data.tamper_detected, restart_count=data.restart_count, log_entry=data.log_entry))
    if data.tamper_detected:
        agent.tamper_protection = False
        agent.self_defense_status = "compromised"
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "tamper", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title="Tamper Protection Triggered", description=f"Agent process was interrupted and restarted {data.restart_count} times. Self-defense mechanism may be compromised.", severity="high", type="tamper", mitre_tactic_id=MITRE_ATTACK_MAP["watchdog_process"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["watchdog_process"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["watchdog_process"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["watchdog_process"]["technique_name"], score=85.0, details=json.dumps({"restart_count": data.restart_count, "log": data.log_entry})))
    else:
        agent.tamper_protection = True
        agent.self_defense_status = "active"
    agent.last_heartbeat = datetime.utcnow()
    agent.status = "online" if data.agent_running else "offline"
    db.commit()
    return {"message": "Watchdog status recorded", "agent_id": agent_id, "tamper_detected": data.tamper_detected, "agent_running": data.agent_running}


# ---- Monitoring Logs -------------------------------------------------------

@router.get("/agents/{agent_id}/monitoring-logs")
async def get_agent_monitoring_logs(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_monitoring_stats(db, agent)}


@router.post("/agents/{agent_id}/monitoring-logs/report")
async def report_agent_monitoring(agent_id: str, data: AgentMonitorReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(AgentMonitorLog(agent_id=agent_id, cpu_percent=data.cpu_percent, ram_percent=data.ram_percent, interval_seconds=data.interval_seconds))
    agent.cpu_usage = data.cpu_percent
    agent.ram_used_gb = round(data.ram_percent / 100 * agent.ram_total_gb, 1) if agent.ram_total_gb else 0.0
    agent.last_heartbeat = datetime.utcnow()
    agent.status = "online"
    db.commit()
    return {"message": "Monitoring data recorded", "agent_id": agent_id, "cpu_percent": data.cpu_percent, "ram_percent": data.ram_percent}


# ---- Telemetry report -------------------------------------------------------

@router.post("/agents/{agent_id}/telemetry/report")
async def report_agent_telemetry(agent_id: str, data: TelemetryReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    if data.hostname: agent.hostname = data.hostname
    if data.os_type: agent.os_type = data.os_type
    if data.processor: agent.cpu_model = data.processor
    if data.cpu_cores: agent.cpu_cores = data.cpu_cores
    if data.ram_gb: agent.ram_total_gb = int(data.ram_gb)
    if data.mac_address: agent.mac_address = data.mac_address
    if data.platform: agent.os_version = data.platform
    agent.last_heartbeat = datetime.utcnow()
    agent.status = "online"
    db.commit()
    return {"message": "Telemetry recorded", "agent_id": agent_id, "fields_received": data.fields_present, "schema_version": data.schema_version, "format_valid": data.format_valid}


# ---- Pre-Execution Events --------------------------------------------------

@router.get("/agents/{agent_id}/pre-execution-events")
async def get_agent_pre_execution(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_execution_prevention_stats(db, agent)}


@router.post("/agents/{agent_id}/pre-execution-events/report")
async def report_agent_pre_execution(agent_id: str, data: PreExecEventReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(ProcessExecutionEvent(agent_id=agent_id, process_name=data.process_name, process_path=data.process_path, file_hash=data.file_hash, blocked=data.blocked, reason=data.reason))
    if data.file_hash:
        _auto_scan_and_alert(agent_id, db, hashes=[data.file_hash])
    if data.blocked:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "malware", Alert.status == "open", Alert.title.like(f"%{data.process_name}%")).first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Pre-Execution Blocked: {data.process_name}", description=f"Process execution prevented. Hash matched known malware. Path: {data.process_path}", severity="critical", type="malware", mitre_tactic_id=MITRE_ATTACK_MAP["pre_execution_prevention"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["pre_execution_prevention"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["pre_execution_prevention"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["pre_execution_prevention"]["technique_name"], score=95.0, details=json.dumps({"process_name": data.process_name, "process_path": data.process_path, "file_hash": data.file_hash, "reason": data.reason})))
    db.commit()
    return {"message": "Execution event recorded", "agent_id": agent_id, "blocked": data.blocked, "reason": data.reason}


# ---- Registry Monitoring ---------------------------------------------------

@router.get("/agents/{agent_id}/registry-monitoring")
async def get_agent_registry_monitoring(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_registry_monitoring_stats(db, agent)}


@router.post("/agents/{agent_id}/registry-monitoring/report")
async def report_agent_registry_change(agent_id: str, data: RegistryChangeReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(RegistryChange(agent_id=agent_id, key_path=data.key_path, value_name=data.value_name, old_value=data.old_value, new_value=data.new_value, change_type=data.change_type, is_auto_start=data.is_auto_start))
    if data.is_auto_start:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "persistence", Alert.status == "open", Alert.title.like(f"%Registry%{data.value_name}%")).first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Registry Persistence Added: {data.value_name}", description=f"New auto-start registry entry in Run key: {data.key_path}\\{data.value_name}", severity="high", type="persistence", mitre_tactic_id=MITRE_ATTACK_MAP["registry_monitoring"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["registry_monitoring"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["registry_monitoring"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["registry_monitoring"]["technique_name"], score=75.0, details=json.dumps({"key_path": data.key_path, "value_name": data.value_name, "new_value": data.new_value, "is_auto_start": data.is_auto_start})))
    db.commit()
    return {"message": "Registry change recorded", "agent_id": agent_id, "is_auto_start": data.is_auto_start}


# ---- Zero-Day Findings -----------------------------------------------------

@router.get("/agents/{agent_id}/zero-day-findings")
async def get_agent_zero_day(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_zero_day_stats(db, agent)}


@router.post("/agents/{agent_id}/zero-day-findings/report")
async def report_agent_zero_day(agent_id: str, data: ZeroDayReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(ZeroDayFinding(agent_id=agent_id, file_name=data.file_name, file_path=data.file_path, unknown_hash=data.unknown_hash, risky_location=data.risky_location))
    if data.unknown_hash or data.risky_location:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "zero_day", Alert.status == "open").first()
        if not existing:
            reasons = []
            if data.unknown_hash: reasons.append("unknown hash")
            if data.risky_location: reasons.append("risky location")
            db.add(Alert(agent_id=agent_id, title=f"Zero-Day Suspicious File: {data.file_name}", description=f"Unknown executable in suspicious location. Reasons: {', '.join(reasons)}", severity="high", type="zero_day", mitre_tactic_id=MITRE_ATTACK_MAP["zero_day_detection"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["zero_day_detection"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["zero_day_detection"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["zero_day_detection"]["technique_name"], score=85.0, details=json.dumps({"file_name": data.file_name, "file_path": data.file_path, "unknown_hash": data.unknown_hash, "risky_location": data.risky_location})))
    db.commit()
    return {"message": "Zero-day finding recorded", "agent_id": agent_id, "file": data.file_name}


# ---- Buffer Polish ----------------------------------------------------------

@router.post("/agents/{agent_id}/buffer-polish/report")
async def report_agent_buffer_polish(agent_id: str, data: BufferPolishReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    if data.hostname: agent.hostname = data.hostname
    if data.os: agent.os_type = data.os
    if data.cpu_usage: agent.cpu_usage = data.cpu_usage
    if data.ram_used_gb: agent.ram_used_gb = data.ram_used_gb
    if data.ram_total_gb: agent.ram_total_gb = int(data.ram_total_gb)
    if data.mac: agent.mac_address = data.mac
    db.add(AgentMonitorLog(agent_id=agent_id, cpu_percent=data.cpu_usage, ram_percent=round(data.ram_used_gb / max(data.ram_total_gb, 1) * 100, 1) if data.ram_total_gb else 0.0, interval_seconds=30))
    agent.last_heartbeat = datetime.utcnow()
    agent.status = data.status if data.status in ("healthy", "degraded", "offline") else "online"
    db.commit()
    return {"message": "Buffer polish telemetry recorded", "agent_id": agent_id, "status": agent.status, "cpu_usage": data.cpu_usage}


# ---- Fileless Detection ----------------------------------------------------

@router.get("/agents/{agent_id}/fileless-detection")
async def get_agent_fileless(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_fileless_stats(db, agent)}


@router.post("/agents/{agent_id}/fileless-detection/report")
async def report_agent_fileless(agent_id: str, data: FilelessDetectionEventReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(FilelessDetectionEvent(agent_id=agent_id, pid=data.pid, process_name=data.process_name, reason=data.reason, eventlog_alert=data.eventlog_alert))
    existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "fileless_malware", Alert.status == "open").first()
    if not existing:
        db.add(Alert(agent_id=agent_id, title=f"Fileless Malware: {data.process_name}", description=data.reason, severity="critical", type="fileless_malware", mitre_tactic_id=MITRE_ATTACK_MAP["fileless_detection"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["fileless_detection"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["fileless_detection"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["fileless_detection"]["technique_name"], score=90.0, details=json.dumps({"pid": data.pid, "process_name": data.process_name, "reason": data.reason, "eventlog_alert": data.eventlog_alert})))
    db.commit()
    return {"message": "Fileless detection recorded", "agent_id": agent_id, "reason": data.reason}


# ---- Memory Scan -----------------------------------------------------------

@router.get("/agents/{agent_id}/memory-scan")
async def get_agent_memory_scan(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_memory_scan_stats(db, agent)}


@router.post("/agents/{agent_id}/memory-scan/report")
async def report_agent_memory_scan(agent_id: str, data: MemoryScanEventReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(MemoryScanEvent(agent_id=agent_id, pid=data.pid, process_name=data.process_name, reason=data.reason, shellcode_detected=data.shellcode_detected))
    if data.shellcode_detected:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "fileless_malware", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Memory Scan: Shellcode Detected in {data.process_name}", description=data.reason, severity="critical", type="fileless_malware", mitre_tactic_id=MITRE_ATTACK_MAP["memory_scan"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["memory_scan"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["memory_scan"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["memory_scan"]["technique_name"], score=88.0, details=json.dumps({"pid": data.pid, "process_name": data.process_name, "reason": data.reason, "shellcode_detected": data.shellcode_detected})))
    db.commit()
    return {"message": "Memory scan recorded", "agent_id": agent_id, "shellcode_detected": data.shellcode_detected}


# ---- USB/Disk Control ------------------------------------------------------

@router.get("/agents/{agent_id}/usb-disk-control")
async def get_agent_usb_disk(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_usb_disk_stats(db, agent)}


@router.post("/agents/{agent_id}/usb-disk-control/report")
async def report_agent_usb_disk(agent_id: str, data: UsbDiskEventReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(UsbDiskEvent(agent_id=agent_id, usb_devices=json.dumps(data.usb_devices), blocked_devices=json.dumps(data.blocked_devices), usb_control_ok=data.usb_control_ok, encrypted=data.encrypted, protection_on=data.protection_on))
    if data.encrypted is not None:
        agent.bitlocker_enabled = data.encrypted
    issues = []
    if not data.usb_control_ok: issues.append("unauthorized USB devices")
    if not data.encrypted: issues.append("disk not encrypted")
    if issues:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "usb_violation", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title="USB/Disk Security Issue", description=f"Issues: {', '.join(issues)}", severity="high", type="usb_violation", mitre_tactic_id=MITRE_ATTACK_MAP["usb_disk_control"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["usb_disk_control"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["usb_disk_control"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["usb_disk_control"]["technique_name"], score=75.0, details=json.dumps({"usb_control_ok": data.usb_control_ok, "encrypted": data.encrypted, "blocked_devices": data.blocked_devices})))
    db.commit()
    return {"message": "USB/Disk control event recorded", "agent_id": agent_id, "usb_control_ok": data.usb_control_ok, "encrypted": data.encrypted}


# ---- C2 Beaconing ----------------------------------------------------------

@router.get("/agents/{agent_id}/c2-beaconing")
async def get_agent_c2(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_c2_stats(db, agent)}


@router.post("/agents/{agent_id}/c2-beaconing/report")
async def report_agent_c2(agent_id: str, data: C2BeaconingReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(C2BeaconingEvent(agent_id=agent_id, src_ip=data.src_ip, dst_ip=data.dst_ip, connections=data.connections, avg_interval=data.avg_interval, variance=data.variance))
    if data.dst_ip:
        _auto_scan_and_alert(agent_id, db, ips=[data.dst_ip])
    if data.variance < 25 and data.connections >= 5:
        fp = f"beaconing:{data.src_ip}:{data.dst_ip}"
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "beaconing", Alert.status == "open", Alert.fingerprint == fp).first()
        if existing:
            existing.occurrence_count += 1
            existing.last_seen_at = datetime.utcnow()
        else:
            db.add(Alert(agent_id=agent_id, title=f"C2 Beaconing Detected: {data.dst_ip}", description=f"Regular beaconing from {data.src_ip} -> {data.dst_ip} | Avg interval: {data.avg_interval:.1f}s | Variance: {data.variance:.2f}", severity="high", type="beaconing", fingerprint=fp, mitre_tactic_id=MITRE_ATTACK_MAP["c2_beaconing"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["c2_beaconing"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["c2_beaconing"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["c2_beaconing"]["technique_name"], score=80.0, details=json.dumps({"src_ip": data.src_ip, "dst_ip": data.dst_ip, "connections": data.connections, "avg_interval": data.avg_interval, "variance": data.variance})))
    db.commit()
    return {"message": "C2 beaconing report recorded", "agent_id": agent_id, "beaconing_detected": data.variance < 25 and data.connections >= 5}


# ---- Threat Intel ----------------------------------------------------------

@router.get("/agents/{agent_id}/threat-intel")
async def get_agent_threat_intel(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_threat_intel_stats(db, agent)}


@router.post("/agents/{agent_id}/threat-intel/report")
async def report_agent_threat_intel(agent_id: str, data: LiveThreatIntelReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(LiveThreatIntelResult(agent_id=agent_id, indicator_type=data.indicator_type, indicator=data.indicator, pulse_count=data.pulse_count, reputation=data.reputation, country=data.country, raw_json=data.raw_json))
    if data.indicator:
        ioc_type = _detect_ioc_type(data.indicator)
        kwargs: dict = {}
        if ioc_type == "ip": kwargs["ips"] = [data.indicator]
        elif ioc_type == "hash": kwargs["hashes"] = [data.indicator]
        elif ioc_type in ("domain", "url"): kwargs["domains"] = [data.indicator]
        _auto_scan_and_alert(agent_id, db, **kwargs)
    if data.pulse_count > 0:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "threat_intel_match", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Threat Intel Match: {data.indicator}", description=f"Indicator {data.indicator} ({data.indicator_type}) has {data.pulse_count} pulse(s) | Reputation: {data.reputation}", severity="high", type="threat_intel_match", mitre_tactic_id=MITRE_ATTACK_MAP["threat_intel"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["threat_intel"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["threat_intel"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["threat_intel"]["technique_name"], score=70.0, details=json.dumps({"indicator_type": data.indicator_type, "indicator": data.indicator, "pulse_count": data.pulse_count, "reputation": data.reputation, "country": data.country})))
    db.commit()
    return {"message": "Threat intel result recorded", "agent_id": agent_id, "indicator": data.indicator, "pulse_count": data.pulse_count}


# ---- Offline Scan ----------------------------------------------------------

@router.get("/agents/{agent_id}/offline-scan")
async def get_agent_offline_scan(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_offline_scan_stats(db, agent)}


@router.post("/agents/{agent_id}/offline-scan/report")
async def report_agent_offline_scan(agent_id: str, data: OfflineScanReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(OfflineScanEvent(agent_id=agent_id, file_path=data.file_path, file_hash=data.file_hash, threat_name=data.threat_name, scan_directory=data.scan_directory, threats_found=data.threats_found))
    if data.file_hash:
        _auto_scan_and_alert(agent_id, db, hashes=[data.file_hash])
    if data.threats_found > 0:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "offline_threat", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Offline Scan Threat: {data.threat_name}", description=f"Threat '{data.threat_name}' found at {data.file_path} (hash: {data.file_hash})", severity="high", type="offline_threat", mitre_tactic_id=MITRE_ATTACK_MAP["offline_protection"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["offline_protection"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["offline_protection"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["offline_protection"]["technique_name"], score=75.0, details=json.dumps({"file_path": data.file_path, "file_hash": data.file_hash, "threat_name": data.threat_name, "scan_directory": data.scan_directory, "threats_found": data.threats_found})))
    db.commit()
    return {"message": "Offline scan result recorded", "agent_id": agent_id, "threats_found": data.threats_found}


# ---- Vulnerability Scan ----------------------------------------------------

@router.get("/agents/{agent_id}/vulnerability-scan")
async def get_agent_vuln_scan(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_vuln_scan_stats(db, agent)}


@router.post("/agents/{agent_id}/vulnerability-scan/report")
async def report_agent_vuln_scan(agent_id: str, data: VulnerabilityScanReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(VulnerabilityFinding(agent_id=agent_id, finding_type=data.finding_type, software=data.software, version=data.version, cve_id=data.cve_id, severity=data.severity, risk=data.risk, description=data.description, port=data.port, service=data.service))
    if data.risk in ("Critical", "HIGH") or data.severity in ("Critical", "High"):
        alert_type = "vulnerability_critical" if data.risk == "Critical" or data.severity == "Critical" else "vulnerability_high"
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == alert_type, Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Vulnerability: {data.cve_id if data.cve_id else data.finding_type}", description=data.description, severity="critical" if data.risk == "Critical" else "high", type=alert_type, mitre_tactic_id=MITRE_ATTACK_MAP["vulnerability_scan"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["vulnerability_scan"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["vulnerability_scan"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["vulnerability_scan"]["technique_name"], score=85.0 if data.risk == "Critical" else 70.0, details=json.dumps({"finding_type": data.finding_type, "software": data.software, "version": data.version, "cve_id": data.cve_id, "severity": data.severity, "port": data.port, "service": data.service, "description": data.description})))
    db.commit()
    return {"message": "Vulnerability finding recorded", "agent_id": agent_id, "finding_type": data.finding_type, "risk": data.risk}


# ---- Process Tree ----------------------------------------------------------

@router.get("/agents/{agent_id}/process-tree")
async def get_agent_process_tree(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_process_tree_stats(db, agent)}


@router.post("/agents/{agent_id}/process-tree/report")
async def report_agent_process_tree(agent_id: str, data: ProcessTreeReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(ProcessTreeFinding(agent_id=agent_id, finding_type=data.finding_type, parent_name=data.parent_name, parent_pid=data.parent_pid, child_name=data.child_name, child_pid=data.child_pid, risk=data.risk, description=data.description, cmdline=data.cmdline))
    if data.risk in ("CRITICAL", "HIGH"):
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "process_anomaly", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Process Anomaly: {data.finding_type}", description=data.description, severity="critical" if data.risk == "CRITICAL" else "high", type="process_anomaly", mitre_tactic_id=MITRE_ATTACK_MAP["process_tree"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["process_tree"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["process_tree"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["process_tree"]["technique_name"], score=90.0 if data.risk == "CRITICAL" else 70.0, details=json.dumps({"finding_type": data.finding_type, "parent_name": data.parent_name, "child_name": data.child_name, "risk": data.risk, "cmdline": data.cmdline, "description": data.description})))
    db.commit()
    return {"message": "Process tree finding recorded", "agent_id": agent_id, "finding_type": data.finding_type, "risk": data.risk}


# ---- Action Result ---------------------------------------------------------

@router.post("/agents/{agent_id}/action-result/report")
async def report_action_result(agent_id: str, data: dict, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    from core.logging import logger
    log_action = data.get("action", "unknown")
    target = data.get("target", "")
    result = data.get("result", {})
    status = result.get("status", "unknown")
    pending = db.query(PendingAction).filter(PendingAction.agent_id == agent_id, PendingAction.action == log_action, PendingAction.target == target, PendingAction.status == "delivered").order_by(PendingAction.delivered_at.desc()).first()
    if pending:
        pending.status = "completed" if status in ("success", "completed", "ok") else "failed"
        pending.completed_at = datetime.utcnow()
        pending.result = json.dumps(result)
        db.commit()
    logger.info(f"Agent {agent_id} reported action result", action=log_action, status=status)
    return {"message": "Action result recorded"}


# ---- Shadow IT -------------------------------------------------------------

@router.get("/agents/{agent_id}/shadow-it")
async def get_agent_shadow_it(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_shadow_it_stats(db, agent)}


@router.post("/agents/{agent_id}/shadow-it/report")
async def report_agent_shadow_it(agent_id: str, data: ShadowITReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(ShadowITFinding(agent_id=agent_id, finding_type=data.finding_type, service_name=data.service_name, domain=data.domain, category=data.category, risk=data.risk, description=data.description, ip=data.ip, mac=data.mac))
    if data.risk == "HIGH" or data.finding_type in ("unauthorized_software",):
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "shadow_it", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Shadow IT: {data.service_name if data.service_name else data.finding_type}", description=data.description, severity="high", type="shadow_it", mitre_tactic_id=MITRE_ATTACK_MAP["shadow_it"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["shadow_it"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["shadow_it"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["shadow_it"]["technique_name"], score=65.0, details=json.dumps({"finding_type": data.finding_type, "service_name": data.service_name, "domain": data.domain, "category": data.category, "risk": data.risk, "ip": data.ip, "mac": data.mac, "description": data.description})))
    db.commit()
    return {"message": "Shadow IT finding recorded", "agent_id": agent_id, "finding_type": data.finding_type, "risk": data.risk}


# ---- Exploit Mitigation ----------------------------------------------------

@router.get("/agents/{agent_id}/exploit-mitigation")
async def get_agent_exploit_mitigation(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_exploit_mitigation_stats(db, agent)}


@router.post("/agents/{agent_id}/exploit-mitigation/report")
async def report_agent_exploit_mitigation(agent_id: str, data: ExploitMitigationReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(ExploitMitigationEvent(agent_id=agent_id, aslr_enabled=data.aslr_enabled, aslr_level=data.aslr_level, dep_enabled=data.dep_enabled, dep_policy=data.dep_policy, acg_enabled=data.acg_enabled, os=data.os, risk_summary=data.risk_summary, severity=data.severity))
    if data.severity in ("high", "medium"):
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "exploit_mitigation", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Exploit Mitigation Issue: {data.risk_summary}", description=data.risk_summary, severity=data.severity, type="exploit_mitigation", mitre_tactic_id=MITRE_ATTACK_MAP["exploit_mitigation"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["exploit_mitigation"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["exploit_mitigation"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["exploit_mitigation"]["technique_name"], score=50.0 if data.severity == "medium" else 70.0, details=json.dumps({"aslr_enabled": data.aslr_enabled, "dep_enabled": data.dep_enabled, "acg_enabled": data.acg_enabled, "risk_summary": data.risk_summary})))
    db.commit()
    return {"message": "Exploit mitigation report recorded", "agent_id": agent_id, "risk_summary": data.risk_summary}


# ---- Installation Visibility -----------------------------------------------

@router.get("/agents/{agent_id}/installation-visibility")
async def get_agent_installation_visibility(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_installation_visibility_stats(db, agent)}


@router.post("/agents/{agent_id}/installation-visibility/report")
async def report_agent_installation_visibility(agent_id: str, data: InstallationVisibilityReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(InstallationVisibilityEvent(agent_id=agent_id, boot_time=data.boot_time, install_path=data.install_path, running_as_username=data.running_as_username, running_as_admin=data.running_as_admin, os_name=data.os_name, os_release=data.os_release, os_machine=data.os_machine, hostname=data.hostname, agent_version=data.agent_version))
    if data.boot_time: agent.last_heartbeat = datetime.utcnow()
    if data.hostname: agent.hostname = data.hostname
    db.commit()
    return {"message": "Installation visibility recorded", "agent_id": agent_id, "hostname": data.hostname}


# ---- Network DPI -----------------------------------------------------------

@router.get("/agents/{agent_id}/network-dpi")
async def get_agent_network_dpi(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_network_dpi_stats(db, agent)}


@router.post("/agents/{agent_id}/network-dpi/report")
async def report_agent_network_dpi(agent_id: str, data: NetworkDPIReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(NetworkDPIEvent(agent_id=agent_id, src_ip=data.src_ip, dst_ip=data.dst_ip, src_port=data.src_port, dst_port=data.dst_port, protocol=data.protocol, reason=data.reason, payload_size=data.payload_size, threat_type=data.threat_type))
    if data.dst_ip:
        _auto_scan_and_alert(agent_id, db, ips=[data.dst_ip])
    if data.threat_type in ("suspicious_c2_port", "dns_tunneling", "cleartext_credentials"):
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "network_dpi", Alert.status == "open").first()
        if not existing:
            severity_label = "critical" if data.threat_type == "cleartext_credentials" else "high"
            db.add(Alert(agent_id=agent_id, title=f"DPI: {data.threat_type.replace('_', ' ').title()}", description=data.reason, severity=severity_label, type="network_dpi", mitre_tactic_id=MITRE_ATTACK_MAP["network_dpi"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["network_dpi"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["network_dpi"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["network_dpi"]["technique_name"], score=85.0 if data.threat_type == "cleartext_credentials" else 68.0, details=json.dumps({"src_ip": data.src_ip, "dst_ip": data.dst_ip, "dst_port": data.dst_port, "protocol": data.protocol, "threat_type": data.threat_type, "payload_size": data.payload_size, "reason": data.reason})))
    db.commit()
    return {"message": "Network DPI event recorded", "agent_id": agent_id, "threat_type": data.threat_type}


# ---- Privilege Escalation --------------------------------------------------

@router.get("/agents/{agent_id}/privilege-escalation")
async def get_agent_privilege_escalation(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_privilege_escalation_stats(db, agent)}


@router.post("/agents/{agent_id}/privilege-escalation/report")
async def report_agent_privilege_escalation(agent_id: str, data: PrivilegeEscalationReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(PrivilegeEscalationEvent(agent_id=agent_id, check_type=data.check_type, os=data.os, finding=data.finding, process_name=data.process_name, user=data.user, privilege=data.privilege, risk_reason=data.risk_reason, severity=data.severity))
    if data.severity in ("critical", "high"):
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "privilege_escalation", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Privilege Escalation: {data.check_type.replace('_', ' ').title()}", description=data.finding, severity=data.severity, type="privilege_escalation", mitre_tactic_id=MITRE_ATTACK_MAP["privilege_escalation"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["privilege_escalation"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["privilege_escalation"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["privilege_escalation"]["technique_name"], score=90.0 if data.severity == "critical" else 72.0, details=json.dumps({"check_type": data.check_type, "finding": data.finding, "process_name": data.process_name, "user": data.user, "privilege": data.privilege, "risk_reason": data.risk_reason})))
    db.commit()
    return {"message": "Privilege escalation event recorded", "agent_id": agent_id, "severity": data.severity}


# ---- Silent Deployment -----------------------------------------------------

@router.get("/agents/{agent_id}/silent-deployment")
async def get_agent_silent_deployment(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_silent_deployment_stats(db, agent)}


@router.post("/agents/{agent_id}/silent-deployment/report")
async def report_agent_silent_deployment(agent_id: str, data: SilentDeploymentReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(SilentDeploymentEvent(agent_id=agent_id, no_window=data.no_window, hidden=data.hidden, startup_type=data.startup_type, process_name=data.process_name, parent_process=data.parent_process, is_silent=data.is_silent))
    if data.is_silent:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "silent_deployment", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title="Silent/Binary Deployment Detected", description=f"Process {data.process_name} running silently (no_window={data.no_window}, hidden={data.hidden}, startup={data.startup_type})", severity="medium", type="silent_deployment", mitre_tactic_id=MITRE_ATTACK_MAP["silent_deployment"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["silent_deployment"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["silent_deployment"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["silent_deployment"]["technique_name"], score=55.0, details=json.dumps({"no_window": data.no_window, "hidden": data.hidden, "startup_type": data.startup_type, "process_name": data.process_name, "parent_process": data.parent_process, "is_silent": data.is_silent})))
    db.commit()
    return {"message": "Silent deployment event recorded", "agent_id": agent_id, "is_silent": data.is_silent}


# ---- Lateral Movement ------------------------------------------------------

@router.get("/agents/{agent_id}/lateral-movement")
async def get_agent_lateral_movement(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_lateral_movement_stats(db, agent)}


@router.post("/agents/{agent_id}/lateral-movement/report")
async def report_agent_lateral_movement(agent_id: str, data: LateralMovementReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(LateralMovementEvent(agent_id=agent_id, movement_type=data.movement_type, source_ip=data.source_ip, destination_ip=data.destination_ip, port=data.port, service=data.service, connection_count=data.connection_count, risk=data.risk, description=data.description))
    if data.risk in ("CRITICAL", "HIGH"):
        fp = f"lateral_movement:{data.source_ip}:{data.destination_ip}:{data.port}"
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "lateral_movement", Alert.status == "open", Alert.fingerprint == fp).first()
        if existing:
            existing.occurrence_count += 1
            existing.last_seen_at = datetime.utcnow()
        else:
            db.add(Alert(agent_id=agent_id, title=f"Lateral Movement: {data.movement_type.replace('_', ' ').title()}", description=data.description, severity=data.risk.lower(), type="lateral_movement", fingerprint=fp, mitre_tactic_id=MITRE_ATTACK_MAP["lateral_movement"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["lateral_movement"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["lateral_movement"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["lateral_movement"]["technique_name"], score=85.0 if data.risk == "CRITICAL" else 68.0, details=json.dumps({"movement_type": data.movement_type, "source_ip": data.source_ip, "destination_ip": data.destination_ip, "port": data.port, "service": data.service, "connection_count": data.connection_count, "risk": data.risk, "description": data.description})))
    db.commit()
    return {"message": "Lateral movement event recorded", "agent_id": agent_id, "risk": data.risk}


# ---- Port Scan -------------------------------------------------------------

@router.get("/agents/{agent_id}/port-scan")
async def get_agent_port_scan(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_port_scan_stats(db, agent)}


@router.post("/agents/{agent_id}/port-scan/report")
async def report_agent_port_scan(agent_id: str, data: PortScanReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(PortScanEvent(agent_id=agent_id, scan_type=data.scan_type, scanner_ip=data.scanner_ip, target_ip=data.target_ip, unique_ports=data.unique_ports, sensitive_ports_hit=data.sensitive_ports_hit, syn_count=data.syn_count, risk=data.risk, description=data.description))
    ML_ENABLED, behavioral_baseliner = _get_ml()
    risk = data.risk
    if ML_ENABLED and behavioral_baseliner:
        behavioral_baseliner.update(agent_id, {"net_connections": data.unique_ports})
        is_anomaly, _ = behavioral_baseliner.is_anomalous(agent_id, {"net_connections": data.unique_ports})
        if is_anomaly and risk != "HIGH":
            risk = "HIGH"
    if risk == "HIGH":
        fp = f"port_scan:{data.scanner_ip}:{data.target_ip}"
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "port_scan", Alert.status == "open", Alert.fingerprint == fp).first()
        if existing:
            existing.occurrence_count += 1
            existing.last_seen_at = datetime.utcnow()
        else:
            db.add(Alert(agent_id=agent_id, title=f"Port Scan: {data.scan_type.replace('_', ' ').title()}", description=data.description, severity="high", type="port_scan", fingerprint=fp, mitre_tactic_id=MITRE_ATTACK_MAP["port_scan"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["port_scan"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["port_scan"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["port_scan"]["technique_name"], score=65.0, details=json.dumps({"scan_type": data.scan_type, "scanner_ip": data.scanner_ip, "target_ip": data.target_ip, "unique_ports": data.unique_ports, "sensitive_ports_hit": data.sensitive_ports_hit, "syn_count": data.syn_count, "risk": data.risk, "description": data.description})))
    db.commit()
    return {"message": "Port scan event recorded", "agent_id": agent_id, "risk": data.risk}


# ---- Host Firewall ---------------------------------------------------------

@router.get("/agents/{agent_id}/host-firewall")
async def get_agent_host_firewall(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_host_firewall_stats(db, agent)}


@router.post("/agents/{agent_id}/host-firewall/report")
async def report_agent_host_firewall(agent_id: str, data: HostFirewallReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(HostFirewallEvent(agent_id=agent_id, chain=data.chain, rule=data.rule, ip_blocked=data.ip_blocked, action=data.action))
    if data.ip_blocked:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "firewall_block", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Firewall Block: {data.ip_blocked}", description=f"IP {data.ip_blocked} blocked on {data.chain}", severity="medium", type="firewall_block", mitre_tactic_id=MITRE_ATTACK_MAP["host_firewall"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["host_firewall"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["host_firewall"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["host_firewall"]["technique_name"], score=50.0, details=json.dumps({"chain": data.chain, "rule": data.rule, "ip_blocked": data.ip_blocked, "action": data.action})))
    db.commit()
    return {"message": "Host firewall event recorded", "agent_id": agent_id, "action": data.action}


# ---- Web / DNS Filter ------------------------------------------------------

@router.get("/agents/{agent_id}/web-dns-filter")
async def get_agent_web_dns_filter(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_web_dns_filter_stats(db, agent)}


@router.post("/agents/{agent_id}/web-dns-filter/report")
async def report_agent_web_dns_filter(agent_id: str, data: WebDNSFilterReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(WebDNSFilterEvent(agent_id=agent_id, domain=data.domain, url=data.url, action=data.action, matched_pattern=data.matched_pattern))
    if data.action == "BLOCK":
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "dns_block", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"DNS/Web Blocked: {data.domain or data.url}", description=f"Blocked by pattern: {data.matched_pattern}", severity="medium", type="dns_block", mitre_tactic_id=MITRE_ATTACK_MAP["web_dns_filter"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["web_dns_filter"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["web_dns_filter"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["web_dns_filter"]["technique_name"], score=55.0, details=json.dumps({"domain": data.domain, "url": data.url, "action": data.action, "matched_pattern": data.matched_pattern})))
    db.commit()
    return {"message": "Web/DNS filter event recorded", "agent_id": agent_id, "action": data.action}


# ---- Script Monitor --------------------------------------------------------

@router.get("/agents/{agent_id}/script-monitor")
async def get_agent_script_monitor(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_script_monitor_stats(db, agent)}


@router.post("/agents/{agent_id}/script-monitor/report")
async def report_agent_script_monitor(agent_id: str, data: ScriptMonitorReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(ScriptMonitorEvent(agent_id=agent_id, command=data.command, user=data.user, suspicious_patterns=json.dumps(data.suspicious_patterns), action=data.action))
    if data.action == "BLOCK":
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "script_block", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Script Blocked for {data.user}", description=f"Suspicious command blocked: {data.command[:80]}", severity="high", type="script_block", mitre_tactic_id=MITRE_ATTACK_MAP["script_monitor"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["script_monitor"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["script_monitor"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["script_monitor"]["technique_name"], score=72.0, details=json.dumps({"command": data.command, "user": data.user, "suspicious_patterns": data.suspicious_patterns, "action": data.action})))
    elif data.action == "ALERT":
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "script_alert", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Suspicious Command: {data.user}", description=f"Patterns: {', '.join(data.suspicious_patterns)}", severity="medium", type="script_alert", mitre_tactic_id=MITRE_ATTACK_MAP["script_monitor"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["script_monitor"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["script_monitor"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["script_monitor"]["technique_name"], score=50.0, details=json.dumps({"command": data.command, "user": data.user, "suspicious_patterns": data.suspicious_patterns, "action": data.action})))
    db.commit()
    return {"message": "Script monitor event recorded", "agent_id": agent_id, "action": data.action}


# ---- Ransomware Canary -----------------------------------------------------

@router.get("/agents/{agent_id}/ransomware-canary")
async def get_agent_ransomware_canary(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_ransomware_canary_stats(db, agent)}


@router.post("/agents/{agent_id}/ransomware-canary/report")
async def report_agent_ransomware_canary(agent_id: str, data: RansomwareCanaryReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(RansomwareCanaryEvent(agent_id=agent_id, file_path=data.file_path, reason=data.reason, file_hash=data.file_hash, directory=data.directory))
    if data.reason:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "canary_tamper", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Ransomware Canary Triggered: {data.reason}", description=f"Canary file {data.file_path} {data.reason.lower()}", severity="critical", type="canary_tamper", mitre_tactic_id=MITRE_ATTACK_MAP["ransomware_canary"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["ransomware_canary"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["ransomware_canary"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["ransomware_canary"]["technique_name"], score=95.0, details=json.dumps({"file_path": data.file_path, "reason": data.reason, "file_hash": data.file_hash, "directory": data.directory})))
    db.commit()
    return {"message": "Ransomware canary event recorded", "agent_id": agent_id, "reason": data.reason}


# ---- Credential Dumping ----------------------------------------------------

@router.get("/agents/{agent_id}/credential-dumping")
async def get_agent_credential_dumping(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_credential_dumping_stats(db, agent)}


@router.post("/agents/{agent_id}/credential-dumping/report")
async def report_agent_credential_dumping(agent_id: str, data: CredentialDumpingReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(CredentialDumpingEvent(agent_id=agent_id, process_name=data.process_name, pid=data.pid, detection_type=data.detection_type))
    existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "credential_dumping", Alert.status == "open").first()
    if not existing:
        db.add(Alert(agent_id=agent_id, title=f"Credential Dumping: {data.process_name}", description=f"Suspicious process {data.process_name} (PID: {data.pid}) - {data.detection_type}", severity="critical", type="credential_dumping", mitre_tactic_id=MITRE_ATTACK_MAP["credential_dumping"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["credential_dumping"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["credential_dumping"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["credential_dumping"]["technique_name"], score=92.0, details=json.dumps({"process_name": data.process_name, "pid": data.pid, "detection_type": data.detection_type})))
    db.commit()
    return {"message": "Credential dumping event recorded", "agent_id": agent_id, "process_name": data.process_name}


# ---- Next-Gen AV -----------------------------------------------------------

@router.get("/agents/{agent_id}/next-gen-av")
async def get_agent_next_gen_av(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_next_gen_av_stats(db, agent)}


@router.post("/agents/{agent_id}/next-gen-av/report")
async def report_agent_next_gen_av(agent_id: str, data: NextGenAVReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(NextGenAVEvent(agent_id=agent_id, file_path=data.file_path, file_hash=data.file_hash, detection_reason=data.detection_reason, action=data.action, scanner_type=data.scanner_type))
    if data.file_hash:
        _auto_scan_and_alert(agent_id, db, hashes=[data.file_hash])
    if data.action in ("malicious", "quarantined"):
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "next_gen_av", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"Next-Gen AV: {data.detection_reason[:60]}", description=f"File {data.file_path} detected as malicious by {data.scanner_type} scanner", severity="critical" if data.action == "quarantined" else "high", type="next_gen_av", mitre_tactic_id=MITRE_ATTACK_MAP["next_gen_av"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["next_gen_av"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["next_gen_av"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["next_gen_av"]["technique_name"], score=88.0 if data.action == "quarantined" else 72.0, details=json.dumps({"file_path": data.file_path, "file_hash": data.file_hash, "detection_reason": data.detection_reason, "action": data.action, "scanner_type": data.scanner_type})))
    db.commit()
    return {"message": "Next-Gen AV event recorded", "agent_id": agent_id, "action": data.action}


# ---- User Behaviour --------------------------------------------------------

@router.get("/agents/{agent_id}/user-behaviour")
async def get_agent_user_behaviour(agent_id: str, agent: Agent = Depends(get_owned_agent), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return {"agent_id": agent_id, "hostname": agent.hostname, **generate_user_behaviour_stats(db, agent)}


@router.post("/agents/{agent_id}/user-behaviour/report")
async def report_agent_user_behaviour(agent_id: str, data: UserBehaviourReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    db.add(UserBehaviourEvent(agent_id=agent_id, file_path=data.file_path, action=data.action, baseline_hash=data.baseline_hash, current_hash=data.current_hash))
    if data.action in ("modified", "deleted"):
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "file_tamper", Alert.status == "open").first()
        if not existing:
            db.add(Alert(agent_id=agent_id, title=f"File Tamper: {data.file_path} {data.action}", description=f"Protected file {data.file_path} was {data.action}", severity="high", type="file_tamper", mitre_tactic_id=MITRE_ATTACK_MAP["user_behaviour"]["tactic_id"], mitre_tactic_name=get_mitre_tactic_name(MITRE_ATTACK_MAP["user_behaviour"]["tactic_id"]), mitre_technique_id=MITRE_ATTACK_MAP["user_behaviour"]["technique_id"], mitre_technique_name=MITRE_ATTACK_MAP["user_behaviour"]["technique_name"], score=70.0, details=json.dumps({"file_path": data.file_path, "action": data.action, "baseline_hash": data.baseline_hash, "current_hash": data.current_hash})))
    db.commit()
    return {"message": "User behaviour event recorded", "agent_id": agent_id, "action": data.action}


# ---- Raw Telemetry (Processes and Connections) ------------------------------

@router.post("/agents/{agent_id}/processes/report")
async def report_agent_processes(agent_id: str, data: ProcessesReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    
    # Clear existing processes for this agent to keep database fresh
    db.query(Process).filter(Process.agent_id == agent_id).delete()
    
    for p in data.processes:
        db.add(Process(
            agent_id=agent_id,
            pid=p.pid,
            name=p.name,
            path=p.path,
            parent_pid=p.ppid,
            cmdline=p.cmdline,
            user=p.user,
            cpu_percent=p.cpu_percent,
            memory_mb=p.memory_mb,
            is_suspicious=p.is_suspicious,
            hash=p.hash
        ))
    db.commit()
    return {"message": "Processes recorded", "count": len(data.processes)}


@router.post("/agents/{agent_id}/network/report")
async def report_agent_network(agent_id: str, data: NetworkConnectionsReport, agent: Agent = Depends(verify_agent_self), db: DBSession = Depends(get_db)):
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    
    # Clear existing connections for this agent to keep database fresh
    db.query(NetworkConnection).filter(NetworkConnection.agent_id == agent_id).delete()
    
    for c in data.connections:
        db.add(NetworkConnection(
            agent_id=agent_id,
            local_ip=c.local_ip,
            local_port=c.local_port,
            remote_ip=c.remote_ip,
            remote_port=c.remote_port,
            protocol=c.protocol,
            state=c.state,
            pid=c.pid,
            process_name=c.process_name,
            is_suspicious=c.is_suspicious,
            threat_intel_match=c.threat_intel_match
        ))
    db.commit()
    return {"message": "Network connections recorded", "count": len(data.connections)}

