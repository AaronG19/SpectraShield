"""Data-generation helper functions and threat-enrichment utilities."""
import json
import random
import re
import socket

from sqlalchemy import func
from sqlalchemy.orm import Session as DBSession

from constants.mitre import MITRE_MAPPINGS, ACTIONS_BY_TYPE, SPAMHAUS_CODES
from models.agent import Agent
from models.alert import Alert
from models.events import (
    Application, FileChange, BehavioralSnapshot, OSPatchInfo,
    ThreatIntel,
    WatchdogEvent, AgentMonitorLog, ProcessExecutionEvent, ZeroDayFinding,
    RegistryChange, FilelessDetectionEvent, MemoryScanEvent, UsbDiskEvent,
    C2BeaconingEvent, LiveThreatIntelResult, OfflineScanEvent,
    VulnerabilityFinding, ProcessTreeFinding, ShadowITFinding,
    ExploitMitigationEvent, InstallationVisibilityEvent, NetworkDPIEvent,
    PrivilegeEscalationEvent, SilentDeploymentEvent, LateralMovementEvent,
    PortScanEvent, HostFirewallEvent, WebDNSFilterEvent, ScriptMonitorEvent,
    RansomwareCanaryEvent, CredentialDumpingEvent, NextGenAVEvent,
    UserBehaviourEvent,
)


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def generate_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02X}" for _ in range(6))


def generate_memory_scan_findings() -> list:
    return [
        {"process": "svchost.exe", "pid": 1104, "region": "0x7ffa00000000", "size_kb": 4096,
         "protection": "RWX", "suspicious": True, "reason": "Executable memory in non-PE process"},
        {"process": "chrome.exe", "pid": 1560, "region": "0x7ffb00000000", "size_kb": 2048,
         "protection": "RW", "suspicious": False, "reason": ""},
    ]


# ---------------------------------------------------------------------------
# Agent-level stat generators
# ---------------------------------------------------------------------------

def generate_misconfig_findings(db: DBSession, agent: Agent) -> list:
    findings = []
    if agent.os_type == "Windows" and not agent.bitlocker_enabled:
        findings.append({"type": "missing_encryption", "severity": "high", "detail": "BitLocker not enabled on system drive"})
    if not agent.firewall_enabled:
        findings.append({"type": "firewall_disabled", "severity": "high", "detail": "OS firewall is disabled"})
    if agent.os_type == "Windows":
        findings.append({"type": "rdp_exposed", "severity": "medium", "detail": "RDP port 3389 is accessible from network"})
        findings.append({"type": "guest_account_active", "severity": "high", "detail": "Built-in Guest account may be enabled"})
        findings.append({"type": "weak_password_policy", "severity": "medium", "detail": "Password policy may not meet minimum complexity requirements"})
    if agent.os_type == "Linux":
        findings.append({"type": "ssh_password_auth", "severity": "medium", "detail": "SSH password authentication may be enabled"})
        findings.append({"type": "firewall_inactive", "severity": "high", "detail": "UFW/iptables firewall may be inactive"})
    return findings


def generate_vulnerability_findings(db: DBSession, agent: Agent) -> list:
    findings = []
    cve_db = {
        "Google Chrome": [{"id": "CVE-2023-7024", "severity": "critical", "description": "Heap buffer overflow in WebRTC"}],
        "Mozilla Firefox": [{"id": "CVE-2023-6856", "severity": "high", "description": "Use-after-free in WebAudio"}],
        "Microsoft Office 365": [{"id": "CVE-2023-38545", "severity": "critical", "description": "Remote code execution via Office"}],
        "OpenSSH Server": [{"id": "CVE-2023-51385", "severity": "high", "description": "SSH prefix truncation attack"}],
        "Apache HTTP Server": [{"id": "CVE-2023-45802", "severity": "high", "description": "HTTP request smuggling"}],
        "PHP": [{"id": "CVE-2023-3824", "severity": "critical", "description": "Remote code execution in PHP"}],
    }
    apps = db.query(Application).filter(Application.agent_id == agent.id).all()
    for app in apps:
        if app.name in cve_db:
            for cve in cve_db[app.name]:
                findings.append({"app_name": app.name, "app_version": app.version, "cve_id": cve["id"],
                                  "severity": cve["severity"], "description": cve["description"], "status": "unpatched"})
    return findings


def generate_file_integrity_findings(db: DBSession, agent: Agent) -> dict:
    target_files = []
    if agent.os_type == "Windows":
        target_files = [r"C:\Windows\System32\drivers\etc\hosts",
                        r"C:\Windows\System32\config\SAM",
                        r"C:\Windows\System32\config\SYSTEM"]
    elif agent.os_type == "Linux":
        target_files = ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/hosts"]
    changes = db.query(FileChange).filter(FileChange.agent_id == agent.id).order_by(FileChange.detected_at.desc()).limit(20).all()
    changed_files = [c.file_path for c in changes if c.change_type == "modified"]
    
    integrity = []
    seen_files = set()
    for tf in target_files:
        status = "Modified" if tf in changed_files else "Intact"
        integrity.append({"file_path": tf, "status": status})
        seen_files.add(tf)
    for cf in changed_files:
        if cf not in seen_files:
            integrity.append({"file_path": cf, "status": "Modified"})
            seen_files.add(cf)

    return {
        "monitored_files": target_files,
        "changes_detected": len(changed_files) > 0,
        "changed_files": changed_files,
        "recent_changes": [{"file_path": c.file_path, "change_type": c.change_type, "detected_at": c.detected_at.isoformat()} for c in changes[:5]],
        "integrity": integrity,
    }


def generate_behavioral_findings(db: DBSession, agent: Agent) -> dict:
    snapshots = db.query(BehavioralSnapshot).filter(BehavioralSnapshot.agent_id == agent.id).order_by(BehavioralSnapshot.detected_at.desc()).limit(10).all()
    recent = snapshots[:1]
    if recent:
        s = recent[0]
        return {"cpu_usage": s.cpu_usage, "ram_usage": s.ram_usage, "process_count": s.process_count,
                "net_connections": s.net_connections, "is_anomaly": s.is_anomaly, "anomaly_score": s.anomaly_score,
                "ml_active": s.ml_active, "history_size": s.history_size, "snapshot_count": len(snapshots)}
    return {"cpu_usage": 0, "ram_usage": 0, "process_count": 0, "net_connections": 0,
            "is_anomaly": False, "anomaly_score": 0.0, "ml_active": False, "history_size": 0, "snapshot_count": 0}


def generate_patch_findings(db: DBSession, agent: Agent) -> dict:
    patches = db.query(OSPatchInfo).filter(OSPatchInfo.agent_id == agent.id).order_by(OSPatchInfo.checked_at.desc()).first()
    if patches:
        return {"missing_patches": json.loads(patches.missing_patches) if isinstance(patches.missing_patches, str) else [],
                "count": patches.count, "oldest_missing_days": patches.oldest_missing_days,
                "severity": patches.severity, "last_checked": patches.checked_at.isoformat()}
    if agent.os_type == "Windows":
        return {"missing_patches": ["KB5034441", "KB5034122"], "count": 2, "oldest_missing_days": 45, "severity": "high", "last_checked": None}
    elif agent.os_type == "Linux":
        return {"missing_patches": ["linux-image-generic", "libssl1.1"], "count": 2, "oldest_missing_days": 12, "severity": "low", "last_checked": None}
    return {"missing_patches": [], "count": 0, "oldest_missing_days": 0, "severity": "info", "last_checked": None}


def generate_software_inventory(db: DBSession, agent: Agent) -> list:
    apps = db.query(Application).filter(Application.agent_id == agent.id).order_by(Application.name).all()
    return [{"name": a.name, "version": a.version, "vendor": a.vendor,
             "install_date": a.install_date.isoformat() if a.install_date else "",
             "is_approved": a.is_approved, "is_running": a.is_running,
             "risk_score": a.risk_score, "cve_list": json.loads(a.cve_list) if isinstance(a.cve_list, str) else []} for a in apps]


def generate_asset_discovery(agent: Agent) -> dict:
    return {"hostname": agent.hostname, "os_type": agent.os_type, "os_version": agent.os_version,
            "os_patch_level": agent.os_patch_level, "architecture": agent.cpu_model, "processor": agent.cpu_model,
            "cpu_cores": agent.cpu_cores, "logical_cpus": agent.cpu_cores * 2 if agent.cpu_cores else 0,
            "ram_gb": agent.ram_total_gb, "mac_address": agent.mac_address, "ip_address": agent.ip_address,
            "status": agent.status, "cpu_usage": agent.cpu_usage, "ram_used_gb": agent.ram_used_gb,
            "disk_total_gb": agent.disk_total_gb, "disk_used_gb": agent.disk_used_gb}


def generate_watchdog_status(db: DBSession, agent: Agent) -> dict:
    last_event = db.query(WatchdogEvent).filter(WatchdogEvent.agent_id == agent.id).order_by(WatchdogEvent.detected_at.desc()).first()
    total_restarts = db.query(func.sum(WatchdogEvent.restart_count)).filter(WatchdogEvent.agent_id == agent.id).scalar() or 0
    tamper_count = db.query(func.count(WatchdogEvent.id)).filter(WatchdogEvent.agent_id == agent.id, WatchdogEvent.tamper_detected == True).scalar() or 0
    if last_event:
        return {"agent_running": last_event.agent_running, "tamper_detected": last_event.tamper_detected,
                "restart_count": total_restarts, "tamper_events": tamper_count, "last_log": last_event.log_entry,
                "last_checked": last_event.detected_at.isoformat(), "self_defense": agent.self_defense_status, "tamper_protection": agent.tamper_protection}
    return {"agent_running": agent.status == "online", "tamper_detected": False, "restart_count": 0,
            "tamper_events": 0, "last_log": "", "last_checked": None,
            "self_defense": agent.self_defense_status, "tamper_protection": agent.tamper_protection}


def generate_monitoring_stats(db: DBSession, agent: Agent) -> dict:
    logs = db.query(AgentMonitorLog).filter(AgentMonitorLog.agent_id == agent.id).order_by(AgentMonitorLog.recorded_at.desc()).limit(20).all()
    avg_cpu = db.query(func.avg(AgentMonitorLog.cpu_percent)).filter(AgentMonitorLog.agent_id == agent.id).scalar() or 0
    avg_ram = db.query(func.avg(AgentMonitorLog.ram_percent)).filter(AgentMonitorLog.agent_id == agent.id).scalar() or 0
    return {"current_cpu": agent.cpu_usage, "current_ram_gb": agent.ram_used_gb,
            "avg_cpu_percent": round(float(avg_cpu), 1), "avg_ram_percent": round(float(avg_ram), 1),
            "log_count": len(logs),
            "recent_logs": [{"cpu_percent": l.cpu_percent, "ram_percent": l.ram_percent, "recorded_at": l.recorded_at.isoformat()} for l in logs[:5]]}


def generate_execution_prevention_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(ProcessExecutionEvent).filter(ProcessExecutionEvent.agent_id == agent.id).order_by(ProcessExecutionEvent.detected_at.desc()).limit(20).all()
    blocked_count = db.query(func.count(ProcessExecutionEvent.id)).filter(ProcessExecutionEvent.agent_id == agent.id, ProcessExecutionEvent.blocked == True).scalar() or 0
    total = db.query(func.count(ProcessExecutionEvent.id)).filter(ProcessExecutionEvent.agent_id == agent.id).scalar() or 0
    return {"total_events": total, "blocked_count": blocked_count, "clean_count": total - blocked_count,
            "recent_events": [{"process_name": e.process_name, "process_path": e.process_path, "blocked": e.blocked, "reason": e.reason, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_zero_day_stats(db: DBSession, agent: Agent) -> dict:
    findings = db.query(ZeroDayFinding).filter(ZeroDayFinding.agent_id == agent.id).order_by(ZeroDayFinding.detected_at.desc()).limit(20).all()
    total = db.query(func.count(ZeroDayFinding.id)).filter(ZeroDayFinding.agent_id == agent.id).scalar() or 0
    return {"total_findings": total,
            "recent_findings": [{"file_name": f.file_name, "file_path": f.file_path, "unknown_hash": f.unknown_hash, "risky_location": f.risky_location, "detected_at": f.detected_at.isoformat()} for f in findings[:10]]}


def generate_registry_monitoring_stats(db: DBSession, agent: Agent) -> dict:
    changes = db.query(RegistryChange).filter(RegistryChange.agent_id == agent.id).order_by(RegistryChange.detected_at.desc()).limit(20).all()
    total = db.query(func.count(RegistryChange.id)).filter(RegistryChange.agent_id == agent.id).scalar() or 0
    auto_start = db.query(func.count(RegistryChange.id)).filter(RegistryChange.agent_id == agent.id, RegistryChange.is_auto_start == True).scalar() or 0
    return {"total_changes": total, "auto_start_changes": auto_start,
            "recent_changes": [{"key_path": c.key_path, "value_name": c.value_name, "change_type": c.change_type, "is_auto_start": c.is_auto_start, "detected_at": c.detected_at.isoformat()} for c in changes[:10]]}


def generate_fileless_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(FilelessDetectionEvent).filter(FilelessDetectionEvent.agent_id == agent.id).order_by(FilelessDetectionEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(FilelessDetectionEvent.id)).filter(FilelessDetectionEvent.agent_id == agent.id).scalar() or 0
    return {"total_events": total, "scan_ok": total == 0,
            "recent_events": [{"pid": e.pid, "process_name": e.process_name, "reason": e.reason, "eventlog_alert": e.eventlog_alert, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_memory_scan_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(MemoryScanEvent).filter(MemoryScanEvent.agent_id == agent.id).order_by(MemoryScanEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(MemoryScanEvent.id)).filter(MemoryScanEvent.agent_id == agent.id).scalar() or 0
    shellcode = db.query(func.count(MemoryScanEvent.id)).filter(MemoryScanEvent.agent_id == agent.id, MemoryScanEvent.shellcode_detected == True).scalar() or 0
    return {"total_events": total, "scan_ok": total == 0, "shellcode_detected_count": shellcode,
            "recent_events": [{"pid": e.pid, "process_name": e.process_name, "reason": e.reason, "shellcode_detected": e.shellcode_detected, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_usb_disk_stats(db: DBSession, agent: Agent) -> dict:
    last = db.query(UsbDiskEvent).filter(UsbDiskEvent.agent_id == agent.id).order_by(UsbDiskEvent.detected_at.desc()).first()
    total = db.query(func.count(UsbDiskEvent.id)).filter(UsbDiskEvent.agent_id == agent.id).scalar() or 0
    if last:
        return {"usb_devices": json.loads(last.usb_devices) if isinstance(last.usb_devices, str) else [],
                "blocked_devices": json.loads(last.blocked_devices) if isinstance(last.blocked_devices, str) else [],
                "usb_control_ok": last.usb_control_ok, "encrypted": last.encrypted, "protection_on": last.protection_on,
                "last_checked": last.detected_at.isoformat(), "total_scans": total}
    return {"usb_devices": [], "blocked_devices": [], "usb_control_ok": True,
            "encrypted": agent.bitlocker_enabled if agent.os_type == "Windows" else False,
            "protection_on": agent.bitlocker_enabled, "last_checked": None, "total_scans": 0}


def generate_c2_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(C2BeaconingEvent).filter(C2BeaconingEvent.agent_id == agent.id).order_by(C2BeaconingEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(C2BeaconingEvent.id)).filter(C2BeaconingEvent.agent_id == agent.id).scalar() or 0
    return {"total_beacons": total, "beaconing_detected": total > 0,
            "recent_events": [{"src_ip": e.src_ip, "dst_ip": e.dst_ip, "connections": e.connections, "avg_interval": e.avg_interval, "variance": e.variance, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_threat_intel_stats(db: DBSession, agent: Agent) -> dict:
    results = db.query(LiveThreatIntelResult).filter(LiveThreatIntelResult.agent_id == agent.id).order_by(LiveThreatIntelResult.checked_at.desc()).limit(20).all()
    total = db.query(func.count(LiveThreatIntelResult.id)).filter(LiveThreatIntelResult.agent_id == agent.id).scalar() or 0
    return {"total_queries": total,
            "recent_queries": [{"indicator_type": r.indicator_type, "indicator": r.indicator, "pulse_count": r.pulse_count, "reputation": r.reputation, "country": r.country, "checked_at": r.checked_at.isoformat()} for r in results[:10]]}


def generate_offline_scan_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(OfflineScanEvent).filter(OfflineScanEvent.agent_id == agent.id).order_by(OfflineScanEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(OfflineScanEvent.id)).filter(OfflineScanEvent.agent_id == agent.id).scalar() or 0
    return {"total_scans": total, "threats_found_total": sum(e.threats_found for e in events),
            "recent_events": [{"file_path": e.file_path, "file_hash": e.file_hash, "threat_name": e.threat_name, "scan_directory": e.scan_directory, "threats_found": e.threats_found, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_vuln_scan_stats(db: DBSession, agent: Agent) -> dict:
    findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.agent_id == agent.id).order_by(VulnerabilityFinding.detected_at.desc()).limit(50).all()
    total = db.query(func.count(VulnerabilityFinding.id)).filter(VulnerabilityFinding.agent_id == agent.id).scalar() or 0
    critical = db.query(func.count(VulnerabilityFinding.id)).filter(VulnerabilityFinding.agent_id == agent.id, VulnerabilityFinding.severity == "Critical").scalar() or 0
    high = db.query(func.count(VulnerabilityFinding.id)).filter(VulnerabilityFinding.agent_id == agent.id, VulnerabilityFinding.severity == "High").scalar() or 0
    return {"total_findings": total, "critical": critical, "high": high,
            "recent_findings": [{"finding_type": f.finding_type, "software": f.software, "cve_id": f.cve_id, "severity": f.severity, "port": f.port, "service": f.service, "description": f.description, "detected_at": f.detected_at.isoformat()} for f in findings[:10]]}


def generate_process_tree_stats(db: DBSession, agent: Agent) -> dict:
    findings = db.query(ProcessTreeFinding).filter(ProcessTreeFinding.agent_id == agent.id).order_by(ProcessTreeFinding.detected_at.desc()).limit(50).all()
    total = db.query(func.count(ProcessTreeFinding.id)).filter(ProcessTreeFinding.agent_id == agent.id).scalar() or 0
    high = db.query(func.count(ProcessTreeFinding.id)).filter(ProcessTreeFinding.agent_id == agent.id, ProcessTreeFinding.risk == "HIGH").scalar() or 0
    critical = db.query(func.count(ProcessTreeFinding.id)).filter(ProcessTreeFinding.agent_id == agent.id, ProcessTreeFinding.risk == "CRITICAL").scalar() or 0
    return {"total_findings": total, "high": high, "critical": critical,
            "recent_findings": [{"finding_type": f.finding_type, "parent_name": f.parent_name, "child_name": f.child_name, "risk": f.risk, "description": f.description, "detected_at": f.detected_at.isoformat()} for f in findings[:10]]}


def generate_shadow_it_stats(db: DBSession, agent: Agent) -> dict:
    findings = db.query(ShadowITFinding).filter(ShadowITFinding.agent_id == agent.id).order_by(ShadowITFinding.detected_at.desc()).limit(50).all()
    total = db.query(func.count(ShadowITFinding.id)).filter(ShadowITFinding.agent_id == agent.id).scalar() or 0
    return {"total_findings": total,
            "recent_findings": [{"finding_type": f.finding_type, "service_name": f.service_name, "domain": f.domain, "category": f.category, "risk": f.risk, "description": f.description, "detected_at": f.detected_at.isoformat()} for f in findings[:10]]}


def generate_exploit_mitigation_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(ExploitMitigationEvent).filter(ExploitMitigationEvent.agent_id == agent.id).order_by(ExploitMitigationEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(ExploitMitigationEvent.id)).filter(ExploitMitigationEvent.agent_id == agent.id).scalar() or 0
    last = events[0] if events else None
    if last:
        return {"total_scans": total, "aslr_enabled": last.aslr_enabled, "aslr_level": last.aslr_level,
                "dep_enabled": last.dep_enabled, "dep_policy": last.dep_policy, "acg_enabled": last.acg_enabled,
                "os": last.os, "risk_summary": last.risk_summary, "severity": last.severity, "last_checked": last.detected_at.isoformat()}
    return {"total_scans": 0, "aslr_enabled": False, "aslr_level": "unknown", "dep_enabled": False,
            "dep_policy": "unknown", "acg_enabled": False, "os": agent.os_type, "risk_summary": "No data", "severity": "info", "last_checked": None}


def generate_installation_visibility_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(InstallationVisibilityEvent).filter(InstallationVisibilityEvent.agent_id == agent.id).order_by(InstallationVisibilityEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(InstallationVisibilityEvent.id)).filter(InstallationVisibilityEvent.agent_id == agent.id).scalar() or 0
    last = events[0] if events else None
    if last:
        return {"total_events": total, "boot_time": last.boot_time, "install_path": last.install_path,
                "username": last.running_as_username, "is_admin": last.running_as_admin,
                "os_name": last.os_name, "os_release": last.os_release, "hostname": last.hostname,
                "agent_version": last.agent_version, "last_reported": last.detected_at.isoformat()}
    return {"total_events": 0, "boot_time": "", "install_path": "", "username": "", "is_admin": False,
            "os_name": agent.os_type, "os_release": "", "hostname": agent.hostname, "agent_version": "", "last_reported": None}


def generate_network_dpi_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(NetworkDPIEvent).filter(NetworkDPIEvent.agent_id == agent.id).order_by(NetworkDPIEvent.detected_at.desc()).limit(50).all()
    total = db.query(func.count(NetworkDPIEvent.id)).filter(NetworkDPIEvent.agent_id == agent.id).scalar() or 0
    threat_counts: dict = {}
    for e in events:
        threat_counts[e.threat_type] = threat_counts.get(e.threat_type, 0) + 1
    return {"total_events": total, "threat_breakdown": threat_counts,
            "recent_events": [{"src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port, "protocol": e.protocol, "threat_type": e.threat_type, "reason": e.reason, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_privilege_escalation_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(PrivilegeEscalationEvent).filter(PrivilegeEscalationEvent.agent_id == agent.id).order_by(PrivilegeEscalationEvent.detected_at.desc()).limit(50).all()
    total = db.query(func.count(PrivilegeEscalationEvent.id)).filter(PrivilegeEscalationEvent.agent_id == agent.id).scalar() or 0
    critical = db.query(func.count(PrivilegeEscalationEvent.id)).filter(PrivilegeEscalationEvent.agent_id == agent.id, PrivilegeEscalationEvent.severity == "critical").scalar() or 0
    high = db.query(func.count(PrivilegeEscalationEvent.id)).filter(PrivilegeEscalationEvent.agent_id == agent.id, PrivilegeEscalationEvent.severity == "high").scalar() or 0
    return {"total_events": total, "critical": critical, "high": high,
            "recent_events": [{"check_type": e.check_type, "finding": e.finding, "process_name": e.process_name, "user": e.user, "privilege": e.privilege, "severity": e.severity, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_silent_deployment_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(SilentDeploymentEvent).filter(SilentDeploymentEvent.agent_id == agent.id).order_by(SilentDeploymentEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(SilentDeploymentEvent.id)).filter(SilentDeploymentEvent.agent_id == agent.id).scalar() or 0
    last = events[0] if events else None
    if last:
        return {"total_scans": total, "no_window": last.no_window, "hidden": last.hidden,
                "startup_type": last.startup_type, "process_name": last.process_name,
                "parent_process": last.parent_process, "is_silent": last.is_silent, "last_checked": last.detected_at.isoformat()}
    return {"total_scans": 0, "no_window": False, "hidden": False, "startup_type": "user", "process_name": "", "parent_process": "", "is_silent": False, "last_checked": None}


def generate_lateral_movement_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(LateralMovementEvent).filter(LateralMovementEvent.agent_id == agent.id).order_by(LateralMovementEvent.detected_at.desc()).limit(50).all()
    total = db.query(func.count(LateralMovementEvent.id)).filter(LateralMovementEvent.agent_id == agent.id).scalar() or 0
    high = db.query(func.count(LateralMovementEvent.id)).filter(LateralMovementEvent.agent_id == agent.id, LateralMovementEvent.risk == "HIGH").scalar() or 0
    critical = db.query(func.count(LateralMovementEvent.id)).filter(LateralMovementEvent.agent_id == agent.id, LateralMovementEvent.risk == "CRITICAL").scalar() or 0
    return {"total_events": total, "high": high, "critical": critical,
            "recent_events": [{"movement_type": e.movement_type, "source_ip": e.source_ip, "destination_ip": e.destination_ip, "port": e.port, "service": e.service, "connection_count": e.connection_count, "risk": e.risk, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_port_scan_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(PortScanEvent).filter(PortScanEvent.agent_id == agent.id).order_by(PortScanEvent.detected_at.desc()).limit(50).all()
    total = db.query(func.count(PortScanEvent.id)).filter(PortScanEvent.agent_id == agent.id).scalar() or 0
    high = db.query(func.count(PortScanEvent.id)).filter(PortScanEvent.agent_id == agent.id, PortScanEvent.risk == "HIGH").scalar() or 0
    return {"total_events": total, "high_risk": high,
            "recent_events": [{"scan_type": e.scan_type, "scanner_ip": e.scanner_ip, "target_ip": e.target_ip, "unique_ports": e.unique_ports, "sensitive_ports_hit": e.sensitive_ports_hit, "risk": e.risk, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_host_firewall_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(HostFirewallEvent).filter(HostFirewallEvent.agent_id == agent.id).order_by(HostFirewallEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(HostFirewallEvent.id)).filter(HostFirewallEvent.agent_id == agent.id).scalar() or 0
    blocks = db.query(func.count(HostFirewallEvent.id)).filter(HostFirewallEvent.agent_id == agent.id, HostFirewallEvent.action == "BLOCK").scalar() or 0
    return {"total_events": total, "blocks": blocks,
            "recent_events": [{"chain": e.chain, "rule": e.rule, "ip_blocked": e.ip_blocked, "action": e.action, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_web_dns_filter_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(WebDNSFilterEvent).filter(WebDNSFilterEvent.agent_id == agent.id).order_by(WebDNSFilterEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(WebDNSFilterEvent.id)).filter(WebDNSFilterEvent.agent_id == agent.id).scalar() or 0
    blocked = db.query(func.count(WebDNSFilterEvent.id)).filter(WebDNSFilterEvent.agent_id == agent.id, WebDNSFilterEvent.action == "BLOCK").scalar() or 0
    return {"total_events": total, "blocked": blocked,
            "recent_events": [{"domain": e.domain, "url": e.url, "action": e.action, "matched_pattern": e.matched_pattern, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_script_monitor_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(ScriptMonitorEvent).filter(ScriptMonitorEvent.agent_id == agent.id).order_by(ScriptMonitorEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(ScriptMonitorEvent.id)).filter(ScriptMonitorEvent.agent_id == agent.id).scalar() or 0
    blocked = db.query(func.count(ScriptMonitorEvent.id)).filter(ScriptMonitorEvent.agent_id == agent.id, ScriptMonitorEvent.action == "BLOCK").scalar() or 0
    alerted = db.query(func.count(ScriptMonitorEvent.id)).filter(ScriptMonitorEvent.agent_id == agent.id, ScriptMonitorEvent.action == "ALERT").scalar() or 0
    return {"total_events": total, "blocked": blocked, "alerted": alerted,
            "recent_events": [{"command": e.command[:80], "user": e.user, "suspicious_patterns": e.suspicious_patterns, "action": e.action, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_ransomware_canary_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(RansomwareCanaryEvent).filter(RansomwareCanaryEvent.agent_id == agent.id).order_by(RansomwareCanaryEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(RansomwareCanaryEvent.id)).filter(RansomwareCanaryEvent.agent_id == agent.id).scalar() or 0
    tampered = db.query(func.count(RansomwareCanaryEvent.id)).filter(RansomwareCanaryEvent.agent_id == agent.id, RansomwareCanaryEvent.reason != "").scalar() or 0
    return {"total_events": total, "tampered": tampered,
            "recent_events": [{"file_path": e.file_path, "reason": e.reason, "directory": e.directory, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_credential_dumping_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(CredentialDumpingEvent).filter(CredentialDumpingEvent.agent_id == agent.id).order_by(CredentialDumpingEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(CredentialDumpingEvent.id)).filter(CredentialDumpingEvent.agent_id == agent.id).scalar() or 0
    return {"total_events": total,
            "recent_events": [{"process_name": e.process_name, "pid": e.pid, "detection_type": e.detection_type, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_next_gen_av_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(NextGenAVEvent).filter(NextGenAVEvent.agent_id == agent.id).order_by(NextGenAVEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(NextGenAVEvent.id)).filter(NextGenAVEvent.agent_id == agent.id).scalar() or 0
    malicious = db.query(func.count(NextGenAVEvent.id)).filter(NextGenAVEvent.agent_id == agent.id, NextGenAVEvent.action == "malicious").scalar() or 0
    quarantined = db.query(func.count(NextGenAVEvent.id)).filter(NextGenAVEvent.agent_id == agent.id, NextGenAVEvent.action == "quarantined").scalar() or 0
    return {"total_events": total, "malicious": malicious, "quarantined": quarantined,
            "recent_events": [{"file_path": e.file_path, "file_hash": e.file_hash, "detection_reason": e.detection_reason, "action": e.action, "scanner_type": e.scanner_type, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


def generate_user_behaviour_stats(db: DBSession, agent: Agent) -> dict:
    events = db.query(UserBehaviourEvent).filter(UserBehaviourEvent.agent_id == agent.id).order_by(UserBehaviourEvent.detected_at.desc()).limit(20).all()
    total = db.query(func.count(UserBehaviourEvent.id)).filter(UserBehaviourEvent.agent_id == agent.id).scalar() or 0
    tamper = db.query(func.count(UserBehaviourEvent.id)).filter(UserBehaviourEvent.agent_id == agent.id, UserBehaviourEvent.action.in_(["modified", "deleted"])).scalar() or 0
    return {"total_events": total, "tamper_events": tamper,
            "recent_events": [{"file_path": e.file_path, "action": e.action, "baseline_hash": e.baseline_hash, "current_hash": e.current_hash, "detected_at": e.detected_at.isoformat()} for e in events[:10]]}


# ---------------------------------------------------------------------------
# Threat enrichment helpers
# ---------------------------------------------------------------------------

def _detect_ioc_type(val: str) -> str:
    if val.startswith("http://") or val.startswith("https://"):
        return "url"
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
        return "ip"
    if re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", val):
        return "hash"
    if "." in val:
        return "domain"
    return "unknown"


def _check_dnsbl(ip: str) -> dict:
    """Check IP against free DNS blocklists (zero config, no key needed)."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return {"checked": [], "hits": []}
    reversed_ip = ".".join(reversed(parts))
    lists = [("spamhaus", "zen.spamhaus.org"), ("tor_exit", "tor.dan.me.uk")]
    checked, hits = [], []
    for name, domain in lists:
        checked.append(name)
        try:
            result = socket.getaddrinfo(f"{reversed_ip}.{domain}", 0)
            code_ip = result[0][4][0] if result else ""
            category = SPAMHAUS_CODES.get(code_ip, "Listed (unknown reason)")
            if name == "tor_exit":
                category = "Tor exit node"
            hits.append({"list": name, "code": code_ip, "category": category})
        except socket.gaierror:
            pass
    return {"checked": checked, "hits": hits}


def _auto_scan_and_alert(agent_id: str, db: DBSession, hashes=None, ips=None, domains=None) -> list:
    """Scan IoCs against all sources and create alerts for matches. Called automatically on agent reports."""
    alerts = []
    for h in (hashes or []):
        h = h.strip().lower()
        if not h:
            continue
        ioc = db.query(ThreatIntel).filter(ThreatIntel.value == h, ThreatIntel.is_active == True).first()
        if ioc:
            alerts.append(("hash", h, "threat_intel", ioc.severity, ioc.description))
    for ip in (ips or []):
        ip = ip.strip().lower()
        if not ip:
            continue
        dnsbl = _check_dnsbl(ip)
        if dnsbl and dnsbl["hits"]:
            cats = [h.get("category", h["list"]) for h in dnsbl["hits"]]
            alerts.append(("ip", ip, "dnsbl", "medium", f"DNSBL: {', '.join(cats)}"))
        ioc = db.query(ThreatIntel).filter(ThreatIntel.value == ip, ThreatIntel.is_active == True).first()
        if ioc:
            alerts.append(("ip", ip, "threat_intel", ioc.severity, ioc.description))
    for d in (domains or []):
        d = d.strip().lower()
        if not d:
            continue
        ioc = db.query(ThreatIntel).filter(ThreatIntel.value == d, ThreatIntel.is_active == True).first()
        if ioc:
            alerts.append(("domain", d, "threat_intel", ioc.severity, ioc.description))
    created = []
    for ioc_type, val, source, sev, desc in alerts:
        existing = db.query(Alert).filter(Alert.agent_id == agent_id, Alert.type == "threat_intel",
                                          Alert.status == "open", Alert.title.like(f"%{val}%")).first()
        if existing:
            continue
        alert = Alert(agent_id=agent_id, title=f"Auto-detected {ioc_type}: {val}", description=desc,
                      severity=sev, type="threat_intel", score=85.0,
                      details=json.dumps({"value": val, "ioc_type": ioc_type, "source": source, "severity": sev}))
        db.add(alert)
        created.append(val)
    if created:
        db.commit()
    return created


def _extract_malware_family(vt: dict) -> str | None:
    if not vt:
        return None
    ptc = vt.get("popular_threat_classification", {})
    if ptc:
        suggested = ptc.get("suggested_threat_label", "")
        if suggested:
            return suggested
        families = ptc.get("popular_threat_category", [])
        if families and isinstance(families, list):
            return families[0].get("value", "") if isinstance(families[0], dict) else families[0]
    tags = vt.get("tags", [])
    family_tags = [t for t in tags if not t.startswith("capr-") and not t.startswith("pt-") and t not in ("dynamic", "peexe", "elf", "macho", "pdf")]
    return family_tags[0] if family_tags else None


def _extract_what_it_does(vt: dict, ioc_type: str) -> list:
    desc = []
    if ioc_type == "hash":
        td = vt.get("type_description", "") if vt else ""
        if td:
            desc.append(td)
        tags = vt.get("tags", []) if vt else []
        if "trojan" in tags: desc.append("Trojan malware - performs malicious actions under remote control")
        if "ransomware" in tags: desc.append("Ransomware - encrypts files and demands payment")
        if "worm" in tags: desc.append("Worm - self-replicating malware that spreads across networks")
        if "spyware" in tags: desc.append("Spyware - harvests sensitive information from the victim")
        if "downloader" in tags: desc.append("Downloader - fetches additional malicious payloads")
        if "keylogger" in tags: desc.append("Keylogger - records keystrokes to steal credentials")
        if "backdoor" in tags: desc.append("Backdoor - provides remote unauthorized access")
        if "miner" in tags: desc.append("Cryptominer - hijacks system resources for cryptocurrency mining")
        if not desc: desc.append("Suspicious executable detected by multiple antivirus engines")
    elif ioc_type == "ip":
        tags = vt.get("tags", []) if vt else []
        if "botnet" in tags: desc.append("Botnet C2 - command and control server for botnet operations")
        if "phishing" in tags: desc.append("Phishing - hosts phishing infrastructure")
        if "malware" in tags: desc.append("Malware distribution - hosts or delivers malicious payloads")
        if "c2" in tags: desc.append("C2 Beaconing - known command and control server")
        if "scanning" in tags: desc.append("Port scanning / reconnaissance activity")
        if not desc: desc.append("Suspicious network activity associated with this IP")
    elif ioc_type == "domain":
        categories = vt.get("categories", {}) if vt else {}
        for engine, cat in categories.items():
            if "malware" in cat.lower() or "phishing" in cat.lower() or "malicious" in cat.lower():
                desc.append(f"Categorized as '{cat}' by {engine}")
                break
        if not desc: desc.append("Domain associated with malicious activity")
    return desc


def _impact_on_victim(vt: dict, ioc_type: str) -> list:
    impacts = []
    if ioc_type == "hash":
        if vt and vt.get("malicious", 0) > 10: impacts.append("System compromise - full host takeover possible")
        if vt and vt.get("malicious", 0) > 5: impacts.append("Data theft - sensitive information may be exfiltrated")
        impacts.append("Performance degradation - malicious processes consume system resources")
        impacts.append("Persistence achieved - malware survives reboots")
    elif ioc_type == "ip":
        impacts.append("Data exfiltration - sensitive data sent to external server")
        impacts.append("C2 communication - attacker maintains remote access")
        impacts.append("Potential lateral movement instructions received")
    elif ioc_type == "domain":
        impacts.append("Malware payload delivery via domain")
        impacts.append("Credential harvesting if phishing domain")
        impacts.append("Command and control channel established")
    return impacts


def _compute_confidence(vt: dict, dnsbl: dict) -> int:
    score = 0
    if vt and vt.get("malicious", 0) > 0:
        ratio = vt["malicious"] / max(vt["total"], 1)
        score += min(ratio * 100, 60)
    if dnsbl and dnsbl.get("hits"):
        score += len(dnsbl["hits"]) * 10
    if vt and vt.get("reputation", 0) < -10:
        score += 15
    if vt and vt.get("reputation", 0) < -50:
        score += 15
    return min(int(score), 100)


def _compute_reputation_label(score: int) -> str:
    if score >= 90: return "critical"
    if score >= 70: return "high"
    if score >= 40: return "medium"
    return "low"


def _generate_mitre(vt: dict, ioc_type: str) -> list:
    base = MITRE_MAPPINGS.get(ioc_type, MITRE_MAPPINGS.get("ip", []))
    tags = vt.get("tags", []) if vt else []
    extra = []
    if "ransomware" in tags:
        extra.append({"tactic": "Impact", "tactic_id": "TA0040", "technique": "Data Encrypted for Impact", "technique_id": "T1486"})
    if "trojan" in tags:
        extra.append({"tactic": "Defense Evasion", "tactic_id": "TA0005", "technique": "Obfuscated Files or Information", "technique_id": "T1027"})
    if "downloader" in tags:
        extra.append({"tactic": "Command and Control", "tactic_id": "TA0011", "technique": "Ingress Tool Transfer", "technique_id": "T1105"})
    if "botnet" in tags or "c2" in tags:
        extra.append({"tactic": "Command and Control", "tactic_id": "TA0011", "technique": "Non-Application Layer Protocol", "technique_id": "T1571"})
    return base + extra


def _recommended_actions(ioc_type: str, severity: str) -> list:
    actions = list(ACTIONS_BY_TYPE.get(ioc_type, []))
    if severity in ("critical", "high"):
        actions.insert(0, "Escalate to CIRT/SOC Tier 3 for immediate investigation")
    return actions
