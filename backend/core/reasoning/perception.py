"""Perception Engine — normalizes heterogeneous telemetry payloads into a unified event.

The engine maps each of the 37+ agent report types to a ``NormalizedEvent`` with
a consistent set of ``features`` (process names, IPs, domains, hashes, flags, ...)
so downstream reasoning is agnostic to the original report format.
"""
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from core.reasoning.models import NormalizedEvent

Extractor = Callable[[Dict[str, Any]], "Extracted"]
"""Extractor signature: takes a payload dict, returns (severity, features)."""


class Extracted:
    __slots__ = ("severity", "features")

    def __init__(self, severity: str = "info", features: Optional[Dict[str, Any]] = None):
        self.severity = severity
        self.features = features or {}


def _first(payload: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for k in keys:
        if k in payload and payload[k] not in (None, ""):
            return payload[k]
    return default


def _truthy(payload: Dict[str, Any], *keys: str) -> bool:
    return any(bool(payload.get(k)) for k in keys)


def _collect(payload: Dict[str, Any], *keys: str) -> list:
    values = []
    for k in keys:
        v = payload.get(k)
        if isinstance(v, (list, tuple)):
            values.extend(str(x) for x in v if x)
        elif v not in (None, ""):
            values.append(str(v))
    return values


def _severity_of(risk: str) -> str:
    risk = (risk or "").lower()
    if risk in ("critical", "high"):
        return risk
    if risk == "medium":
        return "medium"
    if risk in ("low", "info"):
        return "low" if risk == "low" else "info"
    return "info"


def _default_extractor(payload: Dict[str, Any]) -> Extracted:
    return Extracted(severity="info", features={"flags": {}, "strings": _collect(payload)})


# --- Per-event-type extractors (37+ telemetry report types) ---

def _ext_patch_scan(p: Dict[str, Any]) -> Extracted:
    count = int(_first(p, "count", "missing_patches_count", default=0) or 0)
    oldest = int(_first(p, "oldest_missing_days", default=0) or 0)
    sev = "high" if count >= 10 else ("medium" if count >= 3 else "low")
    return Extracted(sev, {"missing_patches": _collect(p, "missing_patches"), "count": count, "oldest_missing_days": oldest})


def _ext_behavioral(p: Dict[str, Any]) -> Extracted:
    is_anomaly = bool(p.get("is_anomaly"))
    score = float(p.get("anomaly_score", 0.0) or 0.0)
    sev = "medium" if is_anomaly and score >= 0.7 else ("low" if is_anomaly else "info")
    return Extracted(sev, {"is_anomaly": is_anomaly, "anomaly_score": score, "ml_active": bool(p.get("ml_active")), "details": p.get("details", "{}")})


def _ext_file_integrity(p: Dict[str, Any]) -> Extracted:
    changed = bool(p.get("changes_detected"))
    return Extracted("high" if changed else "info", {"changes_detected": changed, "changed_files": _collect(p, "changed_files")})


def _ext_misconfiguration(p: Dict[str, Any]) -> Extracted:
    flags = {k: bool(p.get(k)) for k in ("rdp_open", "firewall_off", "guest_account", "weak_password_policy") if k in p}
    sev = "medium" if any(flags.values()) else "info"
    return Extracted(sev, {"flags": flags})


def _ext_software_inventory(p: Dict[str, Any]) -> Extracted:
    software = p.get("software", []) or []
    risky = [s for s in software if isinstance(s, dict) and not s.get("is_approved", True)]
    return Extracted("medium" if risky else "info", {"software_count": len(software), "risky_software": risky})


def _ext_asset_discovery(p: Dict[str, Any]) -> Extracted:
    return Extracted("info", {"hostname": p.get("hostname", ""), "os_type": p.get("os_type", ""), "ip_address": p.get("ip_address", "")})


def _ext_watchdog(p: Dict[str, Any]) -> Extracted:
    tampered = bool(p.get("tamper_detected"))
    return Extracted("critical" if tampered else "info", {"tamper_detected": tampered, "agent_running": bool(p.get("agent_running")), "restart_count": int(p.get("restart_count", 0) or 0)})


def _ext_agent_monitor(p: Dict[str, Any]) -> Extracted:
    cpu = float(p.get("cpu_percent", 0.0) or 0.0)
    ram = float(p.get("ram_percent", 0.0) or 0.0)
    sev = "medium" if cpu > 90 or ram > 90 else "info"
    return Extracted(sev, {"cpu_percent": cpu, "ram_percent": ram})


def _ext_telemetry(p: Dict[str, Any]) -> Extracted:
    return Extracted("info", {"os_type": p.get("os_type", ""), "hostname": p.get("hostname", ""), "platform": p.get("platform", ""), "format_valid": bool(p.get("format_valid"))})


def _ext_pre_execution(p: Dict[str, Any]) -> Extracted:
    blocked = bool(p.get("blocked"))
    reason = p.get("reason", "")
    sev = "medium" if blocked or reason not in ("", "clean") else "info"
    return Extracted(sev, {"blocked": blocked, "reason": reason, "process_name": p.get("process_name", ""), "process_path": p.get("process_path", ""), "file_hash": p.get("file_hash", "")})


def _ext_registry_change(p: Dict[str, Any]) -> Extracted:
    auto = bool(p.get("is_auto_start"))
    key = p.get("key_path", "")
    sev = "medium" if auto else ("low" if p.get("change_type") == "deleted" else "info")
    return Extracted(sev, {"is_auto_start": auto, "key_path": key, "change_type": p.get("change_type", ""), "value_name": p.get("value_name", "")})


def _ext_zero_day(p: Dict[str, Any]) -> Extracted:
    unknown = bool(p.get("unknown_hash"))
    risky = bool(p.get("risky_location"))
    sev = "high" if unknown or risky else "info"
    return Extracted(sev, {"unknown_hash": unknown, "risky_location": risky, "file_name": p.get("file_name", ""), "file_path": p.get("file_path", "")})


def _ext_buffer_polish(p: Dict[str, Any]) -> Extracted:
    cpu = float(p.get("cpu_usage", 0.0) or 0.0)
    sev = "low" if cpu > 85 else "info"
    return Extracted(sev, {"cpu_usage": cpu, "ram_used_gb": p.get("ram_used_gb", 0), "ram_total_gb": p.get("ram_total_gb", 0), "status": p.get("status", "")})


def _ext_fileless_detection(p: Dict[str, Any]) -> Extracted:
    evlog = bool(p.get("eventlog_alert"))
    reason = p.get("reason", "")
    sev = "high" if evlog or reason not in ("", "clean") else "info"
    return Extracted(sev, {"eventlog_alert": evlog, "reason": reason, "process_name": p.get("process_name", ""), "pid": int(p.get("pid", 0) or 0)})


def _ext_memory_scan(p: Dict[str, Any]) -> Extracted:
    shellcode = bool(p.get("shellcode_detected"))
    sev = "high" if shellcode else "info"
    return Extracted(sev, {"shellcode_detected": shellcode, "reason": p.get("reason", ""), "process_name": p.get("process_name", ""), "pid": int(p.get("pid", 0) or 0)})


def _ext_usb_disk(p: Dict[str, Any]) -> Extracted:
    blocked = _collect(p, "blocked_devices")
    sev = "medium" if blocked else "info"
    return Extracted(sev, {"blocked_devices": blocked, "usb_devices": _collect(p, "usb_devices"), "usb_control_ok": bool(p.get("usb_control_ok")), "encrypted": bool(p.get("encrypted"))})


def _ext_c2_beaconing(p: Dict[str, Any]) -> Extracted:
    connections = int(p.get("connections", 0) or 0)
    variance = float(p.get("variance", 0.0) or 0.0)
    dst_ip = p.get("dst_ip", "")
    sev = "critical" if connections >= 50 else ("high" if connections >= 20 or variance < 0.5 else "medium")
    return Extracted(sev, {"connections": connections, "avg_interval": p.get("avg_interval", 0.0), "variance": variance, "src_ip": p.get("src_ip", ""), "dst_ip": dst_ip, "ip_addresses": _collect(p, "dst_ip", "src_ip")})


def _ext_threat_intel(p: Dict[str, Any]) -> Extracted:
    indicator = p.get("indicator", "")
    indicator_type = p.get("indicator_type", "IPv4")
    reputation = p.get("reputation", "")
    sev = "high" if reputation and reputation.lower() in ("malicious", "bad", "malware") else ("medium" if reputation and reputation.lower() in ("suspicious",) else "info")
    iocs = [indicator] if indicator else []
    return Extracted(sev, {"indicator": indicator, "indicator_type": indicator_type, "reputation": reputation, "pulse_count": int(p.get("pulse_count", 0) or 0), "iocs": iocs})


def _ext_offline_scan(p: Dict[str, Any]) -> Extracted:
    threats = int(p.get("threats_found", 0) or 0)
    threat_name = p.get("threat_name", "")
    sev = "high" if threats > 0 else "info"
    return Extracted(sev, {"threats_found": threats, "threat_name": threat_name, "file_path": p.get("file_path", ""), "file_hash": p.get("file_hash", "")})


def _ext_vulnerability(p: Dict[str, Any]) -> Extracted:
    risk = p.get("risk", "") or p.get("severity", "")
    sev = _severity_of(risk) or ("medium" if risk else "info")
    return Extracted(sev, {"finding_type": p.get("finding_type", ""), "software": p.get("software", ""), "cve_id": p.get("cve_id", ""), "risk": risk, "port": int(p.get("port", 0) or 0)})


def _ext_process_tree(p: Dict[str, Any]) -> Extracted:
    risk = p.get("risk", "")
    sev = _severity_of(risk)
    return Extracted(sev, {"parent_name": p.get("parent_name", ""), "parent_pid": int(p.get("parent_pid", 0) or 0), "child_name": p.get("child_name", ""), "child_pid": int(p.get("child_pid", 0) or 0), "cmdline": p.get("cmdline", ""), "process_names": _collect(p, "parent_name", "child_name")})


def _ext_action_result(p: Dict[str, Any]) -> Extracted:
    return Extracted("info", {"action": p.get("action", ""), "result": p.get("result", ""), "status": p.get("status", ""), "target": p.get("target", "")})


def _ext_shadow_it(p: Dict[str, Any]) -> Extracted:
    risk = p.get("risk", "")
    sev = _severity_of(risk)
    return Extracted(sev, {"service_name": p.get("service_name", ""), "domain": p.get("domain", ""), "category": p.get("category", ""), "domains": _collect(p, "domain"), "ip_addresses": _collect(p, "ip")})


def _ext_exploit_mitigation(p: Dict[str, Any]) -> Extracted:
    sev = _severity_of(p.get("severity", "info"))
    return Extracted(sev, {"aslr_enabled": bool(p.get("aslr_enabled")), "dep_enabled": bool(p.get("dep_enabled")), "acg_enabled": bool(p.get("acg_enabled")), "risk_summary": p.get("risk_summary", "")})


def _ext_installation_visibility(p: Dict[str, Any]) -> Extracted:
    admin = bool(p.get("running_as_admin"))
    return Extracted("low" if admin else "info", {"running_as_admin": admin, "running_as_username": p.get("running_as_username", ""), "hostname": p.get("hostname", ""), "agent_version": p.get("agent_version", "")})


def _ext_network_dpi(p: Dict[str, Any]) -> Extracted:
    threat = p.get("threat_type", "")
    reason = p.get("reason", "")
    sev = "high" if threat or reason else "low"
    return Extracted(sev, {"src_ip": p.get("src_ip", ""), "dst_ip": p.get("dst_ip", ""), "src_port": int(p.get("src_port", 0) or 0), "dst_port": int(p.get("dst_port", 0) or 0), "protocol": p.get("protocol", ""), "threat_type": threat, "reason": reason, "ip_addresses": _collect(p, "dst_ip", "src_ip")})


def _ext_privilege_escalation(p: Dict[str, Any]) -> Extracted:
    sev = _severity_of(p.get("severity", "medium"))
    return Extracted(sev, {"check_type": p.get("check_type", ""), "finding": p.get("finding", ""), "process_name": p.get("process_name", ""), "user": p.get("user", ""), "privilege": p.get("privilege", ""), "process_names": _collect(p, "process_name")})


def _ext_silent_deployment(p: Dict[str, Any]) -> Extracted:
    silent = bool(p.get("is_silent")) or bool(p.get("hidden"))
    sev = "medium" if silent else "info"
    return Extracted(sev, {"is_silent": silent, "hidden": bool(p.get("hidden")), "startup_type": p.get("startup_type", ""), "process_name": p.get("process_name", ""), "parent_process": p.get("parent_process", ""), "process_names": _collect(p, "process_name", "parent_process")})


def _ext_lateral_movement(p: Dict[str, Any]) -> Extracted:
    risk = p.get("risk", "")
    sev = _severity_of(risk) or ("medium" if p.get("movement_type") else "info")
    return Extracted(sev, {"movement_type": p.get("movement_type", ""), "source_ip": p.get("source_ip", ""), "destination_ip": p.get("destination_ip", ""), "port": int(p.get("port", 0) or 0), "service": p.get("service", ""), "connection_count": int(p.get("connection_count", 0) or 0), "ip_addresses": _collect(p, "destination_ip", "source_ip")})


def _ext_port_scan(p: Dict[str, Any]) -> Extracted:
    sensitive = bool(p.get("sensitive_ports_hit"))
    unique = int(p.get("unique_ports", 0) or 0)
    syn = int(p.get("syn_count", 0) or 0)
    sev = "high" if sensitive or unique >= 100 else ("medium" if unique >= 20 or syn >= 50 else "low")
    return Extracted(sev, {"scan_type": p.get("scan_type", ""), "scanner_ip": p.get("scanner_ip", ""), "target_ip": p.get("target_ip", ""), "unique_ports": unique, "sensitive_ports_hit": sensitive, "syn_count": syn, "ip_addresses": _collect(p, "scanner_ip", "target_ip")})


def _ext_host_firewall(p: Dict[str, Any]) -> Extracted:
    blocked = p.get("ip_blocked", "")
    sev = "medium" if blocked else "info"
    return Extracted(sev, {"chain": p.get("chain", ""), "rule": p.get("rule", ""), "ip_blocked": blocked, "action": p.get("action", ""), "ip_addresses": _collect(p, "ip_blocked")})


def _ext_web_dns_filter(p: Dict[str, Any]) -> Extracted:
    action = p.get("action", "")
    sev = "high" if action in ("block", "quarantine") else ("medium" if p.get("matched_pattern") else "info")
    return Extracted(sev, {"domain": p.get("domain", ""), "url": p.get("url", ""), "action": action, "matched_pattern": p.get("matched_pattern", ""), "domains": _collect(p, "domain")})


def _ext_script_monitor(p: Dict[str, Any]) -> Extracted:
    patterns = _collect(p, "suspicious_patterns")
    sev = "high" if patterns else "info"
    return Extracted(sev, {"command": p.get("command", ""), "user": p.get("user", ""), "suspicious_patterns": patterns, "action": p.get("action", "")})


def _ext_ransomware_canary(p: Dict[str, Any]) -> Extracted:
    reason = p.get("reason", "")
    sev = "critical" if reason else "info"
    return Extracted(sev, {"file_path": p.get("file_path", ""), "file_hash": p.get("file_hash", ""), "reason": reason, "directory": p.get("directory", "")})


def _ext_credential_dumping(p: Dict[str, Any]) -> Extracted:
    detection = p.get("detection_type", "")
    sev = "critical" if detection else "medium"
    return Extracted(sev, {"process_name": p.get("process_name", ""), "pid": int(p.get("pid", 0) or 0), "detection_type": detection, "process_names": _collect(p, "process_name")})


def _ext_nextgen_av(p: Dict[str, Any]) -> Extracted:
    reason = p.get("detection_reason", "")
    sev = "high" if reason else "info"
    return Extracted(sev, {"file_path": p.get("file_path", ""), "file_hash": p.get("file_hash", ""), "detection_reason": reason, "action": p.get("action", ""), "scanner_type": p.get("scanner_type", "")})


def _ext_user_behaviour(p: Dict[str, Any]) -> Extracted:
    changed = p.get("current_hash", "") and p.get("baseline_hash", "") and p.get("current_hash") != p.get("baseline_hash")
    sev = "medium" if changed else "info"
    return Extracted(sev, {"file_path": p.get("file_path", ""), "action": p.get("action", ""), "baseline_hash": p.get("baseline_hash", ""), "current_hash": p.get("current_hash", ""), "changed": bool(changed)})


# Canonical event_type keys mapped from route segment names.
EXTRACTORS: Dict[str, Extractor] = {
    "patch_scan": _ext_patch_scan,
    "behavioral_heuristics": _ext_behavioral,
    "file_integrity": _ext_file_integrity,
    "misconfiguration": _ext_misconfiguration,
    "software_inventory": _ext_software_inventory,
    "asset_discovery": _ext_asset_discovery,
    "watchdog": _ext_watchdog,
    "agent_monitor": _ext_agent_monitor,
    "telemetry": _ext_telemetry,
    "pre_execution": _ext_pre_execution,
    "registry_change": _ext_registry_change,
    "zero_day": _ext_zero_day,
    "buffer_polish": _ext_buffer_polish,
    "fileless_detection": _ext_fileless_detection,
    "memory_scan": _ext_memory_scan,
    "usb_disk": _ext_usb_disk,
    "c2_beaconing": _ext_c2_beaconing,
    "threat_intel": _ext_threat_intel,
    "offline_scan": _ext_offline_scan,
    "vulnerability_scan": _ext_vulnerability,
    "process_tree": _ext_process_tree,
    "action_result": _ext_action_result,
    "shadow_it": _ext_shadow_it,
    "exploit_mitigation": _ext_exploit_mitigation,
    "installation_visibility": _ext_installation_visibility,
    "network_dpi": _ext_network_dpi,
    "privilege_escalation": _ext_privilege_escalation,
    "silent_deployment": _ext_silent_deployment,
    "lateral_movement": _ext_lateral_movement,
    "port_scan": _ext_port_scan,
    "host_firewall": _ext_host_firewall,
    "web_dns_filter": _ext_web_dns_filter,
    "script_monitor": _ext_script_monitor,
    "ransomware_canary": _ext_ransomware_canary,
    "credential_dumping": _ext_credential_dumping,
    "nextgen_av": _ext_nextgen_av,
    "user_behaviour": _ext_user_behaviour,
}

# Aliases so callers can pass route segments as-is (e.g. "c2-beaconing").
_ALIASES: Dict[str, str] = {k.replace("_", "-"): k for k in EXTRACTORS}


def canonical_event_type(event_type: str) -> str:
    """Normalize a report route segment to the canonical feature key."""
    if not event_type:
        return ""
    key = event_type.strip().lower().replace("/", "-")
    if key in _ALIASES:
        return _ALIASES[key]
    if key in EXTRACTORS:
        return key
    return key


class PerceptionEngine:
    """Normalizes raw telemetry payloads into unified events.

    The engine is stateless; all temporal state lives in WorkingMemoryManager.
    """

    def normalize(self, event_type: str, agent_id: str, payload: Optional[Dict[str, Any]] = None,
                  event_id: str = "", source: str = "telemetry") -> NormalizedEvent:
        payload = payload or {}
        canonical = canonical_event_type(event_type)
        extractor = EXTRACTORS.get(canonical, _default_extractor)
        try:
            extracted = extractor(payload)
        except Exception:
            extracted = Extracted(severity="info", features={})
        return NormalizedEvent(
            event_type=canonical or event_type,
            agent_id=agent_id,
            source=source,
            event_id=event_id or str(payload.get("event_id", "")),
            timestamp=datetime.utcnow(),
            severity=extracted.severity,
            features=extracted.features,
            raw_payload=payload,
        )

    def normalize_batch(self, events: list) -> list:
        normalized = []
        for ev in events:
            if isinstance(ev, NormalizedEvent):
                normalized.append(ev)
                continue
            agent_id = ev.get("agent_id", "") if isinstance(ev, dict) else getattr(ev, "agent_id", "")
            event_type = ev.get("event_type", "") if isinstance(ev, dict) else getattr(ev, "event_type", "")
            payload = ev.get("payload", {}) if isinstance(ev, dict) else {}
            normalized.append(self.normalize(event_type, agent_id, payload))
        return normalized


perception_engine = PerceptionEngine()
