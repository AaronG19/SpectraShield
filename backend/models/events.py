"""All detection/event/domain ORM models (everything except User, Agent, Alert, PendingAction, Policy)."""
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from db.base import Base


class Application(Base):
    __tablename__ = "applications"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    name = Column(String, nullable=False)
    version = Column(String, default="")
    vendor = Column(String, default="")
    install_date = Column(DateTime, default=datetime.utcnow)
    is_approved = Column(Boolean, default=True)
    is_running = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    cve_list = Column(Text, default="[]")
    agent = relationship("Agent", back_populates="applications")


class NetworkConnection(Base):
    __tablename__ = "network_connections"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    local_ip = Column(String, default="")
    local_port = Column(Integer, default=0)
    remote_ip = Column(String, default="")
    remote_port = Column(Integer, default=0)
    protocol = Column(String, default="TCP")
    state = Column(String, default="established")
    pid = Column(Integer, default=0)
    process_name = Column(String, default="")
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    is_suspicious = Column(Boolean, default=False)
    threat_intel_match = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", back_populates="network_connections")


class Process(Base):
    __tablename__ = "processes"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    pid = Column(Integer, nullable=False)
    name = Column(String, nullable=False)
    path = Column(String, default="")
    parent_pid = Column(Integer, default=0)
    parent_name = Column(String, default="")
    cmdline = Column(String, default="")
    user = Column(String, default="")
    cpu_percent = Column(Float, default=0.0)
    memory_mb = Column(Float, default=0.0)
    is_suspicious = Column(Boolean, default=False)
    is_whitelisted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    hash = Column(String, default="")
    agent = relationship("Agent", back_populates="processes")


class FileChange(Base):
    __tablename__ = "file_changes"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    file_path = Column(String, nullable=False)
    change_type = Column(String, default="modified")
    old_hash = Column(String, default="")
    new_hash = Column(String, default="")
    file_size = Column(Integer, default=0)
    is_critical = Column(Boolean, default=False)
    is_canary = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", back_populates="file_changes")


class RegistryChange(Base):
    __tablename__ = "registry_changes"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    key_path = Column(String, nullable=False)
    value_name = Column(String, default="")
    old_value = Column(String, default="")
    new_value = Column(String, default="")
    change_type = Column(String, default="modified")
    is_auto_start = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", back_populates="registry_changes")


class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    indicator_type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    confidence = Column(String, default="medium")
    severity = Column(String, default="medium")
    source = Column(String, default="external")
    description = Column(Text, default="")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    mitre_mapping = Column(String, default="")


class CanaryFile(Base):
    __tablename__ = "canary_files"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=True)
    file_path = Column(String, nullable=False)
    file_name = Column(String, nullable=False)
    content_hash = Column(String, default="")
    is_triggered = Column(Boolean, default=False)
    triggered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=True)
    name = Column(String, nullable=False)
    direction = Column(String, default="inbound")
    action = Column(String, default="allow")
    protocol = Column(String, default="TCP")
    local_port = Column(Integer, default=0)
    remote_ip = Column(String, default="any")
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class UserBehavior(Base):
    __tablename__ = "user_behavior"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    user_name = Column(String, default="")
    event_type = Column(String, default="login")
    details = Column(Text, default="{}")
    anomaly_score = Column(Float, default=0.0)
    is_anomalous = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="user_behaviors")


class OSPatchInfo(Base):
    __tablename__ = "os_patch_info"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    missing_patches = Column(Text, default="[]")
    count = Column(Integer, default=0)
    oldest_missing_days = Column(Integer, default=0)
    severity = Column(String, default="info")
    checked_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="patch_info")


class BehavioralSnapshot(Base):
    __tablename__ = "behavioral_snapshots"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    cpu_usage = Column(Float, default=0.0)
    ram_usage = Column(Float, default=0.0)
    process_count = Column(Integer, default=0)
    net_connections = Column(Integer, default=0)
    is_anomaly = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)
    ml_active = Column(Boolean, default=False)
    history_size = Column(Integer, default=0)
    details = Column(Text, default="{}")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="behavioral_snapshots")


class FileIntegrityCheck(Base):
    __tablename__ = "file_integrity_checks"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    monitored_files = Column(Text, default="[]")
    changes_detected = Column(Boolean, default=False)
    changed_files = Column(Text, default="[]")
    severity = Column(String, default="info")
    checked_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="integrity_checks")


class MisconfigurationCheck(Base):
    __tablename__ = "misconfiguration_checks"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    rdp_open = Column(Boolean, default=False)
    firewall_off = Column(Boolean, default=False)
    guest_account = Column(Boolean, default=False)
    weak_password_policy = Column(Boolean, default=False)
    severity = Column(String, default="info")
    checked_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="misconfiguration_checks")


class WatchdogEvent(Base):
    __tablename__ = "watchdog_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    agent_running = Column(Boolean, default=True)
    tamper_detected = Column(Boolean, default=False)
    restart_count = Column(Integer, default=0)
    log_entry = Column(Text, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="watchdog_events")


class AgentMonitorLog(Base):
    __tablename__ = "agent_monitor_logs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    cpu_percent = Column(Float, default=0.0)
    ram_percent = Column(Float, default=0.0)
    interval_seconds = Column(Integer, default=5)
    recorded_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="monitor_logs")


class ProcessExecutionEvent(Base):
    __tablename__ = "process_execution_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    process_name = Column(String, default="")
    process_path = Column(String, default="")
    file_hash = Column(String, default="")
    blocked = Column(Boolean, default=False)
    reason = Column(String, default="clean")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="execution_events")


class ZeroDayFinding(Base):
    __tablename__ = "zero_day_findings"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    file_name = Column(String, default="")
    file_path = Column(String, default="")
    unknown_hash = Column(Boolean, default=False)
    risky_location = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="zero_day_findings")


class FilelessDetectionEvent(Base):
    __tablename__ = "fileless_detection_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    pid = Column(Integer, default=0)
    process_name = Column(String, default="")
    reason = Column(String, default="")
    eventlog_alert = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="fileless_events")


class MemoryScanEvent(Base):
    __tablename__ = "memory_scan_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    pid = Column(Integer, default=0)
    process_name = Column(String, default="")
    reason = Column(String, default="")
    shellcode_detected = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="memory_scan_events")


class UsbDiskEvent(Base):
    __tablename__ = "usb_disk_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    usb_devices = Column(Text, default="[]")
    blocked_devices = Column(Text, default="[]")
    usb_control_ok = Column(Boolean, default=True)
    encrypted = Column(Boolean, default=False)
    protection_on = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="usb_disk_events")


class C2BeaconingEvent(Base):
    __tablename__ = "c2_beaconing_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    src_ip = Column(String, default="")
    dst_ip = Column(String, default="")
    connections = Column(Integer, default=0)
    avg_interval = Column(Float, default=0.0)
    variance = Column(Float, default=0.0)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="c2_beaconing_events")


class LiveThreatIntelResult(Base):
    __tablename__ = "live_threat_intel_results"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    indicator_type = Column(String, default="IPv4")
    indicator = Column(String, default="")
    pulse_count = Column(Integer, default=0)
    reputation = Column(String, default="")
    country = Column(String, default="")
    raw_json = Column(Text, default="{}")
    checked_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="threat_intel_results")


class OfflineScanEvent(Base):
    __tablename__ = "offline_scan_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    file_path = Column(String, default="")
    file_hash = Column(String, default="")
    threat_name = Column(String, default="")
    scan_directory = Column(String, default=".")
    threats_found = Column(Integer, default=0)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="offline_scan_events")


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    finding_type = Column(String, default="")
    software = Column(String, default="")
    version = Column(String, default="")
    cve_id = Column(String, default="")
    severity = Column(String, default="")
    risk = Column(String, default="")
    description = Column(Text, default="")
    port = Column(Integer, default=0)
    service = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="vulnerability_findings")


class ProcessTreeFinding(Base):
    __tablename__ = "process_tree_findings"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    finding_type = Column(String, default="")
    parent_name = Column(String, default="")
    parent_pid = Column(Integer, default=0)
    child_name = Column(String, default="")
    child_pid = Column(Integer, default=0)
    risk = Column(String, default="")
    description = Column(Text, default="")
    cmdline = Column(Text, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="process_tree_findings")


class ShadowITFinding(Base):
    __tablename__ = "shadow_it_findings"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    finding_type = Column(String, default="")
    service_name = Column(String, default="")
    domain = Column(String, default="")
    category = Column(String, default="")
    risk = Column(String, default="")
    description = Column(Text, default="")
    ip = Column(String, default="")
    mac = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="shadow_it_findings")


class ExploitMitigationEvent(Base):
    __tablename__ = "exploit_mitigation_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    aslr_enabled = Column(Boolean, default=False)
    aslr_level = Column(String, default="unknown")
    dep_enabled = Column(Boolean, default=False)
    dep_policy = Column(String, default="unknown")
    acg_enabled = Column(Boolean, default=False)
    os = Column(String, default="")
    risk_summary = Column(String, default="")
    severity = Column(String, default="info")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="exploit_mitigation_events")


class InstallationVisibilityEvent(Base):
    __tablename__ = "installation_visibility_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    boot_time = Column(String, default="")
    install_path = Column(String, default="")
    running_as_username = Column(String, default="")
    running_as_admin = Column(Boolean, default=False)
    os_name = Column(String, default="")
    os_release = Column(String, default="")
    os_machine = Column(String, default="")
    hostname = Column(String, default="")
    agent_version = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="installation_visibility_events")


class NetworkDPIEvent(Base):
    __tablename__ = "network_dpi_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    src_ip = Column(String, default="")
    dst_ip = Column(String, default="")
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=0)
    protocol = Column(String, default="")
    reason = Column(Text, default="")
    payload_size = Column(Integer, default=0)
    threat_type = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="network_dpi_events")


class PrivilegeEscalationEvent(Base):
    __tablename__ = "privilege_escalation_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    check_type = Column(String, default="")
    os = Column(String, default="")
    finding = Column(Text, default="")
    process_name = Column(String, default="")
    user = Column(String, default="")
    privilege = Column(String, default="")
    risk_reason = Column(Text, default="")
    severity = Column(String, default="medium")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="privilege_escalation_events")


class SilentDeploymentEvent(Base):
    __tablename__ = "silent_deployment_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    no_window = Column(Boolean, default=False)
    hidden = Column(Boolean, default=False)
    startup_type = Column(String, default="user")
    process_name = Column(String, default="")
    parent_process = Column(String, default="")
    is_silent = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="silent_deployment_events")


class LateralMovementEvent(Base):
    __tablename__ = "lateral_movement_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    movement_type = Column(String, default="")
    source_ip = Column(String, default="")
    destination_ip = Column(String, default="")
    port = Column(Integer, default=0)
    service = Column(String, default="")
    connection_count = Column(Integer, default=0)
    risk = Column(String, default="")
    description = Column(Text, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="lateral_movement_events")


class PortScanEvent(Base):
    __tablename__ = "port_scan_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    scan_type = Column(String, default="")
    scanner_ip = Column(String, default="")
    target_ip = Column(String, default="")
    unique_ports = Column(Integer, default=0)
    sensitive_ports_hit = Column(Boolean, default=False)
    syn_count = Column(Integer, default=0)
    risk = Column(String, default="")
    description = Column(Text, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="port_scan_events")


class HostFirewallEvent(Base):
    __tablename__ = "host_firewall_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    chain = Column(String, default="")
    rule = Column(String, default="")
    ip_blocked = Column(String, default="")
    action = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="host_firewall_events")


class WebDNSFilterEvent(Base):
    __tablename__ = "web_dns_filter_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    domain = Column(String, default="")
    url = Column(String, default="")
    action = Column(String, default="")
    matched_pattern = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="web_dns_filter_events")


class ScriptMonitorEvent(Base):
    __tablename__ = "script_monitor_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    command = Column(Text, default="")
    user = Column(String, default="")
    suspicious_patterns = Column(Text, default="[]")
    action = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="script_monitor_events")


class RansomwareCanaryEvent(Base):
    __tablename__ = "ransomware_canary_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    file_path = Column(String, default="")
    reason = Column(String, default="")
    file_hash = Column(String, default="")
    directory = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="ransomware_canary_events")


class CredentialDumpingEvent(Base):
    __tablename__ = "credential_dumping_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    process_name = Column(String, default="")
    pid = Column(Integer, default=0)
    detection_type = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="credential_dumping_events")


class NextGenAVEvent(Base):
    __tablename__ = "next_gen_av_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    file_path = Column(String, default="")
    file_hash = Column(String, default="")
    detection_reason = Column(String, default="")
    action = Column(String, default="")
    scanner_type = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="next_gen_av_events")


class UserBehaviourEvent(Base):
    __tablename__ = "user_behaviour_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id"), nullable=False)
    file_path = Column(String, default="")
    action = Column(String, default="")
    baseline_hash = Column(String, default="")
    current_hash = Column(String, default="")
    detected_at = Column(DateTime, default=datetime.utcnow)
    agent = relationship("Agent", backref="user_behaviour_events")
