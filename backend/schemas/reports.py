"""All agent telemetry report Pydantic schemas."""
from pydantic import BaseModel


class BehavioralReport(BaseModel):
    cpu_usage: float = 0.0
    ram_usage: float = 0.0
    process_count: int = 0
    net_connections: int = 0
    is_anomaly: bool = False
    anomaly_score: float = 0.0
    ml_active: bool = False
    history_size: int = 0
    details: str = "{}"


class PatchReport(BaseModel):
    missing_patches: list[str] = []
    count: int = 0
    oldest_missing_days: int = 0
    severity: str = "info"


class FileIntegrityReport(BaseModel):
    monitored_files: list[str] = []
    changes_detected: bool = False
    changed_files: list[str] = []
    severity: str = "info"


class MisconfigReport(BaseModel):
    rdp_open: bool = False
    firewall_off: bool = False
    guest_account: bool = False
    weak_password_policy: bool = False
    severity: str = "info"


class SoftwareItem(BaseModel):
    name: str
    version: str = ""
    vendor: str = ""
    install_date: str = ""
    is_approved: bool = True
    risk_score: float = 0.0


class SoftwareInventoryReport(BaseModel):
    software: list[SoftwareItem] = []


class AssetDiscoveryReport(BaseModel):
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    architecture: str = ""
    processor: str = ""
    cpu_cores: int = 0
    logical_cpus: int = 0
    ram_gb: float = 0.0
    disk_total_gb: float = 0.0
    disk_used_gb: float = 0.0
    mac_address: str = ""
    ip_address: str = ""


class WatchdogStatusReport(BaseModel):
    agent_running: bool = True
    tamper_detected: bool = False
    restart_count: int = 0
    log_entry: str = ""


class AgentMonitorReport(BaseModel):
    cpu_percent: float = 0.0
    ram_percent: float = 0.0
    interval_seconds: int = 5


class TelemetryReport(BaseModel):
    schema_version: str = "1.0"
    os_type: str = ""
    hostname: str = ""
    platform: str = ""
    processor: str = ""
    cpu_cores: int = 0
    ram_gb: float = 0.0
    mac_address: str = ""
    format_valid: bool = True
    fields_present: int = 0


class PreExecEventReport(BaseModel):
    process_name: str = ""
    process_path: str = ""
    file_hash: str = ""
    blocked: bool = False
    reason: str = "clean"


class RegistryChangeReport(BaseModel):
    key_path: str = ""
    value_name: str = ""
    old_value: str = ""
    new_value: str = ""
    change_type: str = "added"
    is_auto_start: bool = False


class ZeroDayReport(BaseModel):
    file_name: str = ""
    file_path: str = ""
    unknown_hash: bool = False
    risky_location: bool = False


class BufferPolishReport(BaseModel):
    os: str = ""
    hostname: str = ""
    cpu_usage: float = 0.0
    ram_used_gb: float = 0.0
    ram_total_gb: float = 0.0
    mac: str = ""
    status: str = "healthy"


class FilelessDetectionEventReport(BaseModel):
    pid: int = 0
    process_name: str = ""
    reason: str = ""
    eventlog_alert: bool = False


class MemoryScanEventReport(BaseModel):
    pid: int = 0
    process_name: str = ""
    reason: str = ""
    shellcode_detected: bool = False


class UsbDiskEventReport(BaseModel):
    usb_devices: list[str] = []
    blocked_devices: list[str] = []
    usb_control_ok: bool = True
    encrypted: bool = False
    protection_on: bool = False


class C2BeaconingReport(BaseModel):
    src_ip: str = ""
    dst_ip: str = ""
    connections: int = 0
    avg_interval: float = 0.0
    variance: float = 0.0


class LiveThreatIntelReport(BaseModel):
    indicator_type: str = "IPv4"
    indicator: str = ""
    pulse_count: int = 0
    reputation: str = ""
    country: str = ""
    raw_json: str = "{}"


class OfflineScanReport(BaseModel):
    file_path: str = ""
    file_hash: str = ""
    threat_name: str = ""
    scan_directory: str = "."
    threats_found: int = 0


class VulnerabilityScanReport(BaseModel):
    finding_type: str = ""
    software: str = ""
    version: str = ""
    cve_id: str = ""
    severity: str = ""
    risk: str = ""
    description: str = ""
    port: int = 0
    service: str = ""


class ProcessTreeReport(BaseModel):
    finding_type: str = ""
    parent_name: str = ""
    parent_pid: int = 0
    child_name: str = ""
    child_pid: int = 0
    risk: str = ""
    description: str = ""
    cmdline: str = ""


class ShadowITReport(BaseModel):
    finding_type: str = ""
    service_name: str = ""
    domain: str = ""
    category: str = ""
    risk: str = ""
    description: str = ""
    ip: str = ""
    mac: str = ""


class ExploitMitigationReport(BaseModel):
    aslr_enabled: bool = False
    aslr_level: str = "unknown"
    dep_enabled: bool = False
    dep_policy: str = "unknown"
    acg_enabled: bool = False
    os: str = ""
    risk_summary: str = ""
    severity: str = "info"


class InstallationVisibilityReport(BaseModel):
    boot_time: str = ""
    install_path: str = ""
    running_as_username: str = ""
    running_as_admin: bool = False
    os_name: str = ""
    os_release: str = ""
    os_machine: str = ""
    hostname: str = ""
    agent_version: str = ""


class NetworkDPIReport(BaseModel):
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""
    reason: str = ""
    payload_size: int = 0
    threat_type: str = ""


class PrivilegeEscalationReport(BaseModel):
    check_type: str = ""
    os: str = ""
    finding: str = ""
    process_name: str = ""
    user: str = ""
    privilege: str = ""
    risk_reason: str = ""
    severity: str = "medium"


class SilentDeploymentReport(BaseModel):
    no_window: bool = False
    hidden: bool = False
    startup_type: str = "user"
    process_name: str = ""
    parent_process: str = ""
    is_silent: bool = False


class LateralMovementReport(BaseModel):
    movement_type: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    port: int = 0
    service: str = ""
    connection_count: int = 0
    risk: str = ""
    description: str = ""


class PortScanReport(BaseModel):
    scan_type: str = ""
    scanner_ip: str = ""
    target_ip: str = ""
    unique_ports: int = 0
    sensitive_ports_hit: bool = False
    syn_count: int = 0
    risk: str = ""
    description: str = ""


class HostFirewallReport(BaseModel):
    chain: str = ""
    rule: str = ""
    ip_blocked: str = ""
    action: str = ""


class WebDNSFilterReport(BaseModel):
    domain: str = ""
    url: str = ""
    action: str = ""
    matched_pattern: str = ""


class ScriptMonitorReport(BaseModel):
    command: str = ""
    user: str = ""
    suspicious_patterns: list[str] = []
    action: str = ""


class RansomwareCanaryReport(BaseModel):
    file_path: str = ""
    reason: str = ""
    file_hash: str = ""
    directory: str = ""


class CredentialDumpingReport(BaseModel):
    process_name: str = ""
    pid: int = 0
    detection_type: str = ""


class NextGenAVReport(BaseModel):
    file_path: str = ""
    file_hash: str = ""
    detection_reason: str = ""
    action: str = ""
    scanner_type: str = ""


class UserBehaviourReport(BaseModel):
    file_path: str = ""
    action: str = ""
    baseline_hash: str = ""
    current_hash: str = ""


class ProcessItem(BaseModel):
    pid: int
    ppid: int = 0
    name: str
    cmdline: str = ""
    path: str = ""
    user: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    is_suspicious: bool = False
    hash: str = ""


class ProcessesReport(BaseModel):
    processes: list[ProcessItem] = []


class NetworkConnectionItem(BaseModel):
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    protocol: str = "TCP"
    state: str = ""
    pid: int = 0
    process_name: str = ""
    is_suspicious: bool = False
    threat_intel_match: bool = False


class NetworkConnectionsReport(BaseModel):
    connections: list[NetworkConnectionItem] = []

