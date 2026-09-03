import re
from typing import Dict, List, Optional, Tuple


LATERAL_MOVEMENT_PATTERNS: List[Dict] = [
    {"pattern": r'(?i)psexec\s+(?:\\\\[^\\]+|\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', "type": "psexec", "risk": "critical", "description": "PsExec remote execution"},
    {"pattern": r'(?i)wmic\s+/node:\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+process\s+call\s+create', "type": "wmi_remote", "risk": "critical", "description": "WMI remote process creation"},
    {"pattern": r'(?i)winrm\s+(?:-r|-remote)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "winrm", "risk": "high", "description": "WinRM remote execution"},
    {"pattern": r'(?i)Invoke-Command\s+-ComputerName\s+\w+', "type": "powershell_remoting", "risk": "high", "description": "PowerShell remote command execution"},
    {"pattern": r'(?i)Enter-PSSession\s+-ComputerName\s+\w+', "type": "powershell_remoting", "risk": "high", "description": "PowerShell remote session"},
    {"pattern": r'(?i)net\s+use\s+\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "smb_share", "risk": "high", "description": "SMB share mounting"},
    {"pattern": r'(?i)copy\s+\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "smb_copy", "risk": "high", "description": "File copy over SMB"},
    {"pattern": r'(?i)schtasks\s+/create\s+/s\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "schtasks_remote", "risk": "critical", "description": "Remote scheduled task creation"},
    {"pattern": r'(?i)sc\s+\\\\\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "sc_remote", "risk": "high", "description": "Remote service control"},
    {"pattern": r'(?i)mstsc\s+/v:\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "rdp", "risk": "medium", "description": "RDP connection"},
    {"pattern": r'(?i)ssh\s+\w+@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "ssh", "risk": "medium", "description": "SSH remote connection"},
    {"pattern": r'(?i)scp\s+.*@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "scp", "risk": "medium", "description": "SCP file transfer"},
    {"pattern": r'(?i)rsync\s+.*@\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "rsync", "risk": "medium", "description": "Rsync file transfer"},
    {"pattern": r'(?i)smbclient\s+//\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "type": "smbclient", "risk": "high", "description": "SMB client connection"},
]

SMB_ADMIN_SHARES = [r"ADMIN\$", r"C\$", r"IPC\$", r"D\$"]
KNOWN_LATERAL_MOVEMENT_PORTS = {135, 139, 445, 3389, 5985, 5986, 22, 23}

REMOTE_SERVICES = {
    "psexec": {"ports": [135, 445], "protocol": "SMB/RPC"},
    "wmi": {"ports": [135, 445], "protocol": "DCOM/RPC"},
    "winrm": {"ports": [5985, 5986], "protocol": "HTTP/HTTPS"},
    "rdp": {"ports": [3389], "protocol": "RDP"},
    "ssh": {"ports": [22], "protocol": "SSH"},
    "smb": {"ports": [139, 445], "protocol": "SMB"},
}

ADMIN_COUNT_THRESHOLD = 3
SENSITIVE_PORT_THRESHOLD = 3


def detect_lateral_movement_cmdline(cmdline: str) -> List[dict]:
    findings = []
    for pattern in LATERAL_MOVEMENT_PATTERNS:
        if re.search(pattern["pattern"], cmdline):
            findings.append({
                "finding_type": f"lateral_movement_{pattern['type']}",
                "match_type": pattern["type"],
                "risk": pattern["risk"],
                "description": pattern["description"],
                "cmdline": cmdline[:200],
            })
    return findings


def detect_lateral_movement_network(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    protocol: str,
    connection_count: int,
) -> Optional[dict]:
    if dst_port in KNOWN_LATERAL_MOVEMENT_PORTS and connection_count >= 3:
        service_name = None
        for srv_name, srv_info in REMOTE_SERVICES.items():
            if dst_port in srv_info["ports"]:
                service_name = srv_name
                break
        return {
            "finding_type": "lateral_movement_network",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "port": dst_port,
            "protocol": protocol,
            "connection_count": connection_count,
            "risk": "high",
            "service": service_name or f"port_{dst_port}",
            "description": f"Multiple connections ({connection_count}) to {dst_ip}:{dst_port} - possible lateral movement via {service_name or 'unknown service'}",
        }
    return None


def detect_lateral_movement_network_batch(connections: List[dict]) -> List[dict]:
    findings = []
    targets: Dict[Tuple[str, int], int] = {}
    for conn in connections:
        key = (conn.get("remote_ip", ""), conn.get("remote_port", 0))
        if key[0]:
            targets[key] = targets.get(key, 0) + 1
    for (ip, port), count in targets.items():
        result = detect_lateral_movement_network("", ip, port, "", count)
        if result:
            findings.append(result)

    admin_count = sum(1 for (_, port), _ in targets.items() if port in KNOWN_LATERAL_MOVEMENT_PORTS)
    if admin_count >= ADMIN_COUNT_THRESHOLD:
        findings.append({
            "finding_type": "multiple_admin_connections",
            "risk": "critical",
            "unique_targets": admin_count,
            "description": f"Connections to {admin_count} different admin service ports detected - possible lateral movement campaign",
        })
    return findings


def detect_pass_the_hash(username: str, process_name: str, cmdline: str) -> Optional[dict]:
    cmd_lower = cmdline.lower()
    if "sekurlsa" in cmd_lower or "wdigest" in cmd_lower:
        return {
            "finding_type": "credential_theft_lateral",
            "risk": "critical",
            "process": process_name,
            "user": username,
            "description": f"Credential theft tool detected on {process_name} by {username}",
        }
    return None
