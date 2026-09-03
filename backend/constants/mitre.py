"""MITRE ATT&CK constants, data mappings, and helper functions."""

MITRE_TACTICS = {
    "TA0001": {"name": "Initial Access", "order": 1},
    "TA0002": {"name": "Execution", "order": 2},
    "TA0003": {"name": "Persistence", "order": 3},
    "TA0004": {"name": "Privilege Escalation", "order": 4},
    "TA0005": {"name": "Defense Evasion", "order": 5},
    "TA0006": {"name": "Credential Access", "order": 6},
    "TA0007": {"name": "Discovery", "order": 7},
    "TA0008": {"name": "Lateral Movement", "order": 8},
    "TA0009": {"name": "Collection", "order": 9},
    "TA0011": {"name": "Command and Control", "order": 10},
    "TA0040": {"name": "Impact", "order": 11},
}

MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "TA0002"},
    "T1055": {"name": "Process Injection", "tactic": "TA0005"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "TA0006"},
    "T1078": {"name": "Valid Accounts", "tactic": "TA0003"},
    "T1087": {"name": "Account Discovery", "tactic": "TA0007"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "TA0007"},
    "T1021": {"name": "Remote Services", "tactic": "TA0008"},
    "T1574": {"name": "Hijack Execution Flow", "tactic": "TA0004"},
    "T1112": {"name": "Modify Registry", "tactic": "TA0005"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "TA0003"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "TA0003"},
    "T1485": {"name": "Data Destruction", "tactic": "TA0040"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "TA0040"},
    "T1562": {"name": "Impair Defenses", "tactic": "TA0005"},
    "T1566": {"name": "Phishing", "tactic": "TA0001"},
    "T1204": {"name": "User Execution", "tactic": "TA0002"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "TA0011"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "TA0011"},
    "T1090": {"name": "Proxy", "tactic": "TA0011"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "TA0040"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "TA0011"},
    "T1007": {"name": "System Service Discovery", "tactic": "TA0007"},
    "T1035": {"name": "Service Execution", "tactic": "TA0002"},
    "T1018": {"name": "Remote System Discovery", "tactic": "TA0007"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "TA0008"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "TA0006"},
    "T1036": {"name": "Masquerading", "tactic": "TA0005"},
    "T1218": {"name": "Signed Binary Proxy Execution", "tactic": "TA0005"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "TA0004"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "TA0003"},
}

ALERT_TYPES = {
    "malware": {"severity": "critical", "mitre_technique": "T1204", "score_range": (80, 100)},
    "phishing": {"severity": "high", "mitre_technique": "T1566", "score_range": (60, 90)},
    "c2_beaconing": {"severity": "critical", "mitre_technique": "T1071", "score_range": (85, 100)},
    "privilege_escalation": {"severity": "high", "mitre_technique": "T1134", "score_range": (70, 95)},
    "fileless_malware": {"severity": "critical", "mitre_technique": "T1055", "score_range": (80, 100)},
    "ransomware": {"severity": "critical", "mitre_technique": "T1486", "score_range": (90, 100)},
    "port_scan": {"severity": "medium", "mitre_technique": "T1049", "score_range": (30, 60)},
    "misconfiguration": {"severity": "medium", "mitre_technique": "T1562", "score_range": (20, 50)},
    "shadow_it": {"severity": "low", "mitre_technique": "T1078", "score_range": (10, 30)},
    "credential_dumping": {"severity": "critical", "mitre_technique": "T1003", "score_range": (85, 100)},
    "lateral_movement": {"severity": "high", "mitre_technique": "T1021", "score_range": (75, 95)},
    "tamper": {"severity": "high", "mitre_technique": "T1562", "score_range": (70, 90)},
    "usb_violation": {"severity": "medium", "mitre_technique": "T1090", "score_range": (30, 55)},
    "policy_violation": {"severity": "low", "mitre_technique": "T1078", "score_range": (10, 25)},
    "zero_day": {"severity": "critical", "mitre_technique": "T1204", "score_range": (95, 100)},
    "lolbin": {"severity": "high", "mitre_technique": "T1218", "score_range": (60, 85)},
    "c2_dns": {"severity": "critical", "mitre_technique": "T1071", "score_range": (80, 100)},
    "beaconing": {"severity": "high", "mitre_technique": "T1071", "score_range": (65, 90)},
    "reconnaissance": {"severity": "medium", "mitre_technique": "T1087", "score_range": (25, 50)},
    "exploit": {"severity": "critical", "mitre_technique": "T1204", "score_range": (80, 100)},
}

MITRE_ATTACK_MAP = {
    "asset_discovery": {"technique_id": "T1082", "tactic_id": "TA0007", "technique_name": "System Information Discovery"},
    "os_patch_monitoring": {"technique_id": "T1190", "tactic_id": "TA0001", "technique_name": "Exploit Public-Facing Application"},
    "misconfiguration_detection": {"technique_id": "T1068", "tactic_id": "TA0004", "technique_name": "Exploitation for Privilege Escalation"},
    "file_integrity_monitoring": {"technique_id": "T1565", "tactic_id": "TA0040", "technique_name": "Data Manipulation"},
    "behavioral_heuristics": {"technique_id": "T1562", "tactic_id": "TA0005", "technique_name": "Impair Defenses"},
    "privilege_escalation_alert": {"technique_id": "T1068", "tactic_id": "TA0004", "technique_name": "Exploitation for Privilege Escalation"},
    "credential_dumping_protection": {"technique_id": "T1003", "tactic_id": "TA0006", "technique_name": "OS Credential Dumping"},
    "c2_beaconing_detection": {"technique_id": "T1071", "tactic_id": "TA0011", "technique_name": "Application Layer Protocol"},
    "lateral_movement_alert": {"technique_id": "T1021", "tactic_id": "TA0008", "technique_name": "Remote Services"},
    "usb_device_control": {"technique_id": "T1091", "tactic_id": "TA0005", "technique_name": "Replication Through Removable Media"},
    "watchdog_process": {"technique_id": "T1562", "tactic_id": "TA0005", "technique_name": "Impair Defenses"},
    "agent_monitoring": {"technique_id": "T1082", "tactic_id": "TA0007", "technique_name": "System Information Discovery"},
    "cross_platform_telemetry": {"technique_id": "T1082", "tactic_id": "TA0007", "technique_name": "System Information Discovery"},
    "pre_execution_prevention": {"technique_id": "T1055", "tactic_id": "TA0005", "technique_name": "Process Injection"},
    "registry_monitoring": {"technique_id": "T1112", "tactic_id": "TA0005", "technique_name": "Modify Registry"},
    "zero_day_detection": {"technique_id": "T1204", "tactic_id": "TA0002", "technique_name": "User Execution"},
    "buffer_polish": {"technique_id": "T1082", "tactic_id": "TA0007", "technique_name": "System Information Discovery"},
    "fileless_detection": {"technique_id": "T1055", "tactic_id": "TA0005", "technique_name": "Process Injection"},
    "memory_scan": {"technique_id": "T1007", "tactic_id": "TA0007", "technique_name": "System Service Discovery"},
    "usb_disk_control": {"technique_id": "T1091", "tactic_id": "TA0005", "technique_name": "Replication Through Removable Media"},
    "c2_beaconing": {"technique_id": "T1071", "tactic_id": "TA0011", "technique_name": "Application Layer Protocol"},
    "threat_intel": {"technique_id": "T1588", "tactic_id": "TA0042", "technique_name": "Obtain Capabilities"},
    "offline_protection": {"technique_id": "T1562", "tactic_id": "TA0005", "technique_name": "Impair Defenses"},
    "vulnerability_scan": {"technique_id": "T1588", "tactic_id": "TA0042", "technique_name": "Obtain Capabilities"},
    "process_tree": {"technique_id": "T1057", "tactic_id": "TA0007", "technique_name": "Process Discovery"},
    "shadow_it": {"technique_id": "T1040", "tactic_id": "TA0007", "technique_name": "Network Sniffing"},
    "exploit_mitigation": {"technique_id": "T1562", "tactic_id": "TA0005", "technique_name": "Impair Defenses"},
    "installation_visibility": {"technique_id": "T1082", "tactic_id": "TA0007", "technique_name": "System Information Discovery"},
    "network_dpi": {"technique_id": "T1040", "tactic_id": "TA0007", "technique_name": "Network Sniffing"},
    "privilege_escalation": {"technique_id": "T1068", "tactic_id": "TA0004", "technique_name": "Exploitation for Privilege Escalation"},
    "silent_deployment": {"technique_id": "T1562", "tactic_id": "TA0005", "technique_name": "Impair Defenses"},
    "lateral_movement": {"technique_id": "T1021", "tactic_id": "TA0008", "technique_name": "Remote Services"},
    "port_scan": {"technique_id": "T1046", "tactic_id": "TA0043", "technique_name": "Network Service Discovery"},
    "host_firewall": {"technique_id": "T1562", "tactic_id": "TA0005", "technique_name": "Impair Defenses"},
    "web_dns_filter": {"technique_id": "T1071", "tactic_id": "TA0011", "technique_name": "Application Layer Protocol"},
    "script_monitor": {"technique_id": "T1059", "tactic_id": "TA0002", "technique_name": "Command and Scripting Interpreter"},
    "ransomware_canary": {"technique_id": "T1486", "tactic_id": "TA0040", "technique_name": "Data Encrypted for Impact"},
    "credential_dumping": {"technique_id": "T1003", "tactic_id": "TA0006", "technique_name": "OS Credential Dumping"},
    "next_gen_av": {"technique_id": "T1562", "tactic_id": "TA0005", "technique_name": "Impair Defenses"},
    "user_behaviour": {"technique_id": "T1070", "tactic_id": "TA0005", "technique_name": "Indicator Removal on Host"},
}

# Threat enrichment — MITRE mappings by IOC type
MITRE_MAPPINGS = {
    "ip": [
        {"tactic": "Command and Control", "tactic_id": "TA0011", "technique": "Proxy", "technique_id": "T1090"},
        {"tactic": "Command and Control", "tactic_id": "TA0011", "technique": "Remote Access Software", "technique_id": "T1219"},
        {"tactic": "Exfiltration", "tactic_id": "TA0010", "technique": "Exfiltration Over C2 Channel", "technique_id": "T1041"},
    ],
    "hash": [
        {"tactic": "Execution", "tactic_id": "TA0002", "technique": "User Execution", "technique_id": "T1204"},
        {"tactic": "Defense Evasion", "tactic_id": "TA0005", "technique": "Masquerading", "technique_id": "T1036"},
        {"tactic": "Persistence", "tactic_id": "TA0003", "technique": "Boot or Logon Autostart Execution", "technique_id": "T1547"},
    ],
    "domain": [
        {"tactic": "Command and Control", "tactic_id": "TA0011", "technique": "Web Protocols", "technique_id": "T1071.001"},
        {"tactic": "Command and Control", "tactic_id": "TA0011", "technique": "Application Layer Protocol", "technique_id": "T1071"},
        {"tactic": "Resource Development", "tactic_id": "TA0042", "technique": "Domain Generation Algorithms", "technique_id": "T1568"},
    ],
    "url": [
        {"tactic": "Initial Access", "tactic_id": "TA0001", "technique": "Phishing", "technique_id": "T1566"},
        {"tactic": "Command and Control", "tactic_id": "TA0011", "technique": "Web Protocols", "technique_id": "T1071.001"},
    ],
}

ACTIONS_BY_TYPE = {
    "ip": [
        "Block IP at firewall / edge gateway immediately",
        "Add to blocklist in SIEM / XDR policy",
        "Review firewall logs for outbound connections to this IP",
        "Isolate affected endpoints that communicated with this IP",
        "Check proxy logs for repeated beaconing patterns",
    ],
    "hash": [
        "Block file hash via application control / allowlist",
        "Delete quarantined file from all endpoints",
        "Run full host scan on affected systems",
        "Review process execution logs for this hash",
        "Escalate to incident response if lateral movement detected",
    ],
    "domain": [
        "Block domain via DNS sinkhole / content filtering",
        "Add domain to threat intelligence blocklist",
        "Review DNS logs for resolution requests",
        "Isolate hosts that queried this domain",
        "Check for related domains via passive DNS",
    ],
    "url": [
        "Block URL via web proxy / secure web gateway",
        "Add to URL filtering policy",
        "Review web access logs for visits to this URL",
        "Conduct phishing investigation if URL is credential-harvesting",
    ],
}

SPAMHAUS_CODES = {
    "127.0.0.2": "Direct spam source (SBL)",
    "127.0.0.3": "Hijacked IP / spam source (CSS)",
    "127.0.0.4": "Exploit / proxy / malware (XBL)",
    "127.0.0.5": "Passive malware detection",
    "127.0.0.6": "Passive spam detection",
    "127.0.0.7": "Domain blocklist (DBL)",
    "127.0.0.9": "Passive spam source",
    "127.0.0.10": "Dynamic / residential IP (PBL)",
    "127.0.0.11": "Passive dynamic IP",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def get_mitre_technique_name(technique_id: str) -> str:
    return MITRE_TECHNIQUES.get(technique_id, {}).get("name", "Unknown Technique")


def get_mitre_tactic_name(tactic_id: str) -> str:
    return MITRE_TACTICS.get(tactic_id, {}).get("name", "Unknown Tactic")
