import os
import platform
import re
import tempfile
from typing import Dict, List, Optional, Tuple


RISK_WEIGHTS = {
    "encoded_powershell": 30,
    "download_execute": 35,
    "suspicious_parent_child": 10,
    "temp_execution": 20,
    "known_malware_hash": 50,
    "malicious_ip_connection": 40,
    "suspicious_script": 20,
    "suspicious_service": 15,
    "registry_autorun_new": 25,
    "new_persistence_entry": 20,
    "c2_beaconing": 45,
    "lateral_movement": 45,
    "lolbin_abuse": 30,
    "office_macro_execution": 40,
    "credential_dumping": 50,
}

SEVERITY_THRESHOLDS = [
    ("CRITICAL", 71),
    ("HIGH", 41),
    ("MEDIUM", 21),
    ("LOW", 0),
]

# Known temp directories (strict roots only, normalized)
_KNOWN_TEMP_DIRS: Optional[List[str]] = None

def _get_known_temp_dirs() -> List[str]:
    global _KNOWN_TEMP_DIRS
    if _KNOWN_TEMP_DIRS is not None:
        return _KNOWN_TEMP_DIRS
    dirs = set()
    # Windows — only actual temp roots, not bare LOCALAPPDATA
    for var in ("TEMP", "TMP"):
        val = os.environ.get(var)
        if val:
            dirs.add(os.path.normcase(os.path.abspath(val)))
    tempdir = tempfile.gettempdir()
    if tempdir:
        dirs.add(os.path.normcase(os.path.abspath(tempdir)))
    localappdata = os.environ.get("LOCALAPPDATA")
    if localappdata:
        dirs.add(os.path.normcase(os.path.abspath(os.path.join(localappdata, "Temp"))))
    dirs.add(os.path.normcase(os.path.abspath(r"c:\windows\temp")))
    # Linux
    dirs.add("/tmp")
    dirs.add("/var/tmp")
    dirs.add("/dev/shm")
    # macOS
    dirs.add("/private/tmp")
    _KNOWN_TEMP_DIRS = sorted(dirs)
    return _KNOWN_TEMP_DIRS


ENCODED_POWERSHELL_RE = re.compile(
    r'(?i)(?:powershell|pwsh).*\s[-/](?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{20,}'
)

DOWNLOAD_EXECUTE_RE = re.compile(
    r'(?i)(?:downloadstring|downloadfile|invoke-webrequest|iwr|curl|wget)\s+https?://'
)

SUSPICIOUS_SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".jar"}

# --- LOLBin Patterns ---
# Removed "/c" from cmd args — it's a standard flag present in every cmd.exe invocation.
# Bare "powershell" removed — launching powershell from cmd is normal admin behavior;
# only encoded/download patterns are suspicious.
LOLBIN_SUSPICIOUS_ARGS = {
    "powershell": ["-enc", "encodedcommand", "downloadstring", "invoke-expression", "iex", "from base64"],
    "pwsh": ["-enc", "encodedcommand", "downloadstring", "invoke-expression"],
    "cmd": ["certutil -urlcache", "bitsadmin /transfer", "mshta", "rundll32"],
    "wscript": [".vbs", ".js", ".jse"],
    "cscript": [".vbs", ".js", ".jse"],
    "mshta": ["javascript:", "vbscript:", "http://", "https://"],
    "rundll32": ["javascript:", "http://", "https://", "url.dll,", "zipfldr,", "shell32.dll"],
    "regsvr32": ["http://", "https://", "/s /u /i:"],
    "certutil": ["-urlcache", "-decode", "-encode"],
    "bitsadmin": ["/transfer", "/download", "/upload"],
    "msiexec": ["/i http", "/quiet", "/qn"],
    "wmic": ["process call create"],
    "reg": ["add", "delete"],
    "schtasks": ["/create", "/change"],
    "sc": ["create"],
    "net": ["user /add", "localgroup administrators /add"],
}

# Binaries that should never trigger LOLBin alerts.
# These are legitimate OS or vendor components.
LEGITIMATE_BINARIES = {
    "conhost.exe", "explorer.exe", "svchost.exe",
    "runtimebroker.exe", "sihost.exe", "taskhostw.exe",
    "ctfmon.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "smss.exe", "csrss.exe", "wininit.exe",
    "system", "registry",
}

# Path prefixes that indicate legitimate installation directories.
LEGITIMATE_PATHS = {
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows",
}

# --- Office Macro Patterns ---
OFFICE_MACRO_RE = re.compile(r'(?i)(?:winword|excel|powerpnt|outlook|msaccess|mspub)\.exe')
OFFICE_CHILD_SCRIPT_RE = re.compile(
    r'(?i)(?:powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe'
)

# --- Credential Dumping Patterns ---
CREDENTIAL_DUMPING_PATTERNS = [
    re.compile(r'(?i)lsass'),
    re.compile(r'(?i)sam\s*(?:dump|save|copy)'),
    re.compile(r'(?i)secrets?\.dump'),
    re.compile(r'(?i)vaultcmd\s.*/list'),
    re.compile(r'(?i)cmdkey\s.*/list'),
    re.compile(r'(?i)reg\s+save\s+(?:hklm\\sam|hklm\\system)'),
    re.compile(r'(?i)procdump'),
    re.compile(r'(?i)mimikatz'),
    re.compile(r'(?i)comsvcs\.dll'),
    re.compile(r'(?i)ntds\.dit'),
]

# --- Suspicious Service / Task Patterns ---
SUSPICIOUS_SERVICE_PATTERNS = [
    re.compile(r'(?i)sc\s+create\s+\S+.*binpath\s*=.*'),
    re.compile(r'(?i)sc\s+config\s+\S+.*binpath\s*=.*'),
    re.compile(r'(?i)schtasks\s+/create\s+/tr\s+\S+'),
    re.compile(r'(?i)schtasks\s+/create\s+/sc\s+onlogon'),
    re.compile(r'(?i)schtasks\s+/create\s+/sc\s+onstart'),
]


def detect_encoded_powershell(cmdline: str) -> Optional[dict]:
    if ENCODED_POWERSHELL_RE.search(cmdline):
        return {
            "rule": "encoded_powershell",
            "risk_score": RISK_WEIGHTS["encoded_powershell"],
            "severity": "HIGH",
            "mitre_id": "T1059.001",
            "mitre_technique": "Command and Scripting Interpreter: PowerShell",
            "description": "Encoded PowerShell command detected",
            "cmdline_preview": cmdline[:200],
        }
    return None


def detect_download_execute(cmdline: str) -> Optional[dict]:
    if DOWNLOAD_EXECUTE_RE.search(cmdline):
        return {
            "rule": "download_execute",
            "risk_score": RISK_WEIGHTS["download_execute"],
            "severity": "HIGH",
            "mitre_id": "T1105",
            "mitre_technique": "Ingress Tool Transfer",
            "description": "Download and execute pattern detected",
            "cmdline_preview": cmdline[:200],
        }
    return None


def detect_temp_execution(path: str) -> Optional[dict]:
    return None


def detect_script_file(path: str) -> Optional[dict]:
    if not path:
        return None
    _, ext = os.path.splitext(path)
    if ext.lower() in SUSPICIOUS_SCRIPT_EXTENSIONS:
        return {
            "rule": "suspicious_script",
            "risk_score": RISK_WEIGHTS["suspicious_script"],
            "severity": "MEDIUM",
            "mitre_id": "T1059",
            "mitre_technique": "Command and Scripting Interpreter",
            "description": f"Suspicious script file detected: {path}",
            "path": path,
        }
    return None


def detect_lolbin(
    process_name: str,
    cmdline: str,
    path: str = "",
) -> Optional[dict]:
    if not process_name or not cmdline:
        return None
    name_lower = process_name.lower()

    # Skip whitelisted system binaries
    if name_lower in LEGITIMATE_BINARIES:
        return None

    # Skip AMD software running from legitimate directories
    if name_lower in ("amdrsserv.exe", "radeonsoftware.exe"):
        if path:
            path_lower = path.lower()
            for legit in LEGITIMATE_PATHS:
                if path_lower.startswith(legit):
                    return None

    cmd_lower = cmdline.lower()
    for lolbin, args in LOLBIN_SUSPICIOUS_ARGS.items():
        if lolbin in name_lower:
            for arg in args:
                if arg in cmd_lower:
                    return {
                        "rule": "lolbin_abuse",
                        "risk_score": RISK_WEIGHTS["lolbin_abuse"],
                        "severity": "HIGH",
                        "mitre_id": "T1218",
                        "mitre_technique": "System Binary Proxy Execution",
                        "description": f"LOLBin {process_name} invoked with suspicious argument: {arg}",
                        "lolbin": process_name,
                        "suspicious_arg": arg,
                        "cmdline_preview": cmdline[:200],
                    }
    return None


def detect_office_macro(parent_name: str, child_name: str) -> Optional[dict]:
    if not parent_name or not child_name:
        return None
    if OFFICE_MACRO_RE.search(parent_name) and OFFICE_CHILD_SCRIPT_RE.search(child_name):
        return {
            "rule": "office_macro_execution",
            "risk_score": RISK_WEIGHTS["office_macro_execution"],
            "severity": "HIGH",
            "mitre_id": "T1137",
            "mitre_technique": "Office Application Startup",
            "description": f"Office process ({parent_name}) spawned a script host ({child_name})",
            "parent_name": parent_name,
            "child_name": child_name,
        }
    return None


def detect_credential_dumping(cmdline: str) -> Optional[dict]:
    if not cmdline:
        return None
    for pattern in CREDENTIAL_DUMPING_PATTERNS:
        if pattern.search(cmdline):
            return {
                "rule": "credential_dumping",
                "risk_score": RISK_WEIGHTS["credential_dumping"],
                "severity": "CRITICAL",
                "mitre_id": "T1003",
                "mitre_technique": "OS Credential Dumping",
                "description": f"Credential dumping indicator in command line",
                "cmdline_preview": cmdline[:200],
            }
    return None


def detect_suspicious_service_or_task(cmdline: str) -> Optional[dict]:
    if not cmdline:
        return None
    for pattern in SUSPICIOUS_SERVICE_PATTERNS:
        if pattern.search(cmdline):
            mt = pattern.search(cmdline)
            matched = mt.group(0) if mt else cmdline[:100]
            rule = "scheduled_task" if "schtask" in matched.lower() else "suspicious_service"
            risk_key = "suspicious_service"
            mitre_id = "T1543"
            mitre_tech = "Create or Modify System Process"
            if rule == "scheduled_task":
                mitre_id = "T1053"
                mitre_tech = "Scheduled Task/Job"
            return {
                "rule": rule,
                "risk_score": RISK_WEIGHTS.get(risk_key, 15),
                "severity": "HIGH",
                "mitre_id": mitre_id,
                "mitre_technique": mitre_tech,
                "description": f"Suspicious service/task creation: {matched[:120]}",
                "cmdline_preview": cmdline[:200],
            }
    return None


def has_suspicious_indicators(cmdline: str, path: str, process_name: str = "") -> List[str]:
    indicators = []
    if detect_encoded_powershell(cmdline):
        indicators.append("encoded_powershell")
    if detect_download_execute(cmdline):
        indicators.append("download_execute")
    if detect_temp_execution(path):
        indicators.append("temp_execution")
    if detect_script_file(path):
        indicators.append("suspicious_script")
    if detect_credential_dumping(cmdline):
        indicators.append("credential_dumping")
    if detect_suspicious_service_or_task(cmdline):
        indicators.append("suspicious_service")
    if process_name and detect_lolbin(process_name, cmdline, path):
        indicators.append("lolbin_abuse")
    return indicators


def rerank_finding(
    finding: dict,
    child_proc: Optional[dict],
    parent_proc: Optional[dict],
) -> dict:
    finding_type = finding.get("type", "")
    if finding_type != "suspicious_parent_child":
        return finding

    parent_name = (finding.get("parent_name", "") or "").lower()
    child_name = (finding.get("child_name", "") or "").lower()

    # Only rerank explorer.exe → cmd.exe/powershell.exe
    if parent_name not in ("explorer.exe",):
        return finding

    if child_name not in ("cmd.exe", "powershell.exe", "pwsh.exe"):
        return finding

    if not child_proc:
        finding["risk"] = "LOW"
        finding["description"] = (
            f"Interactive shell '{finding.get('child_name', '')}' "
            f"launched from '{finding.get('parent_name', '')}' (no suspicious indicators)"
        )
        return finding

    cmdline = child_proc.get("cmdline", "")
    proc_path = child_proc.get("path", "")
    proc_name = child_proc.get("name", "")
    indicators = has_suspicious_indicators(cmdline, proc_path, proc_name)

    if not indicators:
        finding["risk"] = "LOW"
        finding["description"] = (
            f"Interactive shell '{finding.get('child_name', '')}' "
            f"launched from '{finding.get('parent_name', '')}' (no suspicious indicators)"
        )
        return finding

    score = RISK_WEIGHTS["suspicious_parent_child"] + sum(
        RISK_WEIGHTS.get(i, 0) for i in indicators
    )
    score = min(score, 100)
    risk = "LOW"
    for sev, threshold in SEVERITY_THRESHOLDS:
        if score >= threshold:
            risk = sev
            break
    finding["risk"] = risk
    finding["description"] = (
        f"Suspicious child process '{finding.get('child_name', '')}' "
        f"spawned by '{finding.get('parent_name', '')}' "
        f"(indicators: {', '.join(indicators)})"
    )
    finding["_extra_score"] = score
    return finding


def calculate_risk_score(detections: List[dict]) -> Tuple[int, str]:
    total = sum(d.get("risk_score", 0) for d in detections)
    total = min(total, 100)
    for sev, threshold in SEVERITY_THRESHOLDS:
        if total >= threshold:
            return total, sev
    return total, "LOW"


def generate_alert(detections: List[dict]) -> Optional[dict]:
    if not detections:
        return None
    score, severity = calculate_risk_score(detections)
    rules = [d["rule"] for d in detections]
    descs = [d["description"] for d in detections]
    mitre_ids = list(set(d.get("mitre_id", "") for d in detections if d.get("mitre_id")))
    mitre_techs = list(set(d.get("mitre_technique", "") for d in detections if d.get("mitre_technique")))
    return {
        "risk_score": score,
        "severity": severity,
        "rules": rules,
        "description": "; ".join(descs),
        "detections": detections,
        "mitre_ids": mitre_ids,
        "mitre_techniques": mitre_techs,
    }
