import os
import re
from typing import List, Optional

from agent_lib.logger import log


MITRE_ATTACK = {
    "lolbin": {
        "id": "T1218",
        "technique": "System Binary Proxy Execution",
        "tactics": ["Defense Evasion"],
    },
    "office_macro": {
        "id": "T1137",
        "technique": "Office Application Startup",
        "tactics": ["Persistence"],
    },
    "credential_dumping": {
        "id": "T1003",
        "technique": "OS Credential Dumping",
        "tactics": ["Credential Access"],
    },
    "suspicious_service": {
        "id": "T1543",
        "technique": "Create or Modify System Process",
        "tactics": ["Persistence", "Privilege Escalation"],
    },
    "scheduled_task": {
        "id": "T1053",
        "technique": "Scheduled Task/Job",
        "tactics": ["Execution", "Persistence", "Privilege Escalation"],
    },
    "lateral_movement": {
        "id": "T1021",
        "technique": "Remote Services",
        "tactics": ["Lateral Movement"],
    },
    "fileless": {
        "id": "T1055",
        "technique": "Process Injection",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
    },
}

LOLBINS = {
    "powershell.exe": ["-enc", "encodedcommand", "downloadstring", "invoke-expression", "iex"],
    "pwsh.exe": ["-enc", "encodedcommand", "downloadstring", "invoke-expression"],
    "cmd.exe": ["certutil", "bitsadmin", "mshta", "rundll32"],
    "wscript.exe": [".vbs", ".js", ".jse"],
    "cscript.exe": [".vbs", ".js", ".jse"],
    "mshta.exe": ["javascript:", "vbscript:", "http://", "https://"],
    "rundll32.exe": ["javascript:", "http://", "https://", "url.dll"],
    "regsvr32.exe": ["http://", "https://", "/s", "/u", "/i:"],
    "certutil.exe": ["-urlcache", "-decode", "-encode"],
    "bitsadmin.exe": ["/transfer", "/download", "/upload"],
    "msiexec.exe": ["/i", "http://", "https://", "http"],
    "wmic.exe": ["process", "call", "create", "delete"],
    "mmc.exe": ["-Embedding"],
    "reg.exe": ["add", "delete", "copy", "save", "restore", "load", "unload"],
    "schtasks.exe": ["/create", "/change", "/run"],
    "sc.exe": ["create", "config", "failure"],
    "net.exe": ["user", "localgroup", "group", "share"],
    "net1.exe": ["user", "localgroup", "group", "share"],
}

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

OFFICE_MACRO_RE = re.compile(
    r'(?i)(?:winword|excel|powerpnt|outlook|msaccess|mspub)\.exe'
)
OFFICE_CHILD_SCRIPT_RE = re.compile(
    r'(?i)(?:powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe'
)

CREDENTIAL_DUMPING_PATTERNS = [
    re.compile(r'(?i)lsass'),
    re.compile(r'(?i)sam\s*(?:dump|save|copy)'),
    re.compile(r'(?i)secrets?\.dump'),
    re.compile(r'(?i)vaultcmd\s.*/list'),
    re.compile(r'(?i)cmdkey\s.*/list'),
    re.compile(r'(?i)wmic\s+process\s+get\s+.*commandline'),
    re.compile(r'(?i)reg\s+save\s+(?:hklm\\sam|hklm\\system)'),
    re.compile(r'(?i)procdump'),
    re.compile(r'(?i)mimikatz'),
    re.compile(r'(?i)comsvcs\.dll'),
    re.compile(r'(?i)tasklist.*\s/fo\s+.*svc'),
    re.compile(r'(?i)ntds\.dit'),
]

SUSPICIOUS_SERVICE_PATTERNS = [
    re.compile(r'(?i)sc\s+create\s+\S+.*binpath\s*=.*'),
    re.compile(r'(?i)sc\s+config\s+\S+.*binpath\s*=.*'),
    re.compile(r'(?i)sc\s+failure\s+\S+.*reset\s*='),
    re.compile(r'(?i)schtasks\s+/create\s+/tr\s+\S+'),
    re.compile(r'(?i)schtasks\s+/change\s+/tr\s+\S+'),
    re.compile(r'(?i)schtasks\s+/run\s+/tn\s+\S+'),
    re.compile(r'(?i)schtasks\s+/create\s+/sc\s+onlogon'),
    re.compile(r'(?i)schtasks\s+/create\s+/sc\s+onstart'),
]


LEGITIMATE_BINARIES = {
    "conhost.exe", "explorer.exe", "svchost.exe",
    "runtimebroker.exe", "sihost.exe", "taskhostw.exe",
    "ctfmon.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "smss.exe", "csrss.exe", "wininit.exe",
    "system", "registry",
}

LEGITIMATE_PATHS = {
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows",
}


def detect_lolbin(
    process_name: str,
    cmdline: str,
    path: str = "",
) -> Optional[dict]:
    if not process_name or not cmdline:
        return None
    name_lower = process_name.lower()

    if name_lower in LEGITIMATE_BINARIES:
        return None

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
                        "risk_score": 30,
                        "severity": "HIGH",
                        "mitre_id": MITRE_ATTACK["lolbin"]["id"],
                        "mitre_technique": MITRE_ATTACK["lolbin"]["technique"],
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
            "risk_score": 40,
            "severity": "HIGH",
            "mitre_id": MITRE_ATTACK["office_macro"]["id"],
            "mitre_technique": MITRE_ATTACK["office_macro"]["technique"],
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
                "risk_score": 50,
                "severity": "CRITICAL",
                "mitre_id": MITRE_ATTACK["credential_dumping"]["id"],
                "mitre_technique": MITRE_ATTACK["credential_dumping"]["technique"],
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
            mitre = MITRE_ATTACK.get(rule, MITRE_ATTACK["suspicious_service"])
            return {
                "rule": rule,
                "risk_score": 30,
                "severity": "HIGH",
                "mitre_id": mitre["id"],
                "mitre_technique": mitre["technique"],
                "description": f"Suspicious service/task creation: {matched[:120]}",
                "cmdline_preview": cmdline[:200],
            }
    return None


def run_all_detections(
    process_name: str,
    cmdline: str,
    path: str = "",
    parent_name: str = "",
    parent_cmdline: str = "",
) -> List[dict]:
    results = []

    lol = detect_lolbin(process_name, cmdline, path)
    if lol:
        results.append(lol)

    cd = detect_credential_dumping(cmdline)
    if cd:
        results.append(cd)

    st = detect_suspicious_service_or_task(cmdline)
    if st:
        results.append(st)

    om = detect_office_macro(parent_name, process_name)
    if om:
        results.append(om)

    # Also check parent cmdline for LOLBins in parent
    pl = detect_lolbin(parent_name, parent_cmdline, "")
    if pl:
        pl["description"] = f"Parent LOLBin: {pl['description']}"
        results.append(pl)

    return results
