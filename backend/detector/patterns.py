import base64
import re
from typing import Dict, List, Optional, Tuple


LOLBINS: Dict[str, Dict[str, List[str]]] = {
    "certutil": {
        "risk": "high",
        "suspicious_args": ["-urlcache", "-decode", "-encode", "-download", "-split", "-verifyctl"],
        "description": "certutil can download/encode/decode payloads",
    },
    "mshta": {
        "risk": "critical",
        "suspicious_args": ["javascript:", "vbscript:", "http://", "https://"],
        "description": "mshta executes HTA content, commonly used for fileless malware",
    },
    "regsvr32": {
        "risk": "high",
        "suspicious_args": ["-s", "-i", "http://", "https://", "scrobj.dll"],
        "description": "regsvr32 can load remote COM scripts (Squiblydoo)",
    },
    "rundll32": {
        "risk": "high",
        "suspicious_args": ["javascript:", "http://", "https://", "url.dll", "zipfldr.dll"],
        "description": "rundll32 can execute JavaScript or download payloads",
    },
    "wmic": {
        "risk": "high",
        "suspicious_args": ["process call create", "/node:", "delete", "os get"],
        "description": "WMIC can create processes remotely, used for lateral movement",
    },
    "powershell": {
        "risk": "critical",
        "suspicious_args": [
            "-enc", "-encodedcommand", "-windowstyle hidden", "-w hidden",
            "-exec bypass", "-ep bypass", "-nop", "-noprofile",
            "downloadstring", "downloadfile", "invoke-webrequest", "iwr",
            "invoke-expression", "iex", "invoke-command", "icm",
            "start-process", "new-object net.webclient",
            "frombase64string", "memorystream", "assembly.load",
            "invoke-mimikatz", "invoke-shellcode", "invoke-obfuscation",
        ],
        "description": "PowerShell is a primary LOLBin for fileless attacks",
    },
    "cscript": {
        "risk": "high",
        "suspicious_args": [".vbs", ".js", ".jse", ".vbe", "http://", "https://"],
        "description": "cscript executes scripts, commonly used for initial access",
    },
    "wscript": {
        "risk": "high",
        "suspicious_args": [".vbs", ".js", ".jse", ".vbe", "http://", "https://"],
        "description": "wscript executes scripts, commonly used for initial access",
    },
    "msiexec": {
        "risk": "medium",
        "suspicious_args": ["http://", "https://", "/i", "/quiet", "/qn", "/package"],
        "description": "msiexec can install MSI packages from remote sources",
    },
    "cmd": {
        "risk": "medium",
        "suspicious_args": ["/c", "/k", "reg add", "schtasks", "wmic", "vssadmin", "bcdedit"],
        "description": "cmd.exe with suspicious subcommands",
    },
    "bitsadmin": {
        "risk": "high",
        "suspicious_args": ["/transfer", "/download", "/upload", "http://", "https://"],
        "description": "bitsadmin can download/upload files, used by ransomware",
    },
    "ftp": {
        "risk": "low",
        "suspicious_args": ["-s:", "http://", "https://"],
        "description": "FTP scripted transfers",
    },
    "curl": {
        "risk": "medium",
        "suspicious_args": ["-o", "-O", "http://", "https://", "--data", "--upload-file"],
        "description": "curl used for data exfiltration or download",
    },
    "wget": {
        "risk": "medium",
        "suspicious_args": ["-O", "-o", "http://", "https://", "--post-file"],
        "description": "wget used for data exfiltration or download",
    },
    "net": {
        "risk": "medium",
        "suspicious_args": ["user", "group", "localgroup", "use", "share", "view"],
        "description": "net.exe used for reconnaissance, account creation, lateral movement",
    },
    "sc": {
        "risk": "high",
        "suspicious_args": ["create", "config", "start", "stop", "delete"],
        "description": "sc.exe creates/manipulates Windows services",
    },
    "schtasks": {
        "risk": "high",
        "suspicious_args": ["/create", "/run", "/change", "/f", "/sc:", "http://"],
        "description": "schtasks creates/manipulates scheduled tasks",
    },
    "reg": {
        "risk": "medium",
        "suspicious_args": ["add", "delete", "copy", "import", "save"],
        "description": "reg.exe modifies registry, used for persistence",
    },
    "psexec": {
        "risk": "critical",
        "suspicious_args": ["-s", "-i", "-d", "-u", "-p", "-accepteula"],
        "description": "PsExec executes processes remotely, lateral movement tool",
    },
}

POWER_SHELL_ENCODED_CMD_RE = re.compile(
    r'[-/]e(?:ncod(?:ed)?(?:c(?:omman)?d)?)?\s+([A-Za-z0-9+/=]{20,})',
    re.IGNORECASE
)

BASE64_CMD_RE = re.compile(r'^(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')

ENCODED_COMMAND_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("base64_powershell", re.compile(r'(?i)(?:frombase64string|base64decode)')),
    ("hex_encoded", re.compile(r'(?i)(?:0x[0-9a-f]{2}[,\s]?){4,}')),
    ("char_encoded", re.compile(r'(?i)\[char\](?:\d{2,3})')),
    ("xor_obfuscated", re.compile(r'(?i)(-bxor|-xor)\s+\d+')),
    ("reverse_string", re.compile(r'(?i)(-join\s+\$\(\[char]|\-join\s+\$\([^)]+\|%{)')),
    ("invoke_obfuscation", re.compile(r'(?i)(invoke-obfuscation|out-obfuscatedtokencommand)')),
]

SUSPICIOUS_CMD_PATTERNS: List[Tuple[str, re.Pattern, int]] = [
    ("ip_in_cmdline", re.compile(r'(?:ping|nslookup|tracert|telnet|ssh)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'), 30),
    ("redirect_to_temp", re.compile(r'(?i)[>\|]{1,2}\s*(?:%temp%|%tmp%|\$env:temp|\/tmp|\\temp)'), 40),
    ("piped_to_rundll32", re.compile(r'(?i)[|]\s*rundll32'), 50),
    ("encoded_iex", re.compile(r'(?i)iex\s+\(?\s*\[System\.Text\.Encoding\]'), 60),
    ("download_cradle", re.compile(r'(?i)(?:downloadstring|downloadfile|invoke-webrequest|iwr|curl|wget)\s+https?://'), 50),
    ("shadow_copy_delete", re.compile(r'(?i)vssadmin\s+delete\s+shadows'), 80),
    ("bcdedit_tamper", re.compile(r'(?i)bcdedit\s+/set\s+{?\w+}?\s+recoveryenabled\s+no'), 80),
    ("wmic_process_create", re.compile(r'(?i)wmic\s+process\s+call\s+create'), 60),
    ("reg_add_run", re.compile(r'(?i)reg\s+add\s+.*\\Software\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)'), 60),
    ("schtasks_create", re.compile(r'(?i)schtasks\s+/create'), 50),
    ("net_user_add", re.compile(r'(?i)net\s+user\s+\w+\s+\w+\s+/add'), 70),
    ("net_localgroup_admin", re.compile(r'(?i)net\s+localgroup\s+(?:administrators|admin)\s+\w+\s+/add'), 80),
]

OFFICE_PRODUCTIVITY_APPS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "word.exe", "excel", "powerpoint", "outlook",
    "acrord32.exe", "acrobat.exe", "foxitreader.exe",
}

SCRIPT_INTERPRETERS = {
    "powershell.exe", "cmd.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "bash", "python", "python3", "perl", "ruby", "sh",
}

BROWSERS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "opera.exe", "brave.exe",
}

KNOWN_MALICIOUS_TOOLS = {
    "mimikatz.exe", "mimikatz", "pwdump.exe", "pwdump",
    "gsecdump", "cain.exe", "cain", "bloodhound",
    "sharpkatz", "safetykatz", "procdump", "dumpert",
    "lsassy", "handjive", "netcat.exe", "nc.exe", "ncat",
    "psexec.exe", "psexec", "wmiexec", "wmiexec.py",
    "smbexec", "smbexec.py", "atexec", "atexec.py",
    "crackmapexec", "empire", "cobaltstrike", "beacon",
}

SUSPICIOUS_PATHS: List[re.Pattern] = [
    re.compile(r'(?i)(?:\\temp\\|\\tmp\\|\\appdata\\local\\temp\\|\\users\\[^\\]+\\temp\\)'),
    re.compile(r'(?i)(?:\\windows\\tasks\\|\\windows\\debug\\|\\windows\\system32\\tasks\\)'),
    re.compile(r'(?i)(?:\\programdata\\[^\\]+\\[^\\]+\.exe)'),
    re.compile(r'(?i)(?:\\users\\[^\\]+\\(?:desktop|downloads|documents)\\[^\\]+\.(?:exe|js|vbs|ps1|bat|cmd|hta|scr|jar))'),
]


def analyze_lolbin(process_name: str, cmdline: str) -> Optional[dict]:
    name_lower = process_name.lower().strip()
    for lolbin, info in LOLBINS.items():
        if lolbin in name_lower or name_lower.startswith(lolbin):
            cmd_lower = cmdline.lower()
            matched_args = [arg for arg in info["suspicious_args"] if arg.lower() in cmd_lower]
            if matched_args:
                return {
                    "lolbin": lolbin,
                    "matched_args": matched_args,
                    "risk": info["risk"],
                    "description": info["description"],
                    "process_name": process_name,
                    "cmdline": cmdline,
                }
    return None


def decode_possible_encoded_cmd(cmdline: str) -> List[dict]:
    findings = []
    for match in POWER_SHELL_ENCODED_CMD_RE.finditer(cmdline):
        encoded_str = match.group(1)
        try:
            decoded = base64.b64decode(encoded_str).decode("utf-16le", errors="replace")
            findings.append({
                "type": "encoded_command",
                "encoded": encoded_str[:60] + "...",
                "decoded": decoded[:500],
                "severity": "high",
            })
            for pattern_name, pattern in ENCODED_COMMAND_PATTERNS:
                if pattern.search(decoded):
                    findings.append({
                        "type": pattern_name,
                        "encoded": encoded_str[:60] + "...",
                        "decoded_preview": decoded[:300],
                        "severity": "critical",
                    })
        except Exception:
            try:
                decoded = base64.b64decode(encoded_str).decode("utf-8", errors="replace")
                findings.append({
                    "type": "encoded_command_utf8",
                    "encoded": encoded_str[:60] + "...",
                    "decoded": decoded[:500],
                    "severity": "high",
                })
            except Exception:
                pass
    return findings


def detect_suspicious_cmdline(cmdline: str) -> List[dict]:
    findings = []
    for name, pattern, score in SUSPICIOUS_CMD_PATTERNS:
        if pattern.search(cmdline):
            findings.append({
                "type": name,
                "pattern": pattern.pattern,
                "risk_score": score,
            })
    return findings


def analyze_parent_child(parent_name: str, child_name: str) -> Optional[dict]:
    parent_lower = parent_name.lower().strip() if parent_name else ""
    child_lower = child_name.lower().strip() if child_name else ""

    for office_app in OFFICE_PRODUCTIVITY_APPS:
        if office_app in parent_lower:
            for script_interp in SCRIPT_INTERPRETERS:
                if script_interp in child_lower:
                    return {
                        "finding_type": "office_spawned_script",
                        "parent": parent_name,
                        "child": child_name,
                        "risk": "high",
                        "description": f"{parent_name} spawned {child_name} - possible macro execution",
                    }

    for browser in BROWSERS:
        if browser in parent_lower:
            for script_interp in SCRIPT_INTERPRETERS:
                if script_interp in child_lower:
                    return {
                        "finding_type": "browser_spawned_script",
                        "parent": parent_name,
                        "child": child_name,
                        "risk": "high",
                        "description": f"{parent_name} spawned {child_name} - possible drive-by download",
                    }

    parent_is_script = any(si in parent_lower for si in SCRIPT_INTERPRETERS)
    child_is_suspicious = any(tool in child_lower for tool in KNOWN_MALICIOUS_TOOLS)
    if parent_is_script and child_is_suspicious:
        return {
            "finding_type": "script_spawned_malicious",
            "parent": parent_name,
            "child": child_name,
            "risk": "critical",
            "description": f"Script interpreter {parent_name} spawned known malicious tool {child_name}",
        }

    if child_lower in KNOWN_MALICIOUS_TOOLS or any(tool in child_lower for tool in KNOWN_MALICIOUS_TOOLS):
        return {
            "finding_type": "malicious_tool_detected",
            "parent": parent_name,
            "child": child_name,
            "risk": "critical",
            "description": f"Known malicious tool {child_name} detected (parent: {parent_name})",
        }

    child_in_suspicious_path = any(p.search(child_lower) for p in SUSPICIOUS_PATHS)
    if child_in_suspicious_path:
        return {
            "finding_type": "suspicious_path_execution",
            "parent": parent_name,
            "child": child_name,
            "risk": "high",
            "description": f"Process executing from suspicious path: {child_name}",
        }

    return None


def detect_powershell_abuse(cmdline: str) -> List[dict]:
    findings = []
    cmd_lower = cmdline.lower()

    encoded_findings = decode_possible_encoded_cmd(cmdline)
    findings.extend(encoded_findings)

    if "-windowstyle hidden" in cmd_lower or "-w hidden" in cmd_lower or "-window hidden" in cmd_lower:
        findings.append({"type": "hidden_window", "severity": "high", "detail": "PowerShell running with hidden window"})
    if "-executionpolicy bypass" in cmd_lower or "-ep bypass" in cmd_lower or "-exec bypass" in cmd_lower:
        findings.append({"type": "exec_bypass", "severity": "high", "detail": "PowerShell execution policy bypassed"})
    if "-noprofile" in cmd_lower or "-nop" in cmd_lower:
        findings.append({"type": "no_profile", "severity": "medium", "detail": "PowerShell running without profile"})
    if "downloadstring" in cmd_lower or "downloadfile" in cmd_lower:
        findings.append({"type": "web_download", "severity": "critical", "detail": "PowerShell downloading remote content"})
    if "invoke-expression" in cmd_lower or "iex " in cmd_lower or "iex(" in cmd_lower:
        findings.append({"type": "invoke_expression", "severity": "critical", "detail": "PowerShell dynamic code execution"})
    if "invoke-mimikatz" in cmd_lower or "invoke-shellcode" in cmd_lower:
        findings.append({"type": "malicious_module", "severity": "critical", "detail": "PowerShell loading known malicious module"})
    if "frombase64string" in cmd_lower:
        findings.append({"type": "base64_decode", "severity": "high", "detail": "PowerShell decoding base64 content"})
    if "memorystream" in cmd_lower and ("assembly.load" in cmd_lower or "load(" in cmd_lower):
        findings.append({"type": "reflective_load", "severity": "critical", "detail": "PowerShell reflective PE loading"})
    if "invoke-obfuscation" in cmd_lower:
        findings.append({"type": "obfuscation_tool", "severity": "critical", "detail": "PowerShell obfuscation tool detected"})

    return findings
