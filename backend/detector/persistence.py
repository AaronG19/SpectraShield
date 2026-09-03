import re
from typing import Dict, List, Optional, Set


REGISTRY_AUTORUN_KEYS: List[Dict[str, str]] = [
    {"key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "hive": "HKCU", "tactic": "persistence"},
    {"key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce", "hive": "HKCU", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows\run", "hive": "HKCU", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs", "hive": "HKLM", "tactic": "defense_evasion"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "hive": "HKLM", "tactic": "defense_evasion"},
    {"key": r"HKEY_CURRENT_USER\Software\Microsoft\Command Processor\AutoRun", "hive": "HKCU", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Command Processor\AutoRun", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\Startup", "hive": "HKCU", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Common Startup", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "hive": "HKCU", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms", "hive": "HKLM", "tactic": "persistence"},
    {"key": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "hive": "HKLM", "tactic": "persistence"},
]

REGISTRY_AUTORUN_RE = re.compile(
    r'(?i)(?:currentversion\\(?:run|runonce)|Startup|Winlogon|ShellServiceObjectDelayLoad)'
)

SCHEDULED_TASK_PATTERNS: List[Dict[str, str]] = [
    {"pattern": r'(?i)schtasks\s+/create', "risk": "high", "description": "Scheduled task creation"},
    {"pattern": r'(?i)schtasks\s+/change', "risk": "medium", "description": "Scheduled task modification"},
    {"pattern": r'(?i)schtasks\s+/run', "risk": "medium", "description": "Scheduled task execution"},
    {"pattern": r'(?i)schtasks\s+/delete', "risk": "low", "description": "Scheduled task deletion"},
    {"pattern": r'(?i)at\s+\d{1,2}:\d{2}\s+/interactive', "risk": "high", "description": "Legacy at.exe scheduled task"},
]

WMI_ABUSE_PATTERNS: List[Dict[str, str]] = [
    {"pattern": r'(?i)wmic\s+process\s+call\s+create', "risk": "high", "description": "WMI process creation"},
    {"pattern": r'(?i)wmic\s+/node:', "risk": "high", "description": "WMI remote execution"},
    {"pattern": r'(?i)wmic\s+product\s+call\s+install', "risk": "medium", "description": "WMI software installation"},
    {"pattern": r'(?i)wmic\s+process\s+delete', "risk": "low", "description": "WMI process termination"},
    {"pattern": r'(?i) Invoke-WmiMethod ', "risk": "high", "description": "PowerShell WMI method invocation"},
    {"pattern": r'(?i) Invoke-CimMethod ', "risk": "high", "description": "PowerShell CIM method invocation"},
    {"pattern": r'(?i) Register-WmiEvent ', "risk": "critical", "description": "WMI event subscription for persistence"},
    {"pattern": r'(?i) Set-WmiInstance ', "risk": "medium", "description": "WMI instance modification"},
]

STARTUP_FOLDER_PATHS = [
    r"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    r"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    r"\\config\\autostart\\",
    r"\\.config\\autostart\\",
]

LINUX_PERSISTENCE_PATTERNS: List[Dict[str, str]] = [
    {"pattern": r'(?i)\.bashrc|\.bash_profile|\.profile|\.zshrc', "risk": "high", "description": "Shell rc file modification"},
    {"pattern": r'(?i)crontab\s+-e|@reboot', "risk": "high", "description": "Cron job for persistence"},
    {"pattern": r'(?i)/etc/rc\.local|/etc/init\.d/|/etc/systemd/system/', "risk": "high", "description": "System init persistence"},
    {"pattern": r'(?i)systemctl\s+enable\s+|systemctl\s+start\s+', "risk": "medium", "description": "Systemd service manipulation"},
    {"pattern": r'(?i)update-rc\.d\s+|chkconfig\s+--add', "risk": "medium", "description": "SysV init persistence"},
    {"pattern": r'(?i)~/.ssh/authorized_keys', "risk": "critical", "description": "SSH key backdoor"},
    {"pattern": r'(?i)LD_PRELOAD|ld\.so\.preload', "risk": "critical", "description": "LD_PRELOAD library hijack"},
    {"pattern": r'(?i)/etc/ld\.so\.preload|/etc/ld\.so\.conf', "risk": "critical", "description": "Library loading hijack"},
]


def detect_registry_autorun(key_path: str, value_name: str, new_value: str) -> Optional[dict]:
    if not key_path:
        return None
    for autorun_key in REGISTRY_AUTORUN_KEYS:
        if autorun_key["key"].lower() in key_path.lower() or autorun_key["key"].lower().replace("hkey_", "hkey ").replace("\\", "\\\\") in key_path.lower():
            return {
                "finding_type": "registry_autorun",
                "key": key_path,
                "value": value_name,
                "data": new_value,
                "hive": autorun_key["hive"],
                "tactic": autorun_key["tactic"],
                "risk": "high",
                "description": f"Registry autorun modification detected: {key_path}\\{value_name}",
            }
    if REGISTRY_AUTORUN_RE.search(key_path):
        return {
            "finding_type": "registry_autorun_pattern",
            "key": key_path,
            "value": value_name,
            "data": new_value,
            "risk": "high",
            "description": f"Suspicious registry key modification: {key_path}\\{value_name}",
        }
    return None


def detect_scheduled_task_abuse(cmdline: str) -> List[dict]:
    findings = []
    for pattern in SCHEDULED_TASK_PATTERNS:
        if re.search(pattern["pattern"], cmdline):
            findings.append({
                "finding_type": "scheduled_task_abuse",
                "pattern": pattern["pattern"],
                "risk": pattern["risk"],
                "description": pattern["description"],
                "cmdline": cmdline[:200],
            })
    return findings


def detect_wmi_abuse(cmdline: str) -> List[dict]:
    findings = []
    for pattern in WMI_ABUSE_PATTERNS:
        if re.search(pattern["pattern"], cmdline):
            findings.append({
                "finding_type": "wmi_abuse",
                "pattern": pattern["pattern"],
                "risk": pattern["risk"],
                "description": pattern["description"],
                "cmdline": cmdline[:200],
            })
    return findings


def detect_persistence_mechanisms(cmdline: str, process_name: str, file_path: str, os_type: str = "windows") -> List[dict]:
    findings = []
    findings.extend(detect_scheduled_task_abuse(cmdline))
    findings.extend(detect_wmi_abuse(cmdline))

    cmd_lower = cmdline.lower()
    for startup_path in STARTUP_FOLDER_PATHS:
        if startup_path.lower() in file_path.lower() or startup_path.lower() in cmd_lower:
            findings.append({
                "finding_type": "startup_folder_abuse",
                "risk": "high",
                "description": f"File/command referencing startup folder: {startup_path}",
            })

    if os_type in ("linux", "macos"):
        for pattern in LINUX_PERSISTENCE_PATTERNS:
            if re.search(pattern["pattern"], cmdline):
                findings.append({
                    "finding_type": "linux_persistence",
                    "pattern": pattern["pattern"],
                    "risk": pattern["risk"],
                    "description": pattern["description"],
                    "cmdline": cmdline[:200],
                })

    return findings
