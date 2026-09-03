import os
import platform
from typing import Dict, List

from services.platform.base import PlatformAbstraction, PlatformInfo


class WindowsPlatform(PlatformAbstraction):
    def detect_os(self) -> str:
        return "windows"

    def get_platform_info(self) -> PlatformInfo:
        return PlatformInfo(
            os_type="windows",
            os_version=platform.version(),
            machine=platform.machine(),
            is_admin=self._is_admin(),
        )

    def _is_admin(self) -> bool:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def get_persistence_locations(self) -> List[str]:
        return [
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
            r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services",
        ]

    def get_system_paths(self) -> Dict[str, str]:
        return {
            "system32": os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32"),
            "syswow64": os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SysWOW64"),
            "temp": os.environ.get("TEMP", "C:\\Temp"),
            "appdata": os.environ.get("APPDATA", ""),
            "localappdata": os.environ.get("LOCALAPPDATA", ""),
            "programdata": os.environ.get("ProgramData", "C:\\ProgramData"),
            "programfiles": os.environ.get("ProgramFiles", "C:\\Program Files"),
        }

    def normalize_path(self, path: str) -> str:
        if not path:
            return path
        return path.replace("/", "\\").lower()

    def get_log_location(self) -> str:
        return os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "AgentSecurity", "logs")

    def get_config_location(self) -> str:
        return os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "AgentSecurity", "config")

    def is_system_process(self, process_name: str) -> bool:
        system_processes = {
            "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "spoolsv.exe",
            "explorer.exe", "taskhost.exe", "dwm.exe", "ntoskrnl.exe",
        }
        return process_name.lower() in {p.lower() for p in system_processes}

    def get_temporary_directories(self) -> List[str]:
        return [
            os.environ.get("TEMP", "C:\\Temp"),
            os.environ.get("TMP", "C:\\Temp"),
            "C:\\Windows\\Temp",
            "C:\\Windows\\Tasks",
        ]
