"""
Feature: DLL Sideloading Detection
-------------------------------------
Flags legitimate applications loading unexpected / unsigned DLLs -
a common defense-evasion technique where a malicious DLL is placed
next to a legit signed executable using the name of a real system DLL.

Approach: enumerate running processes -> list their loaded modules
-> flag modules loaded from non-standard paths, especially ones
matching a known system DLL name, or unsigned DLLs outside trusted dirs.

Requires: pip install psutil --break-system-packages
"""

import platform
import subprocess
import os
from datetime import datetime

IS_WINDOWS = platform.system() == "Windows"

TRUSTED_DIR_PREFIXES = [
    r"c:\windows\system32", r"c:\windows\syswow64",
    r"c:\windows\winsxs", r"c:\program files", r"c:\program files (x86)",
]

# DLLs frequently abused for sideloading - flag extra hard if seen outside system dirs
HIGH_RISK_DLL_NAMES = {
    "version.dll", "dbghelp.dll", "wininet.dll", "winmm.dll",
    "uxtheme.dll", "dwmapi.dll", "cryptbase.dll", "profapi.dll",
}


class DLLSideloadMonitor:

    def _is_trusted_path(self, path: str) -> bool:
        p = path.lower()
        return any(p.startswith(prefix) for prefix in TRUSTED_DIR_PREFIXES)

    def _is_signed_windows(self, filepath: str) -> bool:
        """Uses PowerShell Get-AuthenticodeSignature - no kernel driver needed."""
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                f"(Get-AuthenticodeSignature -LiteralPath '{filepath}').Status"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return res.stdout.strip() == "Valid"
        except Exception:
            return False  # fail safe: treat check failures as unsigned

    def _get_windows_modules(self, pid):
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                f"(Get-Process -Id {pid} -Module -ErrorAction SilentlyContinue).FileName"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return [line.strip() for line in res.stdout.splitlines() if line.strip()]
        except Exception:
            return []

    def _get_linux_maps(self, pid):
        """Linux equivalent: shared libraries mapped into the process."""
        try:
            libs = set()
            with open(f"/proc/{pid}/maps", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 6 and parts[5].endswith(".so"):
                        libs.add(parts[5])
            return list(libs)
        except Exception:
            return []

    def scan(self):
        import psutil
        findings = []

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                pname = proc.info["name"]

                modules = self._get_windows_modules(pid) if IS_WINDOWS else self._get_linux_maps(pid)

                for mod_path in modules:
                    mod_name = os.path.basename(mod_path).lower()
                    trusted_location = self._is_trusted_path(mod_path)

                    is_high_risk_name = mod_name in HIGH_RISK_DLL_NAMES
                    flag_reason = None

                    if is_high_risk_name and not trusted_location:
                        flag_reason = "known-system-DLL-name loaded from non-system path"
                    elif not trusted_location and IS_WINDOWS and mod_path.lower().endswith(".dll"):
                        if not self._is_signed_windows(mod_path):
                            flag_reason = "unsigned DLL loaded from non-standard path"

                    if flag_reason:
                        findings.append({
                            "pid": pid,
                            "process": pname,
                            "module": mod_path,
                            "reason": flag_reason,
                        })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "findings": findings,
        }


if __name__ == "__main__":
    import json
    monitor = DLLSideloadMonitor()
    result = monitor.scan()
    print(json.dumps(result, indent=2))
