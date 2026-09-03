import json
import os
import platform
import subprocess
import time
from typing import Dict, List, Optional

from agent_lib.logger import log
from agent_lib.diagnostics import log_persistence_diff


BASELINE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
BASELINE_FILE = os.path.join(BASELINE_DIR, "persistence_baseline.json")

AUTORUN_REGISTRY_KEYS = [
    (r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    (r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
]

STARTUP_FOLDERS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\StartUp"),
]

LINUX_PERSISTENCE_PATHS = [
    "/etc/systemd/system/",
    "/etc/cron.d/",
    "/etc/init.d/",
    os.path.expanduser("~/.config/autostart/"),
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/.bash_profile"),
    os.path.expanduser("~/.zshrc"),
]

MACOS_PERSISTENCE_PATHS = [
    "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/",
    os.path.expanduser("~/Library/LaunchAgents/"),
    os.path.expanduser("~/.bash_profile"),
    os.path.expanduser("~/.zshrc"),
]


class PersistenceMonitor:
    def __init__(self):
        self._snapshots: Dict[str, Dict] = {}
        self._os_type = platform.system().lower()
        self._baseline_loaded = False
        self._baseline: List[str] = []

    def scan(self) -> List[dict]:
        findings = []
        if self._os_type == "windows":
            findings.extend(self._scan_registry())
            findings.extend(self._scan_startup_folder())
            findings.extend(self._scan_scheduled_tasks())
            findings.extend(self._scan_services())
        elif self._os_type == "linux":
            findings.extend(self._scan_linux_persistence())
        elif self._os_type == "darwin":
            findings.extend(self._scan_macos_persistence())

        # Baseline logic: first run saves, subsequent runs diff
        self._ensure_baseline_loaded()
        if not self._baseline:
            # First run — save everything as baseline, return no alerts
            self._baseline = self._make_baseline_keys(findings)
            self.save_baseline()
            return []
        else:
            # Subsequent runs — return only new entries
            new_findings = self._diff_against_baseline(findings)
            return new_findings

    def _make_baseline_key(self, entry: dict) -> str:
        ptype = (entry.get("type") or "").strip().lower()
        # Composite key: combine all identifying fields for uniqueness
        parts = [ptype]
        for field in ("key", "path", "task_name", "service_name", "value", "display_name",
                       "task_to_run", "binary_path", "name"):
            val = entry.get(field)
            if val:
                parts.append(str(val).strip().lower())
        return "|".join(parts)

    def _make_baseline_keys(self, findings: List[dict]) -> List[str]:
        seen = set()
        keys = []
        for f in findings:
            k = self._make_baseline_key(f)
            if k not in seen:
                seen.add(k)
                keys.append(k)
        return keys

    def _ensure_baseline_loaded(self):
        if not self._baseline_loaded:
            self._baseline = self.load_baseline()
            self._baseline_loaded = True

    @staticmethod
    def _normalize_baseline_key(key: str) -> str:
        segments = key.split("|")
        normalized = [segments[0].strip().lower()] if segments else [""]
        for seg in segments[1:]:
            val = seg.strip().lower()
            if val:
                normalized.append(val)
        return "|".join(normalized)

    def _is_whitelisted(self, entry: dict) -> bool:
        # Get path, data, or binary path
        path = (entry.get("path") or entry.get("data") or entry.get("task_to_run") or entry.get("binary_path") or "").lower()
        value = (entry.get("value") or entry.get("name") or entry.get("task_name") or entry.get("service_name") or "").lower()
        
        # List of trusted vendor keywords
        trusted_vendors = [
            "logitech", "logi", "nvidia", "intel", "amd", "realtek", "adobe", "google", 
            "microsoft", "onedrive", "dropbox", "spotify", "discord", "zoom", "webex", 
            "steam", "slack", "cisco", "dell", "hp", "lenovo", "synaptics", "vmware",
            "vbox", "virtualbox", "oracle", "java"
        ]
        
        # Check if the path or value contains trusted vendor names in a secure folder (Program Files or System32)
        in_secure_folder = "c:\\program files" in path or "c:\\windows\\system32" in path or "/usr/" in path or "/opt/" in path
        
        if in_secure_folder:
            for vendor in trusted_vendors:
                if vendor in path or vendor in value:
                    return True
                    
        # Whitelist standard Microsoft Windows built-in tasks and services in System32
        if "c:\\windows\\system32\\" in path and not any(bad in path for bad in ["temp", "appdata", "users"]):
            return True
            
        return False

    def _diff_against_baseline(self, findings: List[dict]) -> List[dict]:
        baseline_set = set(self._normalize_baseline_key(k) for k in self._baseline)
        current_keys = set(self._make_baseline_key(f) for f in findings)
        new_entries = []
        for f in findings:
            k = self._make_baseline_key(f)
            if k not in baseline_set:
                if self._is_whitelisted(f):
                    log.info("Ignoring whitelisted persistence entry", type=f.get("type"), value=f.get("value") or f.get("name") or f.get("task_name") or f.get("service_name"))
                    continue
                ptype = f.get("type", "")
                identifier = (f.get('service_name') or f.get('task_name')
                              or f.get('path') or f.get('key') or f.get('value') or "")
                log.info("New persistence entry detected",
                         type=ptype,
                         identifier=identifier,
                         details={k: v for k, v in f.items() if v})
                new_entries.append(f)
        new_count = len(new_entries)
        removed_count = len(baseline_set - current_keys)
        log.info("Persistence diff",
                 baseline_count=len(self._baseline),
                 new_entries=new_count,
                 removed_entries=removed_count)
        reasons = []
        for f in new_entries:
            reasons.append(f"{f.get('type','')}: {f.get('service_name') or f.get('task_name') or f.get('path') or f.get('key','')}")
        log_persistence_diff(len(self._baseline), new_count, removed_count, reasons)
        return new_entries

    @staticmethod
    def _baseline_file_for(ptype: str) -> str:
        name = {"scheduled_task": "persistence_tasks.json",
                "startup_folder": "persistence_startup.json",
                "startup_entry": "persistence_startup.json",
                "service": "persistence_services.json",
                "registry_autorun": "persistence_registry.json",
                "linux_persistence": "persistence_linux.json",
                "macos_persistence": "persistence_macos.json"}.get(ptype, "persistence_baseline.json")
        return os.path.join(BASELINE_DIR, name)

    def save_baseline(self):
        try:
            os.makedirs(BASELINE_DIR, exist_ok=True)
            # Write per-type files first
            by_type: Dict[str, list] = {}
            for key in self._baseline:
                ptype = key.split("|", 1)[0] if "|" in key else "other"
                by_type.setdefault(ptype, []).append(key)
            for ptype, keys in by_type.items():
                fpath = self._baseline_file_for(ptype)
                if fpath != BASELINE_FILE:  # don't overwrite combined yet
                    with open(fpath, "w") as f:
                        json.dump(keys, f)
            # Write combined file last (may overwrite unknown-type per-file)
            with open(BASELINE_FILE, "w") as f:
                json.dump(self._baseline, f)
            log.info("Persistence baseline saved", count=len(self._baseline))
        except Exception as e:
            log.warn("Failed to save persistence baseline", error=str(e))

    def load_baseline(self) -> List[str]:
        try:
            # Try combined file first (backward compat)
            if os.path.exists(BASELINE_FILE):
                with open(BASELINE_FILE, "r") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    log.info("Persistence baseline loaded (combined)", count=len(data))
                    return data
            # Fall back to per-type files
            seen: List[str] = []
            for ptype in ("scheduled_task", "startup_folder", "service",
                          "registry_autorun", "linux_persistence", "macos_persistence"):
                fpath = self._baseline_file_for(ptype)
                if os.path.exists(fpath):
                    with open(fpath, "r") as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        seen.extend(data)
            if seen:
                log.info("Persistence baseline loaded (per-type)", count=len(seen))
                return seen
        except Exception as e:
            log.warn("Failed to load persistence baseline", error=str(e))
        return []

    def _collect_entries(self) -> List[dict]:
        """Run all scanners irrespective of baseline state."""
        findings = []
        if self._os_type == "windows":
            findings.extend(self._scan_registry())
            findings.extend(self._scan_startup_folder())
            findings.extend(self._scan_scheduled_tasks())
            findings.extend(self._scan_services())
        elif self._os_type == "linux":
            findings.extend(self._scan_linux_persistence())
        elif self._os_type == "darwin":
            findings.extend(self._scan_macos_persistence())
        return findings

    def update_baseline(self, new_findings: List[dict]):
        new_keys = self._make_baseline_keys(new_findings)
        existing_set = set(self._baseline)
        for k in new_keys:
            if k not in existing_set:
                self._baseline.append(k)
        self.save_baseline()

    def _scan_registry(self) -> List[dict]:
        findings = []
        for key, hive in AUTORUN_REGISTRY_KEYS:
            try:
                result = subprocess.run(
                    ["reg", "query", key],
                    capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW
                )
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and "    " in line:
                        parts = line.rsplit("    ", 1)
                        if len(parts) == 2:
                            findings.append({
                                "type": "registry_autorun",
                                "key": key,
                                "value": parts[0].strip(),
                                "data": parts[1].strip(),
                                "hive": hive,
                            })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        return findings

    def _scan_startup_folder(self) -> List[dict]:
        findings = []
        for folder in STARTUP_FOLDERS:
            if os.path.isdir(folder):
                for item in os.listdir(folder):
                    item_path = os.path.join(folder, item)
                    findings.append({
                        "type": "startup_folder",
                        "path": item_path,
                        "name": item,
                        "folder": folder,
                    })
        return findings

    def _scan_scheduled_tasks(self) -> List[dict]:
        findings = []
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                capture_output=True, text=True, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            current_task = {}
            for line in result.stdout.splitlines():
                if ": " in line:
                    k, v = line.split(": ", 1)
                    current_task[k.strip()] = v.strip()
                elif line.strip() == "" and current_task:
                    if current_task.get("TaskName", "").lower() not in ( "", "taskname" ):
                        findings.append({
                            "type": "scheduled_task",
                            "task_name": current_task.get("TaskName", ""),
                            "task_to_run": current_task.get("Task To Run", ""),
                            "schedule": current_task.get("Schedule Type", ""),
                            "next_run": current_task.get("Next Run Time", ""),
                        })
                    current_task = {}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return findings

    def _scan_services(self) -> List[dict]:
        findings = []
        try:
            result = subprocess.run(
                ["sc", "query", "type=", "service", "state=", "all"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            current = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    current[k.strip()] = v.strip()
                if "STATE" in line and "SERVICE_NAME" in current:
                    name = current.get("SERVICE_NAME", "")
                    state_part = line.split(":")[-1].strip() if ":" in line else ""
                    display_name = current.get("DISPLAY_NAME", "")
                    findings.append({
                        "type": "service",
                        "service_name": name,
                        "state": state_part,
                        "display_name": display_name,
                    })
                    current = {}
            # Enrich with binary paths via PowerShell (single call)
            if findings:
                try:
                    ps_result = subprocess.run(
                        ["powershell", "-Command",
                         "Get-CimInstance Win32_Service | Select-Object Name,PathName | ConvertTo-Json"],
                        capture_output=True, text=True, timeout=30,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if ps_result.returncode == 0:
                        import json as _json
                        svc_list = _json.loads(ps_result.stdout)
                        svc_list = svc_list if isinstance(svc_list, list) else [svc_list]
                        svc_paths = {s["Name"]: s.get("PathName", "") or "" for s in svc_list}
                        for f in findings:
                            f["binary_path"] = svc_paths.get(f["service_name"], "")
                except Exception:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return findings

    def _scan_linux_persistence(self) -> List[dict]:
        findings = []
        for path in LINUX_PERSISTENCE_PATHS:
            expanded = os.path.expanduser(path)
            if os.path.isfile(expanded):
                try:
                    with open(expanded, "r") as f:
                        content = f.read()
                    findings.append({
                        "type": "linux_persistence",
                        "path": expanded,
                        "size": len(content),
                    })
                except Exception:
                    pass
            elif os.path.isdir(expanded):
                for item in os.listdir(expanded):
                    findings.append({
                        "type": "linux_persistence",
                        "path": os.path.join(expanded, item),
                    })
        return findings

    def _scan_macos_persistence(self) -> List[dict]:
        findings = []
        for path in MACOS_PERSISTENCE_PATHS:
            expanded = os.path.expanduser(path)
            if os.path.isfile(expanded):
                findings.append({"type": "macos_persistence", "path": expanded})
            elif os.path.isdir(expanded):
                for item in os.listdir(expanded):
                    findings.append({
                        "type": "macos_persistence",
                        "path": os.path.join(expanded, item),
                    })
        return findings

    def detect_changes(self, scan_results: List[dict], scan_type: str) -> List[dict]:
        return self._diff_against_baseline(scan_results)


def rebuild_baseline(baseline_dir: str = BASELINE_DIR):
    """Full system scan, save baselines for all persistence types.

    Use from CLI:  python agent.py --rebuild-baseline
    """
    global BASELINE_DIR
    BASELINE_DIR = baseline_dir
    monitor = PersistenceMonitor()
    # Force full scan by skipping baseline diff
    monitor._baseline = []
    monitor._baseline_loaded = True
    os.makedirs(baseline_dir, exist_ok=True)
    entries = monitor._collect_entries()
    monitor._baseline = monitor._make_baseline_keys(entries)
    monitor.save_baseline()
    log.info("Baseline rebuilt", count=len(monitor._baseline), dir=baseline_dir)
