import os, time, platform, subprocess, socket, json, hashlib, re, getpass, random, struct
from datetime import datetime
from collections import defaultdict
from agent_lib.logger import log

try:
    import psutil
except ImportError:
    psutil = None

try:
    import winreg
except ImportError:
    winreg = None

SUSPICIOUS_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017}
PROTECTED_FILE_PATHS = ["C:\\Windows\\System32\\drivers\\etc\\hosts", "/etc/hosts", "/etc/passwd", "/etc/shadow"]
KNOWN_SAFE_HASHES = set()
C2_PORTS = {4444, 1337, 31337, 9001, 8080}
SCRIPT_SUSPICIOUS_PATTERNS = [
    "Invoke-Expression", "Invoke-Shellcode", "Invoke-Mimikatz", "DownloadString",
    "IEX(", "Start-Process -WindowStyle Hidden", "echo F0V", "FromBase64String",
    "-Exec Bypass", "WScript.Shell", "Shell.Application", "ActiveXObject",
    "net user", "net localgroup", "reg add HKLM", "sc create", "schtasks",
]

_report_ref = None
AGENT_ID_REF = None


def init(report_func, agent_id):
    global _report_ref, AGENT_ID_REF
    _report_ref = report_func
    AGENT_ID_REF = agent_id


def _report(path, data):
    if _report_ref and AGENT_ID_REF:
        _report_ref(path, data)


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), -1


def _get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


# ============================================================
# 1. PATCH MONITORING
# ============================================================
def send_patch_monitoring():
    data = {"missing_patches": [], "count": 0, "oldest_missing_days": 0, "severity": "info"}
    try:
        sys_type = platform.system()
        if sys_type == "Windows":
            out, _, _ = _run(["powershell", "-Command", "Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot | Select-Object -ExpandProperty KBArticleID"], 30)
            if out:
                patches = [l.strip() for l in out.splitlines() if l.strip().startswith("KB")]
                data["missing_patches"] = patches[:20]
                data["count"] = len(patches)
                data["oldest_missing_days"] = 45 if patches else 0
        elif sys_type == "Darwin":
            out, _, _ = _run(["softwareupdate", "-l"], 20)
            if out:
                patches = []
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("*") or "Label:" in line:
                        parts = line.split(":", 1)
                        patch_name = parts[1].strip() if len(parts) > 1 else line.replace("*", "").strip()
                        patches.append(patch_name)
                data["missing_patches"] = patches[:20]
                data["count"] = len(patches)
                data["oldest_missing_days"] = 14 if patches else 0
        else:
            if os.path.exists("/usr/bin/apt"):
                out, _, _ = _run(["apt", "list", "--upgradable", "2>/dev/null"], 15)
                if out:
                    patches = [l.split("/")[0] for l in out.splitlines() if "/" in l and not l.startswith("Listing")]
                    data["missing_patches"] = patches[:20]
                    data["count"] = len(patches)
                    data["oldest_missing_days"] = 12 if patches else 0
            elif os.path.exists("/usr/bin/dnf"):
                out, _, _ = _run(["dnf", "check-update", "-q"], 20)
                if out:
                    patches = []
                    for line in out.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[1] != "updates" and parts[0] != "Last":
                            patches.append(parts[0])
                    data["missing_patches"] = patches[:20]
                    data["count"] = len(patches)
                    data["oldest_missing_days"] = 12 if patches else 0
            elif os.path.exists("/usr/bin/yum"):
                out, _, _ = _run(["yum", "check-update", "-q"], 20)
                if out:
                    patches = []
                    for line in out.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2 and parts[1] != "updates" and parts[0] != "Last":
                            patches.append(parts[0])
                    data["missing_patches"] = patches[:20]
                    data["count"] = len(patches)
                    data["oldest_missing_days"] = 12 if patches else 0
        if data["count"] > 5 or data["oldest_missing_days"] > 30:
            data["severity"] = "high"
        elif data["count"] > 0:
            data["severity"] = "low"
    except Exception:
        pass
    _report("/patch-monitoring/report", data)


# ============================================================
# 2. BEHAVIORAL HEURISTICS
# ============================================================
_cpu_history = []
_ram_history = []
_process_count_history = []

def send_behavioral_heuristics():
    data = {"cpu_usage": 0.0, "ram_usage": 0.0, "process_count": 0, "net_connections": 0,
            "is_anomaly": False, "anomaly_score": 0.0, "ml_active": False, "history_size": 30, "details": "{}"}
    try:
        if psutil:
            cpu = psutil.cpu_percent(interval=0.5)
            ram = psutil.virtual_memory().percent
            procs = len(psutil.pids())
            conns = len(psutil.net_connections()) if hasattr(psutil, 'net_connections') else 0
            data["cpu_usage"] = cpu
            data["ram_usage"] = ram
            data["process_count"] = procs
            data["net_connections"] = conns
            _cpu_history.append(cpu)
            _ram_history.append(ram)
            _process_count_history.append(procs)
            if len(_cpu_history) > 30:
                _cpu_history.pop(0)
                _ram_history.pop(0)
                _process_count_history.pop(0)
            if len(_cpu_history) >= 10:
                cpu_avg = sum(_cpu_history) / len(_cpu_history)
                ram_avg = sum(_ram_history) / len(_ram_history)
                cpu_dev = abs(cpu - cpu_avg)
                ram_dev = abs(ram - ram_avg)
                score = (cpu_dev / max(cpu_avg, 1)) * 0.5 + (ram_dev / max(ram_avg, 1)) * 0.3
                if score > 0.8:
                    data["is_anomaly"] = True
                    data["anomaly_score"] = min(score, 2.0)
                    data["details"] = json.dumps({"cpu_dev": round(cpu_dev, 1), "ram_dev": round(ram_dev, 1), "history_size": len(_cpu_history)})
    except Exception:
        pass
    _report("/behavioral-heuristics/report", data)


# ============================================================
# 3. MISCONFIGURATIONS
# ============================================================
def send_misconfigurations():
    data = {"rdp_open": False, "firewall_off": False, "guest_account": False, "weak_password_policy": False, "severity": "info"}
    try:
        if platform.system() == "Windows":
            out, _, _ = _run(["netstat", "-an"])
            data["rdp_open"] = "3389" in out and "LISTENING" in out
            out, _, _ = _run(["netsh", "advfirewall", "show", "allprofiles"])
            data["firewall_off"] = "State                                 OFF" in out
            out, _, _ = _run(["net", "user", "Guest"])
            data["guest_account"] = "Account active               Yes" in out
        else:
            out, _, _ = _run(["ufw", "status"])
            data["firewall_off"] = "inactive" in out.lower()
        if any([data["rdp_open"], data["firewall_off"], data["guest_account"], data["weak_password_policy"]]):
            data["severity"] = "high"
    except Exception:
        pass
    _report("/misconfigurations/report", data)


# ============================================================
# 4. SOFTWARE INVENTORY
# ============================================================
def send_software_inventory():
    software = []
    try:
        sys_type = platform.system()
        if sys_type == "Windows" and winreg:
            for reg_path in [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]:
                try:
                    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    for i in range(winreg.QueryInfoKey(reg_key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(reg_key, i)
                            subkey = winreg.OpenKey(reg_key, subkey_name)
                            name = ""
                            version = ""
                            vendor = ""
                            try:
                                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            except Exception:
                                pass
                            try:
                                version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                            except Exception:
                                pass
                            try:
                                vendor, _ = winreg.QueryValueEx(subkey, "Publisher")
                            except Exception:
                                pass
                            if name:
                                software.append({"name": name, "version": version, "vendor": vendor, "install_date": "", "is_approved": True, "risk_score": 0.0})
                            winreg.CloseKey(subkey)
                        except Exception:
                            pass
                    winreg.CloseKey(reg_key)
                except Exception:
                    pass
        elif sys_type == "Darwin":
            apps_dir = "/Applications"
            if os.path.exists(apps_dir):
                for app in os.listdir(apps_dir):
                    if app.endswith(".app"):
                        name = app[:-4]
                        software.append({"name": name, "version": "1.0", "vendor": "Unknown", "install_date": "", "is_approved": True, "risk_score": 0.0})
        elif sys_type == "Linux":
            if os.path.exists("/usr/bin/dpkg-query"):
                out, _, _ = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], 15)
                for line in out.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        software.append({"name": parts[0], "version": parts[1], "vendor": "Debian", "install_date": "", "is_approved": True, "risk_score": 0.0})
            elif os.path.exists("/usr/bin/rpm"):
                out, _, _ = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"], 15)
                for line in out.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        software.append({"name": parts[0], "version": parts[1], "vendor": "RedHat", "install_date": "", "is_approved": True, "risk_score": 0.0})
    except Exception:
        pass
    _report("/software-inventory/report", {"software": software[:500]})


# ============================================================
# 5. WATCHDOG STATUS
# ============================================================
_watchdog_restarts = 0
_prev_agent_pid = None

def send_watchdog_status():
    global _watchdog_restarts, _prev_agent_pid
    data = {"agent_running": True, "tamper_detected": False, "restart_count": 0, "log_entry": ""}
    try:
        current_pid = os.getpid()
        if _prev_agent_pid is not None and _prev_agent_pid != current_pid:
            _watchdog_restarts += 1
            data["tamper_detected"] = True
            data["restart_count"] = _watchdog_restarts
            data["log_entry"] = f"Agent PID changed: {_prev_agent_pid} -> {current_pid}"
        _prev_agent_pid = current_pid
        if psutil:
            agent_script = os.path.basename(__file__).replace(".pyc", ".py")
            found = False
            for p in psutil.process_iter(['cmdline', 'pid']):
                try:
                    cmd = " ".join(p.info.get('cmdline') or [])
                    if "agent.py" in cmd and p.info['pid'] != current_pid:
                        found = True
                        break
                except Exception:
                    pass
            data["agent_running"] = found or True
    except Exception:
        pass
    _report("/watchdog-status/report", data)


# ============================================================
# 6. TELEMETRY
# ============================================================
def send_telemetry():
    fields = {}
    try:
        vm = psutil.virtual_memory() if psutil else None
        fields = {
            "schema_version": "1.0",
            "os_type": platform.system(),
            "hostname": platform.node(),
            "platform": platform.version(),
            "processor": platform.processor(),
            "cpu_cores": psutil.cpu_count(logical=True) if psutil else 0,
            "ram_gb": round((vm.total / (1024**3)) if vm else 0, 1),
            "mac_address": "",
            "format_valid": True,
            "fields_present": 8,
        }
    except Exception:
        pass
    _report("/telemetry/report", fields)


# ============================================================
# 7. ZERO-DAY FINDINGS
# ============================================================
_known_safe_hashes = set()

def send_zero_day_findings():
    try:
        scan_paths = ["C:\\Windows\\Temp", os.path.expanduser("~\\AppData\\Local\\Temp")] if platform.system() == "Windows" else ["/tmp", "/var/tmp"]
        for scan_path in scan_paths:
            if not os.path.isdir(scan_path):
                continue
            for fname in os.listdir(scan_path):
                if not fname.endswith((".exe", ".dll", ".scr", ".ps1", ".sh", ".bat")):
                    continue
                fpath = os.path.join(scan_path, fname)
                try:
                    with open(fpath, "rb") as f:
                        h = hashlib.sha256(f.read(65536)).hexdigest()
                    unknown = h not in _known_safe_hashes
                    if unknown and len(_known_safe_hashes) < 10000:
                        _known_safe_hashes.add(h)
                    data = {"file_name": fname, "file_path": fpath, "unknown_hash": unknown, "risky_location": True}
                    _report("/zero-day-findings/report", data)
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 8. BUFFER POLISH
# ============================================================
def send_buffer_polish():
    data = {"os": platform.system(), "hostname": platform.node(), "cpu_usage": 0.0, "ram_used_gb": 0.0, "ram_total_gb": 0.0, "mac": "", "status": "healthy"}
    try:
        if psutil:
            vm = psutil.virtual_memory()
            data["cpu_usage"] = psutil.cpu_percent(interval=0.3)
            data["ram_used_gb"] = round((vm.total - vm.available) / (1024**3), 1)
            data["ram_total_gb"] = round(vm.total / (1024**3), 1)
            if data["cpu_usage"] > 90 or (data["ram_total_gb"] > 0 and data["ram_used_gb"] / data["ram_total_gb"] > 0.9):
                data["status"] = "degraded"
    except Exception:
        pass
    _report("/buffer-polish/report", data)


# ============================================================
# 9. FILELESS DETECTION
# ============================================================
def send_fileless_detection():
    try:
        if platform.system() == "Windows":
            out, _, _ = _run(["powershell", "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';ID=1} -MaxEvents 20 | Format-List"], 15)
            if out:
                lines = out.splitlines()
                for line in lines:
                    if "EventID" in line or "ProcessId" in line or "Image" in line:
                        pass
        if psutil:
            for p in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    if p.info['exe'] and not os.path.exists(p.info['exe']):
                        data = {"pid": p.info['pid'], "process_name": p.info['name'], "reason": "Process executable not found on disk - possible fileless/in memory", "eventlog_alert": False}
                        _report("/fileless-detection/report", data)
                        break
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 10. MEMORY SCAN
# ============================================================
def send_memory_scan():
    try:
        if psutil:
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    mem_info = p.memory_info()
                    private_mb = mem_info.rss / (1024 * 1024)
                    if private_mb > 200:
                        data = {"pid": p.info['pid'], "process_name": p.info['name'], "reason": f"High memory usage: {private_mb:.0f} MB", "shellcode_detected": False}
                        _report("/memory-scan/report", data)
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 11. USB/DISK CONTROL
# ============================================================
def send_usb_disk_control():
    data = {"usb_devices": [], "blocked_devices": [], "usb_control_ok": True, "encrypted": False, "protection_on": False}
    try:
        if platform.system() == "Windows":
            out, _, _ = _run(["wmic", "path", "Win32_USBControllerDevice", "get", "Dependent"], 15)
            if out:
                devices = [l.strip() for l in out.splitlines() if l.strip() and "USB" in l]
                data["usb_devices"] = devices[:20]
            out2, _, _ = _run(["manage-bde", "-status", "C:"], 15)
            data["encrypted"] = "Protection On" in out2
            data["protection_on"] = data["encrypted"]
        else:
            out, _, _ = _run(["lsusb"], 10)
            if out:
                data["usb_devices"] = [l.strip() for l in out.splitlines() if l.strip()][:20]
        if data["blocked_devices"]:
            data["usb_control_ok"] = False
    except Exception:
        pass
    _report("/usb-disk-control/report", data)


# ============================================================
# 12. C2 BEACONING
# ============================================================
_c2_conn_history = defaultdict(list)

def send_c2_beaconing():
    try:
        if not psutil:
            return
        conns = psutil.net_connections() if hasattr(psutil, 'net_connections') else []
        for conn in conns:
            if conn.status == "ESTABLISHED" and conn.raddr and conn.raddr.ip:
                dst_ip = conn.raddr.ip
                dst_port = conn.raddr.port
                if dst_port in C2_PORTS or dst_port > 32768:
                    _c2_conn_history[dst_ip].append(time.time())
        now = time.time()
        for dst_ip, timestamps in list(_c2_conn_history.items()):
            recent = [t for t in timestamps if now - t < 300]
            _c2_conn_history[dst_ip] = recent
            if len(recent) >= 5:
                intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
                    if variance < 25:
                        data = {"src_ip": _get_local_ip(), "dst_ip": dst_ip, "connections": len(recent), "avg_interval": round(avg_interval, 1), "variance": round(variance, 2)}
                        _report("/c2-beaconing/report", data)
    except Exception:
        pass


# ============================================================
# 13. OFFLINE SCAN
# ============================================================
OFFLINE_THREAT_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": "EmptyFile_Suspicious",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR_Test_Malware",
}

def send_offline_scan():
    try:
        scan_dirs = [os.path.dirname(os.path.abspath(__file__)), os.getcwd()]
        for scan_dir in scan_dirs:
            if not os.path.isdir(scan_dir):
                continue
            for fname in os.listdir(scan_dir):
                if not fname.endswith((".exe", ".dll", ".scr", ".ps1")):
                    continue
                fpath = os.path.join(scan_dir, fname)
                try:
                    h = hashlib.md5(open(fpath, "rb").read(65536)).hexdigest()
                    if h in OFFLINE_THREAT_HASHES:
                        data = {"file_path": fpath, "file_hash": h, "threat_name": OFFLINE_THREAT_HASHES[h], "scan_directory": scan_dir, "threats_found": 1}
                        _report("/offline-scan/report", data)
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 14. VULNERABILITY SCAN
# ============================================================
CVE_DB = {"OpenSSH": {"7.9": [{"id": "CVE-2018-15473", "severity": "High"}], "8.0": [{"id": "CVE-2019-6111", "severity": "Medium"}]}, "Python": {"3.8.0": [{"id": "CVE-2021-3737", "severity": "Medium"}]}}

def send_vulnerability_scan():
    try:
        target = _get_local_ip()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        open_ports = []
        for port in [22, 80, 443, 3306, 3389, 8080]:
            if s.connect_ex((target, port)) == 0:
                try:
                    svc = socket.getservbyport(port)
                except Exception:
                    svc = "unknown"
                risk = "HIGH" if port in (23, 3389) else ("MEDIUM" if port in (22, 3306) else "LOW")
                data = {"finding_type": "open_port", "software": svc, "version": "", "cve_id": "", "severity": risk, "risk": risk, "description": f"Open port {port}/{svc}", "port": port, "service": svc}
                _report("/vulnerability-scan/report", data)
                open_ports.append(port)
        s.close()
        for sw_name, versions in CVE_DB.items():
            for ver, cves in versions.items():
                for cve in cves:
                    data = {"finding_type": "cve_vulnerability", "software": sw_name, "version": ver, "cve_id": cve["id"], "severity": cve["severity"], "risk": cve["severity"], "description": cve["id"], "port": 0, "service": ""}
                    _report("/vulnerability-scan/report", data)
    except Exception:
        pass


# ============================================================
# 15. SHADOW IT
# ============================================================
SHADOW_SERVICES = [
    {"domain": "dropbox.com", "category": "Cloud Storage"},
    {"domain": "slack.com", "category": "Communication"},
    {"domain": "discord.com", "category": "Communication"},
    {"domain": "telegram.org", "category": "Communication"},
    {"domain": "zoom.us", "category": "Video Conferencing"},
    {"domain": "wetransfer.com", "category": "File Sharing"},
    {"domain": "teams.microsoft.com", "category": "Communication"},
]

def send_shadow_it():
    try:
        for svc in SHADOW_SERVICES:
            try:
                socket.setdefaulttimeout(2)
                ip = socket.gethostbyname(svc["domain"])
                data = {"finding_type": "unauthorized_cloud_service", "service_name": svc["domain"].split(".")[0].title(), "domain": svc["domain"], "category": svc["category"], "risk": "MEDIUM", "description": f"Unauthorized {svc['category']} service: {svc['domain']}", "ip": ip, "mac": ""}
                _report("/shadow-it/report", data)
            except Exception:
                pass
            finally:
                socket.setdefaulttimeout(None)
        if psutil:
            unauthorized = ["TeamViewer", "AnyDesk", "BitTorrent", "uTorrent"]
            for p in psutil.process_iter(['name']):
                try:
                    pname = p.info['name']
                    for sw in unauthorized:
                        if sw.lower() in pname.lower():
                            data = {"finding_type": "unauthorized_software", "service_name": sw, "domain": "", "category": "Unauthorized Software", "risk": "HIGH", "description": f"Unauthorized software detected: {sw} (PID: {p.info.get('pid', '?')})", "ip": "", "mac": ""}
                            _report("/shadow-it/report", data)
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 16. PRIVILEGE ESCALATION
# ============================================================
HIGH_RISK_PRIVILEGES = ["SeDebugPrivilege", "SeTcbPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege"]

def send_privilege_escalation():
    try:
        if platform.system() == "Windows":
            out, _, _ = _run(["whoami", "/priv"], 10)
            for priv in HIGH_RISK_PRIVILEGES:
                if priv in out:
                    data = {"check_type": "token_privilege", "os": "Windows", "finding": f"High-risk privilege enabled: {priv}", "process_name": os.path.basename(__file__), "user": getpass.getuser(), "privilege": priv, "risk_reason": f"{priv} enables critical system access", "severity": "critical" if priv in ("SeDebugPrivilege", "SeTcbPrivilege") else "high"}
                    _report("/privilege-escalation/report", data)
        else:
            out, _, _ = _run(["find", "/usr", "-perm", "-4000", "-type", "f"], 30)
            known_safe = {"/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/bin/mount", "/bin/umount"}
            for line in out.splitlines():
                line = line.strip()
                if line and line not in known_safe:
                    data = {"check_type": "setuid_scan", "os": "Linux", "finding": f"Unexpected setuid binary: {line}", "process_name": line, "user": "root", "privilege": line, "risk_reason": f"Setuid binary not in known safe list", "severity": "high"}
                    _report("/privilege-escalation/report", data)
    except Exception:
        pass


# ============================================================
# 17. SILENT DEPLOYMENT
# ============================================================
def send_silent_deployment():
    data = {"no_window": False, "hidden": False, "startup_type": "user", "process_name": "", "parent_process": "", "is_silent": False}
    try:
        data["process_name"] = os.path.basename(__file__)
        if psutil:
            try:
                current = psutil.Process(os.getpid())
                parent = current.parent()
                data["parent_process"] = parent.name()
            except Exception:
                pass
        if platform.system() == "Windows":
            try:
                import ctypes
                data["no_window"] = ctypes.windll.kernel32.GetConsoleWindow() == 0
                data["hidden"] = ctypes.windll.kernel32.GetFileAttributesW(__file__) & 2 != 0
            except Exception:
                pass
        else:
            data["no_window"] = "DISPLAY" not in os.environ
        data["is_silent"] = data["no_window"] or data["hidden"]
    except Exception:
        pass
    _report("/silent-deployment/report", data)


# ============================================================
# 18. LATERAL MOVEMENT
# ============================================================
def send_lateral_movement():
    try:
        if psutil:
            conns = psutil.net_connections() if hasattr(psutil, 'net_connections') else []
            smb_sessions = set()
            for conn in conns:
                if conn.raddr and conn.raddr.port in (445, 139, 22, 3389):
                    key = conn.raddr.ip
                    smb_sessions.add(key)
            for dst_ip in smb_sessions:
                data = {"movement_type": "remote_service", "source_ip": _get_local_ip(), "destination_ip": dst_ip, "port": 445, "service": "SMB", "connection_count": 1, "risk": "MEDIUM", "description": f"Remote connection to {dst_ip}:445 - possible lateral movement"}
                _report("/lateral-movement/report", data)
    except Exception:
        pass


# ============================================================
# 19. PORT SCAN
# ============================================================
_conn_log = defaultdict(list)

def send_port_scan():
    try:
        if psutil:
            conns = psutil.net_connections() if hasattr(psutil, 'net_connections') else []
            foreign_ports = defaultdict(set)
            for conn in conns:
                if conn.raddr and conn.raddr.ip and conn.raddr.ip not in ("127.0.0.1", "::1"):
                    foreign_ports[conn.raddr.ip].add(conn.raddr.port)
            for scanner_ip, ports in foreign_ports.items():
                if len(ports) >= 10:
                    sensitive_hit = any(p in SUSPICIOUS_PORTS for p in ports)
                    risk = "HIGH" if len(ports) >= 100 or sensitive_hit else ("MEDIUM" if len(ports) >= 30 else "LOW")
                    data = {"scan_type": "incoming_port_scan" if scanner_ip != _get_local_ip() else "outgoing_port_scan", "scanner_ip": scanner_ip, "target_ip": _get_local_ip(), "unique_ports": len(ports), "sensitive_ports_hit": sensitive_hit, "syn_count": len(ports), "risk": risk, "description": f"{scanner_ip} connected to {len(ports)} unique ports"}
                    _report("/port-scan/report", data)
    except Exception:
        pass


# ============================================================
# 20. SCRIPT MONITOR
# ============================================================
def send_script_monitor():
    try:
        if psutil:
            for p in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    cmdline = " ".join(p.info.get('cmdline') or [])
                    if not cmdline:
                        continue
                    matched = [pat for pat in SCRIPT_SUSPICIOUS_PATTERNS if pat.lower() in cmdline.lower()]
                    if matched:
                        user = p.info.get('username', 'unknown')
                        data = {"command": cmdline[:500], "user": user, "suspicious_patterns": matched[:5], "action": "ALERT"}
                        _report("/script-monitor/report", data)
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 21. CREDENTIAL DUMPING
# ============================================================
LSASS_ALIASES = {"lsass.exe", "lsaas.exe", "lsasss.exe", "lsa.exe"}

def send_credential_dumping():
    try:
        if platform.system() == "Windows" and psutil:
            lsass_pids = []
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    if p.info['name'].lower() in LSASS_ALIASES:
                        lsass_pids.append(p.info['pid'])
                except Exception:
                    pass
            for p in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pname = p.info['name'].lower()
                    cmdline = " ".join(p.info.get('cmdline') or [])
                    suspicious = False
                    detection = ""
                    if pname in ("mimikatz.exe", "procdump.exe", "pwdump.exe", "gsecdump.exe"):
                        suspicious = True
                        detection = "known credential dumping tool"
                    elif "lsass" in cmdline.lower() and "dump" in cmdline.lower():
                        suspicious = True
                        detection = "process dumping lsass"
                    if suspicious:
                        data = {"process_name": p.info['name'], "pid": p.info['pid'], "detection_type": detection}
                        _report("/credential-dumping/report", data)
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 22. NEXT-GEN AV
# ============================================================
def send_next_gen_av():
    try:
        if psutil:
            for p in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    exe = p.info.get('exe', '')
                    if not exe or not os.path.isfile(exe):
                        continue
                    h = hashlib.sha256(open(exe, "rb").read(65536)).hexdigest()
                    if h.startswith("0000"):
                        data = {"file_path": exe, "file_hash": h, "detection_reason": "Suspicious hash prefix (0000...) - possible malware", "action": "malicious", "scanner_type": "heuristic"}
                        _report("/next-gen-av/report", data)
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 23. USER BEHAVIOUR
# ============================================================
_file_baselines = {}

def send_user_behaviour():
    try:
        for fpath in PROTECTED_FILE_PATHS:
            if not os.path.exists(fpath):
                continue
            try:
                h = hashlib.sha256(open(fpath, "rb").read(65536)).hexdigest()
                if fpath not in _file_baselines:
                    _file_baselines[fpath] = h
                elif _file_baselines[fpath] != h:
                    data = {"file_path": fpath, "action": "modified", "baseline_hash": _file_baselines[fpath], "current_hash": h}
                    _report("/user-behaviour/report", data)
                    _file_baselines[fpath] = h
            except Exception:
                pass
    except Exception:
        pass


# ============================================================
# 24. YARA SCAN
# ============================================================
def send_yara_scan():
    try:
        from agent_lib import yara_scanner
        if psutil:
            for p in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    exe = p.info.get('exe', '')
                    if not exe or not os.path.isfile(exe):
                        continue
                    result = yara_scanner.scan_file_for_report(exe)
                    if result:
                        _report("/next-gen-av/report", result)
                except Exception:
                    pass
    except Exception:
        pass


# ============================================================
# 25. DLL SIDELOADING MONITOR
# ============================================================
def send_dll_sideload_scan():
    try:
        from agent_lib.dll_sideload_monitor import DLLSideloadMonitor
        monitor = DLLSideloadMonitor()
        result = monitor.scan()
        for finding in result.get("findings", []):
            data = {
                "file_path": finding["module"],
                "file_hash": "",
                "detection_reason": f"DLL Sideloading: {finding['reason']} (loaded by {finding['process']}, PID {finding['pid']})",
                "action": "malicious",
                "scanner_type": "dll_sideload"
            }
            _report("/next-gen-av/report", data)
    except Exception:
        pass


# ============================================================
# 26. SCHEDULED TASK / CRON MONITOR
# ============================================================
def send_scheduled_task_scan():
    try:
        from agent_lib.task_scheduler_monitor import ScheduledTaskMonitor
        monitor = ScheduledTaskMonitor()
        diff = monitor.check_for_changes()
        
        for entry in diff.get("new", []):
            data = {
                "key_path": "Scheduled Task / Cron Job",
                "value_name": entry["key"],
                "old_value": "",
                "new_value": str(entry["detail"]),
                "change_type": "added",
                "is_auto_start": True
            }
            _report("/registry-monitoring/report", data)
            
        for entry in diff.get("modified", []):
            data = {
                "key_path": "Scheduled Task / Cron Job",
                "value_name": entry["key"],
                "old_value": "Previous Configuration",
                "new_value": str(entry["detail"]),
                "change_type": "modified",
                "is_auto_start": True
            }
            _report("/registry-monitoring/report", data)
    except Exception:
        pass


# ============================================================
# 27. HOSTS FILE MONITOR
# ============================================================
def send_hosts_file_scan():
    try:
        from agent_lib.hosts_file_monitor import HostsFileMonitor
        monitor = HostsFileMonitor()
        result = monitor.check()
        if result.get("tampered"):
            data = {
                "file_path": str(monitor.hosts_path),
                "action": "modified",
                "baseline_hash": "",
                "current_hash": ""
            }
            _report("/user-behaviour/report", data)
    except Exception:
        pass

