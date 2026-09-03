import hashlib
import os
import platform
import sys
import threading
import time
import uuid
from typing import Dict, List
from urllib.parse import urlparse

import psutil
import requests
import yaml

from config import (
    AGENT_POLL_INTERVAL,
    AGENT_HASH_INTERVAL,
    VIRUSTOTAL_API_KEY,
)

# --- Agent Library Imports ---
from agent_lib.logger import log
from agent_lib.network_monitor import (
    get_network_connections,
    get_suspicious_connections,
    get_rare_external_connections,
    get_connection_domain_intel,
)
from agent_lib.behavioral import (
    detect_encoded_powershell,
    detect_download_execute,
    detect_temp_execution,
    detect_script_file,
    detect_lolbin,
    detect_office_macro,
    detect_credential_dumping,
    detect_suspicious_service_or_task,
    calculate_risk_score,
    generate_alert,
    rerank_finding,
)
from agent_lib.intel_submitter import IntelSubmitter, start_background_worker, submit_background
from agent_lib.beaconing import BeaconingDetector
from agent_lib.domain_intel import DomainIntel
from agent_lib.detections import run_all_detections as run_advanced_detections
from agent_lib.correlation import CorrelationEngine
from agent_lib.timeline import InvestigationTimeline
from agent_lib.diagnostics import configure as configure_diagnostics
from agent_lib.ransomware_canary import check_canaries, deploy_canaries
from agent_lib.exploit_mitigation import check_mitigations
from agent_lib.host_firewall import check_firewall
from agent_lib.web_dns_filter import check_web_dns
import agent_lib.all_features as all_features

# --- Optional feature imports (graceful fallback) ---
FILE_MONITOR_AVAILABLE = False
PERSISTENCE_MONITOR_AVAILABLE = False
try:
    from agent_lib.file_monitor import FileMonitor
    FILE_MONITOR_AVAILABLE = True
except ImportError:
    FileMonitor = None

try:
    from agent_lib.persistence_monitor import PersistenceMonitor
    PERSISTENCE_MONITOR_AVAILABLE = True
except ImportError:
    PersistenceMonitor = None

# --- Configuration ---
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "agent_config.yaml")
_CFG = {
    "backend_url": "http://localhost:8080",
    "poll_interval": AGENT_POLL_INTERVAL,
    "hash_scan_interval": AGENT_HASH_INTERVAL,
    "log_level": "INFO",
    "log_dir": "logs",
    "enable_network_monitoring": True,
    "enable_file_monitoring": True,
    "enable_persistence_monitoring": True,
    "enable_threat_intel": True,
    "enable_beaconing_detection": True,
    "enable_domain_intel": True,
    "enable_correlation": True,
    "enable_timeline": True,
    "enable_advanced_detections": True,
    "enable_ransomware_canary": True,
    "enable_exploit_mitigation": True,
    "enable_host_firewall": True,
    "enable_web_dns_filter": True,
    "enable_installation_visibility": True,
    "enable_patch_monitoring": True,
    "enable_behavioral_heuristics": True,
    "enable_misconfigurations": True,
    "enable_software_inventory": True,
    "enable_watchdog_status": True,
    "enable_telemetry": True,
    "enable_zero_day_findings": True,
    "enable_buffer_polish": True,
    "enable_fileless_detection": True,
    "enable_memory_scan": True,
    "enable_usb_disk_control": True,
    "enable_c2_beaconing": True,
    "enable_offline_scan": True,
    "enable_vulnerability_scan": True,
    "enable_shadow_it": True,
    "enable_privilege_escalation": True,
    "enable_silent_deployment": True,
    "enable_lateral_movement": True,
    "enable_port_scan": True,
    "enable_script_monitor": True,
    "enable_credential_dumping": True,
    "enable_next_gen_av": True,
    "enable_user_behaviour": True,
    "enable_yara_scanning": True,
    "yara_rules_dir": "yara_rules",
    "enable_dll_sideload_monitor": True,
    "enable_task_scheduler_monitor": True,
    "enable_hosts_file_monitor": True,
}
try:
    with open(CONFIG_PATH, "r") as f:
        cfg = yaml.safe_load(f) or {}
        _CFG.update(cfg)
except Exception:
    pass

BACKEND = _CFG["backend_url"].rstrip("/")
AGENT_ID = None
API_TOKEN = None
AGENT_TOKEN = None
_intel = None  # Initialized in main() after post() is defined

AGENT_ID_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__) or "."), "agent.id")
AGENT_TOKEN_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__) or "."), "agent.token")

def load_agent_id():
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE) as f:
            aid = f.read().strip()
            if aid:
                log.info("Loaded saved agent ID", agent_id=aid)
                return aid
    return None

def save_agent_id(aid):
    with open(AGENT_ID_FILE, "w") as f:
        f.write(aid.strip())
    log.info("Saved agent ID", agent_id=aid)

def load_agent_token():
    if os.path.exists(AGENT_TOKEN_FILE):
        with open(AGENT_TOKEN_FILE) as f:
            tok = f.read().strip()
            if tok:
                log.info("Loaded saved agent token")
                return tok
    return None

def save_agent_token(tok):
    with open(AGENT_TOKEN_FILE, "w") as f:
        f.write(tok.strip())
    log.info("Saved agent token")

# Process hash throttle: path -> (sha256, last_mtime)
_hash_mtime_cache: Dict[str, tuple[str, float]] = {}

# --- Telemetry Queue & Batching ---
_telemetry_queue = []
_backend_online = True
_MAX_QUEUE_SIZE = 5000


class TelemetryBatcher:
    """Accumulates telemetry events and flushes in configurable batches.

    Flush triggers:
      - queue reaches *batch_size* events
      - *force=True* called from the main loop timer (every 30 s)

    On final failure (after 3 retries) items are persisted to the
    global ``_telemetry_queue`` for later retry.
    """

    def __init__(self, batch_size: int = 50):
        self._batch: List[tuple[str, dict]] = []
        self._batch_size = batch_size
        self._lock = threading.Lock()
        self._sent_count = 0

    def add(self, path: str, data: dict):
        """Queue a telemetry event; flush if batch is full."""
        with self._lock:
            self._batch.append((path, data))
            if len(self._batch) >= self._batch_size:
                self._flush_locked()

    def flush(self):
        """Explicit flush — called from main loop timer."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self):
        if not self._batch:
            return
        batch = self._batch[:]
        self._batch.clear()
        sent = 0
        for path, data in batch:
            r = post(path, data, max_retries=3)
            if r is not None:
                sent += 1
        self._sent_count += sent
        if sent:
            log.debug("Batch sent", count=sent, total=self._sent_count)
        failed = len(batch) - sent
        if failed:
            log.debug("Batch persisted",
                      count=failed,
                      reason="backend_timeout")


_telemetry_batcher = TelemetryBatcher()


# --- New Engine Instances ---
_beaconing = BeaconingDetector(
    window_seconds=_CFG.get("beaconing_window_seconds", 300),
    min_connections=_CFG.get("beaconing_min_connections", 5),
    max_jitter_pct=_CFG.get("beaconing_max_jitter", 0.25),
)
_domain_intel = DomainIntel()
_correlation = CorrelationEngine()
_timeline = InvestigationTimeline()

_KOWN_DOMAINS = {"microsoft.com", "google.com", "github.com", "stackoverflow.com", "python.org"}
_TRUSTED_PATH_PREFIXES = (
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Windows\\servicing\\",
    "C:\\Windows\\Microsoft.NET\\",
)
_verdict_cache: Dict[str, int] = {}


# --- Fault Tolerance ---

def health_check():
    global _backend_online
    try:
        r = requests.get(build_url("/health"), timeout=(5, 12))
        if r.status_code == 200:
            if not _backend_online:
                log.info("Backend connection restored")
                _backend_online = True
            return True
    except requests.exceptions.ConnectionError:
        if _backend_online:
            log.warn("Backend connection lost")
            _backend_online = False
    except Exception:
        pass
    return _backend_online


def flush_queue():
    if not _telemetry_queue or not _backend_online:
        return
    sent = 0
    remaining = []
    for item in _telemetry_queue:
        _, path, data, _ = item
        try:
            r = requests.post(build_url(path), json=data, timeout=(5, 12))
            if r.status_code in (200, 201, 202):
                sent += 1
                continue
        except Exception:
            pass
        remaining.append(item)
    if sent:
        log.info(f"Flushed {sent} queued telemetry events")
    _telemetry_queue[:] = remaining


# --- Existing Functions (kept unchanged) ---

def get_mac():
    n = uuid.getnode()
    return ':'.join(f"{(n >> i) & 0xff:02x}" for i in range(40, -8, -8))


def build_url(path: str) -> str:
    """Resolve *path* against BACKEND, supporting both relative and absolute URLs."""
    parsed = urlparse(path)
    if parsed.scheme and parsed.netloc:
        return path  # already absolute
    return f"{BACKEND}/{path.lstrip('/')}"


RETRY_BACKOFFS = [0, 1, 2]  # seconds between retries

def post(path, data, max_retries=3):
    global _backend_online
    last_exc = None
    url = build_url(path)
    t_start = time.time()
    headers = {}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    if AGENT_TOKEN:
        headers["X-Agent-Token"] = AGENT_TOKEN
    log.debug(f"HTTP POST | url={url} data_size={len(str(data))}")
    for attempt in range(max_retries):
        try:
            r = requests.post(url, json=data, headers=headers, timeout=(5, 12))
            elapsed = time.time() - t_start
            log.debug(f"HTTP POST done | url={url} latency={elapsed:.3f}s attempt={attempt+1}")
            if not _backend_online:
                _backend_online = True
                log.info("Backend connection restored")
            return r.json()
        except requests.exceptions.ConnectionError as e:
            last_exc = e
            log.debug(f"HTTP POST attempt {attempt+1} failed | url={url} error=ConnectionError")
            if _backend_online:
                log.warn("Backend unavailable, queuing telemetry", path=path)
                _backend_online = False
        except requests.exceptions.Timeout as e:
            last_exc = e
            log.debug(f"HTTP POST attempt {attempt+1} failed | url={url} error=Timeout")
            if _backend_online:
                log.warn("Backend timeout", path=path, attempt=attempt+1)
        except requests.exceptions.RequestException as e:
            last_exc = e
            log.debug(f"HTTP POST attempt {attempt+1} failed | url={url} error=RequestException")
            if _backend_online:
                log.warn("Backend request error", path=path, error=str(e))
        except Exception as e:
            log.error("POST failed", path=path, error=str(e))
            return {}
        if attempt < max_retries - 1:
            backoff = RETRY_BACKOFFS[attempt] if attempt < len(RETRY_BACKOFFS) else 2
            if backoff > 0:
                log.debug(f"HTTP POST retry {attempt+2} in {backoff}s | url={url}")
                time.sleep(backoff)
    if last_exc:
        if len(_telemetry_queue) < _MAX_QUEUE_SIZE:
            _telemetry_queue.append(("POST", path, data, time.time()))
            log.warn("Telemetry queued after retries", path=path)
    return {}


def hash_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def check_virustotal(file_hash):
    if not VIRUSTOTAL_API_KEY:
        return False
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=(3, 5)
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return stats["malicious"] > 0
    except Exception:
        pass
    return False


def register():
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    data = {
        "hostname":     platform.node(),
        "os_type":      platform.system(),
        "os_version":   platform.version(),
        "cpu_model":    platform.processor(),
        "cpu_cores":    psutil.cpu_count(logical=False) or 1,
        "ram_total_gb": vm.total // (1024 ** 3),
        "disk_total_gb": disk.total // (1024 ** 3),
        "mac_address":  get_mac(),
        "ip_address":   "",
    }
    headers = {}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    try:
        r = requests.post(build_url("/api/agents/register"), json=data, headers=headers, timeout=(3, 5))
        if r.status_code == 401:
            log.error("Registration rejected (401) — check API token")
            return None
        body = r.json()
        agent_id = body.get("id")
        agent_token = body.get("agent_token")
        if agent_token:
            global AGENT_TOKEN
            AGENT_TOKEN = agent_token
            save_agent_token(agent_token)
        ott = body.get("one_time_token")
        log.info("Registered with backend", agent_id=agent_id)
        if ott:
            print("\n" + "=" * 64)
            print("  NEW AGENT REGISTERED — claim it from your dashboard")
            print("=" * 64)
            print(f"  Hostname:        {platform.node()}")
            print(f"  One-time token:  {ott}")
            print("  Go to Settings > Claim Agent in the dashboard,")
            print("  log in, and enter the hostname + token above.")
            print("=" * 64 + "\n")
        return agent_id
    except Exception as e:
        log.error("Registration failed", error=str(e))
        return None


def _report(path_suffix, data):
    """Queue a telemetry report through the batcher."""
    _telemetry_batcher.add(f"/api/agents/{AGENT_ID}{path_suffix}", data)


def fetch_and_execute_actions():
    """Poll the backend for pending actions and execute them."""
    try:
        resp = requests.get(build_url(f"/api/agents/{AGENT_ID}/pending-actions"), timeout=(3, 5))
        if resp.status_code != 200:
            return
        data = resp.json()
        actions = data.get("actions", [])
        if not actions:
            return
        from agent_lib.action_dispatcher import execute_action
        for action in actions:
            act = action.get("action", "")
            target = action.get("target", "")
            result = execute_action(act, target)
            log.info("Fetched and executed action", action=act, target=target, status=result.get("status"))
            _report("/action-result/report", {"action": act, "target": target, "result": result, "executed_at": time.time()})
    except Exception as e:
        log.debug("Fetch actions failed", error=str(e))


def send_monitoring():
    _report("/monitoring-logs/report", {
        "cpu_percent":      psutil.cpu_percent(interval=1),
        "ram_percent":      psutil.virtual_memory().percent,
        "interval_seconds": _CFG["poll_interval"],
    })


def send_processes():
    raw = []
    for p in psutil.process_iter(
        ['pid', 'name', 'ppid', 'cmdline', 'cpu_percent', 'memory_info', 'username', 'exe']
    ):
        try:
            path = p.info['exe'] or ""
            file_hash = ""
            if path:
                cached = _hash_mtime_cache.get(path)
                if cached is not None:
                    file_hash = cached[0]
                else:
                    file_hash = hash_file(path)
                    try:
                        current_mtime = os.path.getmtime(path)
                    except OSError:
                        current_mtime = 0
                    _hash_mtime_cache[path] = (file_hash, current_mtime)

            raw.append({
                "pid":         p.info['pid'],
                "ppid":        p.info['ppid'],
                "name":        p.info['name'] or "",
                "cmdline":     " ".join(p.info['cmdline'] or []),
                "path":        path,
                "user":        p.info['username'] or "",
                "cpu_percent": p.info['cpu_percent'] or 0.0,
                "memory_mb":   (p.info['memory_info'].rss / 1024 / 1024)
                                if p.info['memory_info'] else 0.0,
                "hash":        file_hash,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    try:
        from tracker.tracker import ProcessTreeTracker
        from tracker.utils.event import EventEmitter

        tracker = ProcessTreeTracker(EventEmitter())
        tracker.all_processes = [{
            "pid": p["pid"], "ppid": p["ppid"],
            "name": p["name"], "cmdline": p["cmdline"], "path": p["path"]
        } for p in raw]
        tracker.build_tree()

        findings = (
            tracker.detect_suspicious_parent_child() +
            tracker.detect_suspicious_process_names() +
            tracker.detect_temp_directory_processes()
        )

        # Build child/parent lookup for reranking
        child_by_pid = {p["pid"]: p for p in raw}
        parent_by_pid = {p["pid"]: p for p in raw}

        for f in findings:
            # Rerank parent-child findings to reduce false positives
            child_pid = f.get("child_pid", 0)
            parent_pid = f.get("parent_pid", 0)
            child_proc = child_by_pid.get(child_pid)
            parent_proc = parent_by_pid.get(parent_pid)
            f = rerank_finding(f, child_proc, parent_proc)

            _report("/process-tree/report", {
                "finding_type": f.get("type", ""),
                "parent_name":  f.get("parent_name", ""),
                "parent_pid":   parent_pid,
                "child_name":   f.get("child_name", ""),
                "child_pid":    child_pid,
                "risk":         f.get("risk", "LOW"),
                "description":  f.get("description", ""),
                "cmdline":      f.get("child_cmdline", ""),
            })
            risk = f.get("risk", "LOW")
            if risk in ("HIGH", "CRITICAL"):
                log.warn("Process tree alert", risk=risk, desc=f.get("description"))
            elif risk in ("MEDIUM",):
                log.info("Process tree alert", risk=risk, desc=f.get("description"))
            if _CFG.get("enable_timeline", True):
                _timeline.add_event(
                    "behavioral_alert",
                    f.get("description", ""),
                    risk,
                    {"finding": f},
                )

    except Exception as e:
        log.warn("Tracker error", error=str(e))

    # --- Behavioral detection on collected processes ---
    # Build parent lookup
    parent_map = {p["pid"]: p for p in raw}
    if _CFG.get("enable_threat_intel", True):
        # Collect all detections per process for correlation
        process_detections: Dict[int, List[dict]] = {}
        for p in raw:
            detections = []
            cmdline = p.get("cmdline", "")
            proc_path = p.get("path", "")
            proc_name = p.get("name", "")
            pid = p.get("pid", 0)

            ed = detect_encoded_powershell(cmdline)
            if ed:
                detections.append(ed)
            dd = detect_download_execute(cmdline)
            if dd:
                detections.append(dd)
            td = detect_temp_execution(proc_path)
            if td:
                detections.append(td)
            sd = detect_script_file(proc_path)
            if sd:
                detections.append(sd)

            # --- Advanced detections ---
            if _CFG.get("enable_advanced_detections", True):
                parent_pid = p.get("ppid", 0)
                parent = parent_map.get(parent_pid, {})
                parent_name = parent.get("name", "")
                parent_cmdline = parent.get("cmdline", "")

                ld = detect_lolbin(proc_name, cmdline, proc_path)
                if ld:
                    detections.append(ld)
                cd = detect_credential_dumping(cmdline)
                if cd:
                    detections.append(cd)
                st = detect_suspicious_service_or_task(cmdline)
                if st:
                    detections.append(st)
                om = detect_office_macro(parent_name, proc_name)
                if om:
                    detections.append(om)
                pl = detect_lolbin(parent_name, parent_cmdline, "")
                if pl:
                    pl["description"] = f"Parent LOLBin: {pl['description']}"
                    detections.append(pl)

            if detections:
                process_detections.setdefault(pid, []).extend(detections)

        # Correlate: send one unified alert per process with all detections
        for pid, detections in process_detections.items():
            alert = generate_alert(detections)
            if not alert:
                continue
            p = parent_map.get(pid) or next(
                (x for x in raw if x["pid"] == pid), {}
            )
            proc_name = p.get("name", "")
            cmdline = p.get("cmdline", "")
            risk_label = alert["severity"]
            detection_names = [d.get("rule", d.get("description", "unknown"))[:30]
                               for d in detections]
            _report("/process-tree/report", {
                "finding_type": "_".join(alert["rules"]),
                "parent_name":  "",
                "parent_pid":   0,
                "child_name":   proc_name,
                "child_pid":    pid,
                "risk":         risk_label,
                "description":  alert["description"],
                "cmdline":      cmdline[:500],
            })
            log.warn("Behavioral alert",
                     rule=",".join(alert["rules"]),
                     risk=risk_label,
                     process=proc_name,
                     detections=detection_names)

            if _CFG.get("enable_correlation", True):
                for d in detections:
                    d["process_name"] = proc_name
                    _correlation.add_finding(d)

            if _CFG.get("enable_timeline", True):
                _timeline.add_alert_event(alert)

    # Report the raw process list to backend
    try:
        _report("/processes/report", {"processes": raw})
    except Exception as e:
        log.warn("Failed to report processes list", error=str(e))

    log.debug(f"Processes sent ({len(raw)} total)")


def send_network():
    if not _CFG.get("enable_network_monitoring", True):
        return
    connections = get_network_connections()

    # --- Port-based suspicious connections ---
    suspicious = get_suspicious_connections(connections)
    reported_count = 0
    seen_intel_ips = set()
    for conn in suspicious:
        remote_ip = conn.get("remote_ip", "")
        report_data = {
            "src_ip":      conn.get("local_ip", ""),
            "dst_ip":      remote_ip,
            "src_port":    conn.get("local_port", 0),
            "dst_port":    conn.get("remote_port", 0),
            "protocol":    conn.get("protocol", "TCP"),
            "reason":      conn.get("suspicious_reason", ""),
            "payload_size": 0,
            "threat_type": "suspicious_connection",
        }
        _report("/network-dpi/report", report_data)
        reported_count += 1

        if remote_ip and remote_ip not in seen_intel_ips and _CFG.get("enable_threat_intel", True):
            seen_intel_ips.add(remote_ip)
            _intel.submit_ip(remote_ip, conn.get("process_name", ""), conn.get("suspicious_reason", ""))

        # --- Domain intel enrichment ---
        if _CFG.get("enable_domain_intel", True) and remote_ip:
            domain_info = _domain_intel.enrich_connection(remote_ip)
            if domain_info.get("is_dynamic_dns"):
                log.warn("Dynamic DNS connection", ip=remote_ip, hostname=domain_info.get("hostname"))
                report_data["threat_type"] = "dynamic_dns_connection"
                _report("/network-dpi/report", report_data)
            if domain_info.get("is_suspicious_tld"):
                log.warn("Suspicious TLD connection", hostname=domain_info.get("hostname"))

    # --- Beaconing detection ---
    if _CFG.get("enable_beaconing_detection", True):
        for conn in connections:
            remote_ip = conn.get("remote_ip", "")
            if not remote_ip:
                continue
            proc_name = conn.get("process_name", "")
            remote_port = conn.get("remote_port", 0)
            beacon_alert = _beaconing.analyze_connection(proc_name, remote_ip, remote_port)
            if beacon_alert:
                log.warn("Beaconing detected",
                         process=proc_name,
                         ip=remote_ip,
                         interval=beacon_alert.get("mean_interval"))
                _report("/network-dpi/report", {
                    "src_ip":      conn.get("local_ip", ""),
                    "dst_ip":      remote_ip,
                    "src_port":    conn.get("local_port", 0),
                    "dst_port":    remote_port,
                    "protocol":    conn.get("protocol", "TCP"),
                    "reason":      beacon_alert["description"],
                    "payload_size": 0,
                    "threat_type": "beaconing",
                })
                if _CFG.get("enable_correlation", True):
                    beacon_alert["process_name"] = proc_name
                    _correlation.add_finding(beacon_alert)
                if _CFG.get("enable_timeline", True):
                    _timeline.add_alert_event(beacon_alert)

    # Report the raw network connections list to backend
    try:
        _report("/network/report", {"connections": connections})
    except Exception as e:
        log.warn("Failed to report network connections list", error=str(e))

    log.debug(f"Network checked — {len(connections)} connections, {reported_count} suspicious")



def send_process_hashes():
    global _hash_mtime_cache
    seen = set()
    hashed_count = 0
    for p in psutil.process_iter(['name', 'exe']):
        try:
            path = p.info['exe']
            if not path or path in seen:
                continue
            seen.add(path)

            # Mtime check — skip if unchanged
            try:
                current_mtime = os.path.getmtime(path)
            except OSError:
                current_mtime = 0
            cached = _hash_mtime_cache.get(path)
            if cached is not None:
                cached_hash, cached_mtime = cached
                if current_mtime > 0 and current_mtime == cached_mtime:
                    file_hash = cached_hash
                else:
                    file_hash = hash_file(path)
                    _hash_mtime_cache[path] = (file_hash, current_mtime)
            else:
                file_hash = hash_file(path)
                _hash_mtime_cache[path] = (file_hash, current_mtime)

            if not file_hash:
                continue

            # Trusted binary noise reduction
            is_trusted = path.lower().startswith(tuple(p.lower() for p in _TRUSTED_PATH_PREFIXES))

            # Skip if trusted and verdict is known (0=clean) or pending (-1=submitted)
            if is_trusted and _verdict_cache.get(file_hash) in (0, -1):
                continue

            log.info("File detected", event_type="hash_scan", path=path, filename=p.info['name'])
            log.info("SHA256 generated", hash=file_hash)
            hashed_count += 1
            _report("/pre-execution-events/report", {
                "process_name": p.info['name'],
                "process_path": path,
                "file_hash":    file_hash,
                "blocked":      False,
                "reason":       "periodic_hash_scan",
            })

            # Only submit for lookup if verdict not yet known
            if _CFG.get("enable_threat_intel", True):
                if file_hash not in _verdict_cache and _intel.should_submit(path):
                    _verdict_cache[file_hash] = -1  # mark as pending immediately
                    submit_background(file_hash, path)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Prune stale cache entries
    if len(_hash_mtime_cache) > 5000:
        current_paths = set(seen)
        _hash_mtime_cache = {k: v for k, v in _hash_mtime_cache.items() if k in current_paths}

    log.debug(f"Hashes sent ({hashed_count} hashed, {len(_hash_mtime_cache)} cached)")


def send_asset_info():
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    post(f"/api/agents/{AGENT_ID}/asset-discovery/report", {
        "hostname":    platform.node(),
        "os_type":     platform.system(),
        "os_version":  platform.version(),
        "processor":   platform.processor(),
        "cpu_cores":   psutil.cpu_count(logical=False) or 1,
        "ram_gb":      vm.total / (1024 ** 3),
        "disk_total_gb": disk.total / (1024 ** 3),
        "disk_used_gb":  disk.used / (1024 ** 3),
        "mac_address": get_mac(),
    })
    log.info("Asset info sent")


def send_installation_visibility():
    if not _CFG.get("enable_installation_visibility", True):
        return
    import getpass
    vm = psutil.virtual_memory()
    install_path = os.path.abspath(os.path.dirname(__file__))
    data = {
        "boot_time": str(psutil.boot_time()),
        "install_path": install_path,
        "running_as_username": getpass.getuser(),
        "running_as_admin": False,
        "os_name": platform.system(),
        "os_release": platform.version(),
        "os_machine": platform.machine(),
        "hostname": platform.node(),
        "agent_version": "3.7.0",
    }
    try:
        import ctypes
        data["running_as_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        try:
            data["running_as_admin"] = os.geteuid() == 0
        except AttributeError:
            data["running_as_admin"] = False
    _report("/installation-visibility/report", data)
    log.info("Installation visibility sent")


# --- Ransomware Canary ---
def send_ransomware_canary():
    if not _CFG.get("enable_ransomware_canary", True):
        return
    events = check_canaries()
    for ev in events:
        _report("/ransomware-canary/report", ev)


# --- Exploit Mitigation ---
def send_exploit_mitigation():
    if not _CFG.get("enable_exploit_mitigation", True):
        return
    result = check_mitigations()
    _report("/exploit-mitigation/report", result)


# --- Host Firewall ---
_sent_firewall_rules = set()
def send_host_firewall():
    if not _CFG.get("enable_host_firewall", True):
        return
    events = check_firewall()
    for ev in events:
        key = f"{ev.get('chain', '')}:{ev.get('ip_blocked', '')}"
        if key not in _sent_firewall_rules:
            _sent_firewall_rules.add(key)
            _report("/host-firewall/report", ev)


# --- Web/DNS Filter ---
_sent_dns_blocks = set()
def send_web_dns_filter():
    if not _CFG.get("enable_web_dns_filter", True):
        return
    events = check_web_dns()
    for ev in events:
        key = ev.get("domain", "") or ev.get("url", "")
        if key and key not in _sent_dns_blocks:
            _sent_dns_blocks.add(key)
            _report("/web-dns-filter/report", ev)


# --- File Monitoring ---
_file_monitor = None
if FILE_MONITOR_AVAILABLE and _CFG.get("enable_file_monitoring", True):
    try:
        _file_monitor = FileMonitor(platform.system().lower())
        log.info("File monitor initialized")
    except Exception as e:
        log.warn("File monitor init failed", error=str(e))


def is_in_temp_dir(path: str) -> bool:
    if not path:
        return False
    normalized = os.path.normcase(os.path.abspath(path))
    
    # Standard Temp Dir
    import tempfile
    temp_roots = {
        os.path.normcase(tempfile.gettempdir()),
        os.path.normcase(r"C:\Windows\Temp"),
        os.path.normcase(r"C:\Temp"),
        os.path.normcase(r"/tmp"),
        os.path.normcase(r"/var/tmp")
    }
    # Add from environment variables just in case
    for env_var in ("TEMP", "TMP"):
        val = os.environ.get(env_var)
        if val:
            temp_roots.add(os.path.normcase(os.path.abspath(val)))
            
    for root in temp_roots:
        if normalized.startswith(root):
            return True
            
    # Also check if the string contains "\appdata\local\temp\" or "\temp\" or "\tmp\"
    if any(p in normalized for p in ("\\appdata\\local\\temp\\", "\\temp\\", "\\tmp\\", "/tmp/", "/temp/")):
        return True
        
    return False


def send_file_events():
    if not _file_monitor:
        return
    if not _CFG.get("enable_file_monitoring", True):
        _file_monitor.drain_events()
        return
    raw_events = _file_monitor.drain_events()
    events = [ev for ev in raw_events if ev.get("file_path") and not is_in_temp_dir(ev["file_path"])]
    if not events:
        return
    changed_files = []
    seen_intel_paths = set()
    for ev in events:
        fpath = ev["file_path"]
        changed_files.append(fpath)

        # YARA scanning
        if _CFG.get("enable_yara_scanning", True):
            h = ev.get("sha256", "")
            try:
                from agent_lib import yara_scanner
                yara_result = yara_scanner.scan_file_for_report(fpath, sha256=h)
                if yara_result:
                    if not yara_result.get("file_hash"):
                        from agent_lib.file_monitor import hash_file_sha256
                        yara_result["file_hash"] = hash_file_sha256(fpath)
                    log.warn("YARA match", path=fpath, rules=yara_result["matched_rules"])
                    _report("/next-gen-av/report", yara_result)
            except Exception as ex:
                log.debug("YARA inline scan failed", error=str(ex))

        if ev.get("is_executable") and _CFG.get("enable_threat_intel", True):
            h = ev.get("sha256", "")
            log.info("File detected (event)",
                     event_type=ev.get("event_type", "unknown"),
                     path=fpath, filename=ev.get("file_name", ""))
            if not h:
                log.debug("File skipped", reason="no_hash", path=fpath)
                continue
            if fpath in seen_intel_paths:
                log.debug("File skipped", reason="already_seen", path=fpath)
                continue
            seen_intel_paths.add(fpath)
            if not _intel.should_submit(fpath):
                log.debug("File skipped", reason="not_submittable", path=fpath)
                continue
            log.info("SHA256 generated (event)", hash=h)
            submit_background(h, fpath)
    if changed_files:
        _report("/file-integrity/report", {
            "monitored_files": [],
            "changes_detected": True,
            "changed_files": changed_files,
            "severity": "medium",
        })
        log.debug(f"File events sent ({len(events)} events)")
        if _CFG.get("enable_timeline", True):
            for ev in events:
                _timeline.add_event(
                    "file_created" if ev.get("change_type") == "created" else "file_modified",
                    f"File {ev.get('change_type')}: {ev.get('file_name')}",
                    "MEDIUM" if ev.get("is_executable") else "INFO",
                    ev,
                )


# --- Persistence Monitoring ---
_persistence_monitor = None
if PERSISTENCE_MONITOR_AVAILABLE and _CFG.get("enable_persistence_monitoring", True):
    try:
        _persistence_monitor = PersistenceMonitor()
        log.info("Persistence monitor initialized")
    except Exception as e:
        log.warn("Persistence monitor init failed", error=str(e))


def send_persistence_report():
    if not _persistence_monitor:
        return
    try:
        changes = _persistence_monitor.scan()
        for change in changes:
            log.warn("New persistence entry detected", type=change.get("type"))
            _report("/registry-monitoring/report", {
                "key_path":    change.get("key", ""),
                "value_name":  change.get("value", ""),
                "old_value":   "",
                "new_value":   change.get("data", ""),
                "change_type": "added",
                "is_auto_start": True,
            })
            if _CFG.get("enable_timeline", True):
                _timeline.add_event(
                    "persistence_added",
                    f"New persistence: {change.get('type')} — {change.get('path', change.get('key', ''))}",
                    "HIGH",
                    change,
                )
        log.debug(f"Persistence scan complete ({len(changes)} new entries)")
    except Exception as e:
        log.warn("Persistence scan failed", error=str(e))


# --- New: Correlated Threats ---
def send_correlated_threats():
    if not _CFG.get("enable_correlation", True):
        return
    alerts = _correlation.get_recent_alerts(max_age=300)
    for alert in alerts:
        _report("/threat-intel/report", {
            "threat_type": alert["threat_type"],
            "risk_score": alert["risk_score"],
            "severity": alert["severity"],
            "mitre_techniques": alert["mitre_techniques"],
            "processes": alert["processes"],
            "indicator_count": alert["indicator_count"],
        })
        log.warn("Correlated threat reported",
                 type=alert["threat_type"],
                 score=alert["risk_score"],
                 severity=alert["severity"])
        if _CFG.get("enable_timeline", True):
            _timeline.add_event(
                "correlated_threat",
                f"{alert['threat_type']} — {alert['severity']} ({alert['risk_score']})",
                alert["severity"],
                alert,
            )
    if alerts:
        log.debug(f"Correlated threats sent ({len(alerts)} alerts)")


# --- New: Timeline Sync ---
def send_timeline():
    if not _CFG.get("enable_timeline", True):
        return
    events = _timeline.get_timeline_since(seconds=_CFG["poll_interval"] * 3)
    if events:
        _report("/threat-intel/report", {
            "threat_type": "investigation_timeline",
            "risk_score": 0,
            "severity": "info",
            "events": events,
            "event_count": len(events),
        })
        log.debug(f"Timeline events sent ({len(events)} events)")


# --- Windows Service Support ---
def install_service():
    if platform.system().lower() != "windows":
        log.error("Service install is Windows-only")
        return
    try:
        import win32serviceutil
        import servicemanager
        import win32service
        import win32event

        class AgentSecurityService(win32serviceutil.ServiceFramework):
            _svc_name_ = "AgentSecurityEDR"
            _svc_display_name_ = "Agent Security EDR Agent"
            _svc_description_ = "Endpoint Detection and Response agent for the Agent Security platform"

            def __init__(self, args):
                super().__init__(args)
                self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.hWaitStop)

            def SvcDoRun(self):
                servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                     servicemanager.PYS_SERVICE_STARTED,
                                     (self._svc_name_, ""))
                main()

        win32serviceutil.HandleCommandLine(AgentSecurityService)
    except ImportError:
        log.error("pywin32 not installed. Run: pip install pywin32")



def update_agent_policies_from_backend():
    try:
        url = build_url("/api/policies")
        headers = {}
        if API_TOKEN:
            headers["Authorization"] = f"Bearer {API_TOKEN}"
        if AGENT_TOKEN:
            headers["X-Agent-Token"] = AGENT_TOKEN
            
        r = requests.get(url, headers=headers, timeout=(3, 5))
        if r.status_code == 200:
            policies = r.json()
            # Map frontend keys to agent _CFG keys
            mapping = {
                "realtime":     ["enable_file_monitoring", "enable_behavioral_heuristics", "enable_yara_scanning", "enable_dll_sideload_monitor", "enable_hosts_file_monitor"],
                "firewall":     ["enable_host_firewall"],
                "usbControl":   ["enable_usb_disk_control"],
                "webFilter":    ["enable_web_dns_filter"],
                "appControl":   ["enable_advanced_detections", "enable_software_inventory", "enable_task_scheduler_monitor"],
                "scriptControl":["enable_script_monitor"],
                "ransomware":   ["enable_ransomware_canary"],
                "networkIntel": ["enable_threat_intel", "enable_c2_beaconing", "enable_domain_intel", "enable_network_monitoring"]
            }
            for ui_key, agent_keys in mapping.items():
                if ui_key in policies:
                    val = policies[ui_key]
                    is_enabled = val == "true" or val is True
                    for a_key in agent_keys:
                        if a_key in _CFG and _CFG[a_key] != is_enabled:
                            _CFG[a_key] = is_enabled
                            log.info(f"Policy updated dynamically | {a_key}={is_enabled}")
    except Exception as e:
        log.debug("Failed to update agent policies from backend", error=str(e))


# --- Main Entry Point ---
def main():
    global AGENT_ID, AGENT_TOKEN, _intel

    log.info("Agent starting", version="3.7.0", backend=BACKEND, auth=bool(API_TOKEN))
    _intel = IntelSubmitter(BACKEND, post_func=post)
    start_background_worker(_intel)
    configure_diagnostics(enabled=_CFG.get("enable_diagnostics", False))

    AGENT_ID = load_agent_id()
    AGENT_TOKEN = load_agent_token()
    if AGENT_ID:
        # Verify the saved ID & token are still valid — if not 200, re-register
        headers = {"X-Agent-Token": AGENT_TOKEN} if AGENT_TOKEN else {}
        try:
            r = requests.get(build_url(f"/api/agents/{AGENT_ID}/pending-actions"), headers=headers, timeout=(2, 3))
            if r.status_code != 200:
                log.warn("Saved agent credentials rejected by backend, re-registering")
                AGENT_ID = None
                AGENT_TOKEN = None
        except Exception:
            log.warn("Could not verify saved agent credentials with backend")

    if not AGENT_ID:
        AGENT_ID = register()
        if not AGENT_ID:
            log.error("Could not register with backend. Is main.py running?")
            return
        save_agent_id(AGENT_ID)

    all_features.init(_report, AGENT_ID)

    # Initialize YARA scanner
    try:
        from agent_lib import yara_scanner
        rules_dir = _CFG.get("yara_rules_dir", "yara_rules")
        if not os.path.isabs(rules_dir):
            rules_dir = os.path.join(os.path.dirname(__file__), rules_dir)
        yara_scanner.init(rules_dir=rules_dir)
    except Exception as e:
        log.error("Failed to initialize YARA scanner", error=str(e))

    # Initialize baselines for hosts and tasks monitors
    try:
        from agent_lib.hosts_file_monitor import HostsFileMonitor
        from agent_lib.task_scheduler_monitor import ScheduledTaskMonitor
        hosts_mon = HostsFileMonitor()
        if not hosts_mon.baseline_file.exists():
            hosts_mon.set_baseline()
            log.info("Hosts file baseline initialized")
        task_mon = ScheduledTaskMonitor()
        if not task_mon.state_file.exists():
            # Create first snapshot
            task_mon.check_for_changes()
            log.info("Scheduled task baseline snapshot initialized")
    except Exception as e:
        log.error("Failed to initialize baseline monitors", error=str(e))



    from agent_lib.action_dispatcher import register_callback
    def on_demand_scan_handler(scan_type):
        log.info(f"Starting on-demand scan: {scan_type}")
        send_processes()
        send_process_hashes()
        send_persistence_report()
        send_file_events()
        return {"status": "success", "message": f"On-demand scan {scan_type} completed"}
    register_callback("run_scan", on_demand_scan_handler)

    send_asset_info()
    send_installation_visibility()
    if _CFG.get("enable_ransomware_canary", True):
        deploy_canaries()

    # Start file monitor (background thread)
    if _file_monitor:
        try:
            _file_monitor.start()
            log.info("File monitor started")
        except Exception as e:
            log.warn("File monitor start failed", error=str(e))

    cycle = 0
    hash_interval_cycles = max(1, _CFG["hash_scan_interval"] // _CFG["poll_interval"])
    health_interval = max(1, 30 // _CFG["poll_interval"])
    flush_interval = max(1, 15 // _CFG["poll_interval"])

    while True:
        log.debug(f"Cycle {cycle}")

        if _backend_online:
            update_agent_policies_from_backend()

        if not _backend_online:
            if cycle % health_interval == 0:
                health_check()

        send_monitoring()
        send_processes()
        send_network()
        send_persistence_report()
        send_file_events()
        send_ransomware_canary()
        send_exploit_mitigation()
        send_host_firewall()
        send_web_dns_filter()
        send_correlated_threats()
        send_timeline()
        # --- All 23 features ---
        if _CFG.get("enable_patch_monitoring", True): all_features.send_patch_monitoring()
        if _CFG.get("enable_behavioral_heuristics", True): all_features.send_behavioral_heuristics()
        if _CFG.get("enable_misconfigurations", True): all_features.send_misconfigurations()
        if _CFG.get("enable_software_inventory", True): all_features.send_software_inventory()
        if _CFG.get("enable_watchdog_status", True): all_features.send_watchdog_status()
        if _CFG.get("enable_telemetry", True): all_features.send_telemetry()
        if _CFG.get("enable_zero_day_findings", True): all_features.send_zero_day_findings()
        if _CFG.get("enable_buffer_polish", True): all_features.send_buffer_polish()
        if _CFG.get("enable_fileless_detection", True): all_features.send_fileless_detection()
        if _CFG.get("enable_memory_scan", True): all_features.send_memory_scan()
        if _CFG.get("enable_usb_disk_control", True): all_features.send_usb_disk_control()
        if _CFG.get("enable_c2_beaconing", True): all_features.send_c2_beaconing()
        if _CFG.get("enable_offline_scan", True): all_features.send_offline_scan()
        if _CFG.get("enable_vulnerability_scan", True): all_features.send_vulnerability_scan()
        if _CFG.get("enable_shadow_it", True): all_features.send_shadow_it()
        if _CFG.get("enable_privilege_escalation", True): all_features.send_privilege_escalation()
        if _CFG.get("enable_silent_deployment", True): all_features.send_silent_deployment()
        if _CFG.get("enable_lateral_movement", True): all_features.send_lateral_movement()
        if _CFG.get("enable_port_scan", True): all_features.send_port_scan()
        if _CFG.get("enable_script_monitor", True): all_features.send_script_monitor()
        if _CFG.get("enable_credential_dumping", True): all_features.send_credential_dumping()
        if _CFG.get("enable_next_gen_av", True): all_features.send_next_gen_av()
        if _CFG.get("enable_yara_scanning", True): all_features.send_yara_scan()
        if _CFG.get("enable_dll_sideload_monitor", True): all_features.send_dll_sideload_scan()
        if _CFG.get("enable_task_scheduler_monitor", True): all_features.send_scheduled_task_scan()
        if _CFG.get("enable_hosts_file_monitor", True): all_features.send_hosts_file_scan()
        if _CFG.get("enable_user_behaviour", True): all_features.send_user_behaviour()

        if cycle % hash_interval_cycles == 0:
            send_process_hashes()

        # Poll backend for pending response actions every cycle
        fetch_and_execute_actions()

        if _telemetry_queue and cycle % flush_interval == 0:
            flush_queue()

        # Flush telemetry batch every cycle (~30s)
        _telemetry_batcher.flush()

        cycle += 1
        time.sleep(_CFG["poll_interval"])


if __name__ == "__main__":
    # Parse --token before command check
    API_TOKEN = None
    i = 1
    cmd = None
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--token" and i + 1 < len(sys.argv):
            API_TOKEN = sys.argv[i + 1]
            log.info("Using API token for authentication")
            i += 2
        elif arg.startswith("--"):
            i += 1
        else:
            cmd = arg.lower()
            i += 1
    # Service commands
    if cmd == "--rebuild-baseline":
        from agent_lib.persistence_monitor import rebuild_baseline
        rebuild_baseline()
        log.info("Baseline rebuilt — run agent normally for differential alerts")
        sys.exit(0)
    if cmd:
        if cmd == "install":
            install_service()
        elif cmd == "start":
            os.system("net start AgentSecurityEDR")
        elif cmd == "stop":
            os.system("net stop AgentSecurityEDR")
        elif cmd == "uninstall":
            try:
                import win32serviceutil
                win32serviceutil.RemoveService("AgentSecurityEDR")
                log.info("Service uninstalled")
            except ImportError:
                log.error("pywin32 not installed")
        else:
            log.error("Unknown command", command=cmd)
            print("Usage: agent.py [install|start|stop|uninstall|--rebuild-baseline]")
        sys.exit(0)

    main()
