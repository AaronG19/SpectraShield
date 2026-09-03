"""
Security Agent Monitoring Module
---------------------------------
Three defensive detection features:
  1. Scheduled Task / Cron Job monitoring (persistence detection)
  2. Hosts file tampering detection (DNS hijack detection)
  3. DLL sideloading detection (unsigned/unexpected module loads)

Requires: psutil  (pip install psutil --break-system-packages)
"""

import json
from agent_lib.task_scheduler_monitor import ScheduledTaskMonitor
from agent_lib.hosts_file_monitor import HostsFileMonitor
from agent_lib.dll_sideload_monitor import DLLSideloadMonitor

if __name__ == "__main__":
    # --- Scheduled Task / Cron monitoring ---
    task_mon = ScheduledTaskMonitor()
    diff = task_mon.check_for_changes()
    print("[Scheduled Task Monitor]", json.dumps(diff, indent=2)[:500])

    # --- Hosts file monitoring ---
    hosts_mon = HostsFileMonitor()
    if not hosts_mon.baseline_file.exists():
        hosts_mon.set_baseline()
        print("[Hosts Monitor] Baseline created.")
    else:
        result = hosts_mon.check()
        print("[Hosts Monitor]", json.dumps(result, indent=2)[:500])

    # --- DLL sideload detection ---
    dll_mon = DLLSideloadMonitor()
    findings = dll_mon.scan()
    print("[DLL Sideload Monitor]", json.dumps(findings, indent=2)[:500])
