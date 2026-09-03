"""
Feature: Hosts File Tampering Detection
-----------------------------------------
Detects unauthorized entries in the hosts file (used for DNS hijacking).

Approach: save a baseline (file hash + parsed entries) when the system
is known clean, then periodically compare current state against it.

Implemented purely with file hashing/diffing - no kernel access needed.
"""

import platform
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime

IS_WINDOWS = platform.system() == "Windows"

# Well-known domains attackers commonly hijack via hosts file redirection
HIGH_VALUE_DOMAINS = {
    "google.com", "facebook.com", "microsoft.com", "windowsupdate.com",
    "paypal.com", "bankofamerica.com", "chase.com"
}


class HostsFileMonitor:

    def __init__(self, baseline_file="hosts_baseline.json"):
        self.hosts_path = (
            Path(r"C:\Windows\System32\drivers\etc\hosts") if IS_WINDOWS
            else Path("/etc/hosts")
        )
        if not os.path.isabs(baseline_file):
            baseline_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", baseline_file)
        self.baseline_file = Path(baseline_file)

    def _read_entries(self):
        """Parse hosts file into a normalized set of (ip, hostname) tuples."""
        entries = set()
        if not self.hosts_path.exists():
            return entries
        for line in self.hosts_path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip, hostnames = parts[0], parts[1:]
                for h in hostnames:
                    entries.add((ip, h.lower()))
        return entries

    def _file_hash(self):
        if not self.hosts_path.exists():
            return None
        return hashlib.sha256(self.hosts_path.read_bytes()).hexdigest()

    def set_baseline(self):
        """Call this once, when the system is known to be clean."""
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        baseline = {
            "timestamp": datetime.utcnow().isoformat(),
            "hash": self._file_hash(),
            "entries": sorted(list(self._read_entries())),
        }
        self.baseline_file.write_text(json.dumps(baseline, indent=2))
        return baseline

    def check(self):
        """Compare current hosts file against saved baseline."""
        if not self.baseline_file.exists():
            self.set_baseline()

        try:
            baseline = json.loads(self.baseline_file.read_text())
        except Exception:
            baseline = self.set_baseline()
            
        current_hash = self._file_hash()
        current_entries = self._read_entries()
        baseline_entries = set(tuple(e) for e in baseline["entries"])

        added = current_entries - baseline_entries
        removed = baseline_entries - current_entries

        # Flag with higher priority if a known/high-value domain was hijacked
        flagged = [e for e in added if any(d in e[1] for d in HIGH_VALUE_DOMAINS)]

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "tampered": current_hash != baseline["hash"],
            "added_entries": list(added),
            "removed_entries": list(removed),
            "high_risk_hijacks": flagged,
        }


if __name__ == "__main__":
    monitor = HostsFileMonitor()
    if not monitor.baseline_file.exists():
        monitor.set_baseline()
        print("Baseline created.")
    else:
        result = monitor.check()
        print(json.dumps(result, indent=2))
