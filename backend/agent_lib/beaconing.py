import time
from collections import defaultdict
from typing import Dict, List, Optional

from agent_lib.logger import log


class BeaconingDetector:
    def __init__(self, window_seconds: int = 300, min_connections: int = 5, max_jitter_pct: float = 0.25):
        self._window = window_seconds
        self._min_conn = min_connections
        self._max_jitter = max_jitter_pct
        self._history: Dict[str, List[float]] = defaultdict(list)

    def analyze_connection(self, process_name: str, remote_ip: str, remote_port: int) -> Optional[dict]:
        if not remote_ip:
            return None
        key = f"{process_name}|{remote_ip}:{remote_port}"
        now = time.time()
        self._history[key].append(now)
        timestamps = self._history[key]
        cutoff = now - self._window
        timestamps[:] = [t for t in timestamps if t >= cutoff]

        if len(timestamps) < self._min_conn:
            return None

        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals:
            return None

        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            return None

        max_dev = max(abs(i - mean_interval) for i in intervals)
        jitter = max_dev / mean_interval

        if jitter <= self._max_jitter:
            return {
                "rule": "c2_beaconing",
                "risk_score": 45,
                "severity": "HIGH",
                "mitre_id": "T1071",
                "mitre_technique": "Application Layer Protocol",
                "description": (
                    f"Beaconing detected: {process_name} -> {remote_ip}:{remote_port} "
                    f"({len(timestamps)} connections, ~{mean_interval:.1f}s interval, "
                    f"{jitter*100:.0f}% jitter)"
                ),
                "process_name": process_name,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "connection_count": len(timestamps),
                "mean_interval": round(mean_interval, 1),
                "jitter": round(jitter, 3),
            }
        return None

    def get_stats(self) -> dict:
        return {
            "monitored_endpoints": len(self._history),
            "tracked_connections": sum(len(v) for v in self._history.values()),
        }
