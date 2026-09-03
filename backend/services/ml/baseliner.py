from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
import statistics


class BehavioralBaseliner:
    def __init__(self, window_days: int = 30, std_dev_threshold: float = 3.0):
        self.window_days = window_days
        self.std_dev_threshold = std_dev_threshold
        self._baselines: Dict[str, Dict[str, Any]] = {}
        self._history: Dict[str, List[dict]] = defaultdict(list)

    def update(self, agent_id: str, metrics: Dict[str, float]):
        self._history[agent_id].append({
            **metrics,
            "_timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self._prune_old(agent_id)
        self._recalculate(agent_id)

    def _prune_old(self, agent_id: str):
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.window_days)
        self._history[agent_id] = [
            h for h in self._history[agent_id]
            if datetime.fromisoformat(h["_timestamp"]) > cutoff
        ]

    def _recalculate(self, agent_id: str):
        history = self._history.get(agent_id, [])
        if len(history) < 5:
            return

        numeric_keys = [k for k in history[0].keys() if k != "_timestamp"]
        baseline = {}
        for key in numeric_keys:
            values = [h[key] for h in history if isinstance(h.get(key), (int, float))]
            if len(values) >= 5:
                baseline[key] = {
                    "mean": statistics.mean(values),
                    "stdev": statistics.stdev(values) if len(values) > 1 else 0,
                    "min": min(values),
                    "max": max(values),
                    "count": len(values),
                }
        if baseline:
            self._baselines[agent_id] = baseline

    def get_baseline(self, agent_id: str) -> Optional[Dict[str, Any]]:
        return self._baselines.get(agent_id)

    def is_anomalous(self, agent_id: str, metrics: Dict[str, float]) -> Tuple[bool, Dict[str, Any]]:
        baseline = self._baselines.get(agent_id)
        if not baseline:
            return False, {"reason": "Insufficient baseline data"}

        anomalies = {}
        for key, value in metrics.items():
            bl = baseline.get(key)
            if bl and bl["stdev"] > 0:
                z_score = abs(value - bl["mean"]) / bl["stdev"]
                if z_score > self.std_dev_threshold:
                    anomalies[key] = {
                        "value": value,
                        "mean": bl["mean"],
                        "stdev": bl["stdev"],
                        "z_score": round(z_score, 2),
                    }

        is_anomaly = len(anomalies) > 0
        return is_anomaly, {
            "is_anomalous": is_anomaly,
            "anomalies": anomalies,
            "threshold": self.std_dev_threshold,
            "baseline_samples": baseline.get(next(iter(baseline)), {}).get("count", 0) if baseline else 0,
        }

    def get_agent_status(self, agent_id: str) -> dict:
        baseline = self._baselines.get(agent_id)
        history = self._history.get(agent_id, [])
        return {
            "agent_id": agent_id,
            "has_baseline": baseline is not None,
            "sample_count": len(history),
            "baseline": baseline,
            "features": list(baseline.keys()) if baseline else [],
        }

    def reset_agent(self, agent_id: str):
        self._baselines.pop(agent_id, None)
        self._history.pop(agent_id, None)
