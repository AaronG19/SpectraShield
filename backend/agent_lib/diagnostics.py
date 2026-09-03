import threading
import time
from typing import Optional

from agent_lib.logger import log

_DIAGNOSTICS_ENABLED = False
_lock = threading.Lock()

# Counters
_cache_hits = 0
_cache_misses = 0
_lookups_total = 0
_lookups_failed = 0
_latency_total = 0.0


def configure(enabled: bool = False):
    global _DIAGNOSTICS_ENABLED
    _DIAGNOSTICS_ENABLED = enabled


def is_enabled() -> bool:
    return _DIAGNOSTICS_ENABLED


# --- Intel lookup diagnostics ---

def record_cache_hit():
    if not _DIAGNOSTICS_ENABLED:
        return
    global _cache_hits
    with _lock:
        _cache_hits += 1


def record_cache_miss():
    if not _DIAGNOSTICS_ENABLED:
        return
    global _cache_misses
    with _lock:
        _cache_misses += 1


def record_lookup_complete(latency: float, failed: bool = False):
    if not _DIAGNOSTICS_ENABLED:
        return
    global _lookups_total, _lookups_failed, _latency_total
    with _lock:
        _lookups_total += 1
        _latency_total += latency
        if failed:
            _lookups_failed += 1


def log_lookup(indicator: str, ioc_type: str, file_path: str, result: Optional[dict], latency: float):
    if not _DIAGNOSTICS_ENABLED:
        return
    status = "HIT" if result and result.get("cached") else "MISS" if result else "FAIL"
    if file_path:
        log.info("[DIAG] Intel lookup",
                 indicator=indicator[:16],
                 type=ioc_type,
                 file_path=file_path,
                 status=status,
                 latency=f"{latency:.3f}s")
    else:
        log.info("[DIAG] Intel lookup",
                 indicator=indicator[:16],
                 type=ioc_type,
                 status=status,
                 latency=f"{latency:.3f}s")


def log_cache(indicator: str, hit: bool):
    if not _DIAGNOSTICS_ENABLED:
        return
    log.info("[DIAG] Cache", indicator=indicator[:16], hit=hit)
    if hit:
        record_cache_hit()
    else:
        record_cache_miss()


def log_persistence_diff(baseline_count: int, new_count: int, removed_count: int, reasons: list):
    if not _DIAGNOSTICS_ENABLED:
        return
    log.info("[DIAG] Persistence diff",
             baseline=baseline_count,
             new_entries=new_count,
             removed_entries=removed_count)
    for r in reasons:
        log.info("[DIAG] Persistence alert reason", reason=r)


def summary() -> dict:
    if not _DIAGNOSTICS_ENABLED:
        return {}
    with _lock:
        avg_latency = _latency_total / max(_lookups_total, 1)
        return {
            "cache_hits": _cache_hits,
            "cache_misses": _cache_misses,
            "lookups_total": _lookups_total,
            "lookups_failed": _lookups_failed,
            "avg_latency": round(avg_latency, 3),
        }
