import os
import queue
import re
import threading
import time
from typing import Dict, List, Optional, Tuple

import requests

from agent_lib.logger import log
from agent_lib.diagnostics import log_cache, log_lookup


# Only these extensions are submitted for threat intelligence lookups
SUBMITTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd",
                          ".vbs", ".js", ".hta", ".scr", ".msi"}
INTEL_CACHE_TTL = 86400  # 24 hours (legacy, kept for backward compat)

# Per-lookup cache: 10-minute TTL
_LOOKUP_CACHE_TTL = 600  # 10 minutes
_lookup_cache: Dict[str, Tuple[Optional[dict], float]] = {}
_lookup_cache_lock = threading.Lock()

# Per-indicator cooldown — 10 s minimum between same-indicator lookups
_indicator_cooldowns: Dict[str, float] = {}
_indicator_cooldown_lock = threading.Lock()
_INDICATOR_COOLDOWN = 30  # seconds — suppress duplicates within 30s

# Concurrency limit — at most 5 concurrent lookups
_lookup_semaphore = threading.Semaphore(5)

# Rate limiter — minimum 200 ms between lookups
_last_lookup_time: float = 0
_rate_limit_lock = threading.Lock()
_MIN_LOOKUP_INTERVAL = 0.2


# Domains commonly used for dynamic DNS (indicative of C2)
DYNAMIC_DNS_DOMAINS = {
    "duckdns.org", "no-ip.org", "noip.com", "dyndns.org",
    "dyn.com", "dnsdynamic.org", "changeip.com", "free-my-ip.com",
    "myftp.org", "myftp.biz", "ddns.net", "servehttp.com",
    "servehttps.com", "serveftp.com", "serveftp.net", "servegame.com",
    "serveminecraft.net", "sytes.net", "zapto.org", "zapto.net",
    "hopto.org", "hopto.net", "strangled.net", "blogdns.com",
    "dnsalias.com", "dnsalias.net", "dnsdojo.com", "dnsdojo.net",
    "dynalias.org", "dynalias.net", "dynalias.com",
}

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".gq", ".ml", ".cf", ".tk", ".work"}


class IntelSubmitter:
    def __init__(self, backend_url: str, post_func=None):
        self._backend_url = backend_url.rstrip("/")
        self._reported_indicators: set = set()
        self._reputation_cache: Dict[str, int] = {}  # indicator -> score
        self._hash_cache: Dict[str, Tuple[Optional[dict], float]] = {}  # sha256 -> (result, timestamp)
        self._post = post_func or self._direct_post

    @staticmethod
    def _direct_post(url, json, timeout=None):
        return requests.post(url, json=json, timeout=timeout or (5, 12))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_key(indicator: str) -> str:
        return indicator.strip().lower()

    @classmethod
    def _get_cached_lookup(cls, indicator: str) -> Optional[dict]:
        key = cls._cache_key(indicator)
        with _lookup_cache_lock:
            entry = _lookup_cache.get(key)
            if entry is None:
                return None
            result, ts = entry
            if time.time() - ts < _LOOKUP_CACHE_TTL:
                return result
            del _lookup_cache[key]
            return None

    @classmethod
    def _set_cached_lookup(cls, indicator: str, result: Optional[dict]):
        key = cls._cache_key(indicator)
        with _lookup_cache_lock:
            _lookup_cache[key] = (result, time.time())
            if len(_lookup_cache) > 10000:
                cutoff = time.time() - _LOOKUP_CACHE_TTL
                stale = [k for k, v in _lookup_cache.items() if v[1] < cutoff]
                for k in stale:
                    del _lookup_cache[k]

    def _rate_limit(self):
        """Ensure at least ``_MIN_LOOKUP_INTERVAL`` between successive lookups."""
        global _last_lookup_time
        with _rate_limit_lock:
            elapsed = time.time() - _last_lookup_time
            if elapsed < _MIN_LOOKUP_INTERVAL:
                time.sleep(_MIN_LOOKUP_INTERVAL - elapsed)
            _last_lookup_time = time.time()

    def _relative_path(self, url: str) -> str:
        """Strip the backend base URL, leaving only the relative path."""
        base = self._backend_url.rstrip("/")
        if url.startswith(base):
            return url[len(base):] or "/"
        return url

    def _post_json(self, url: str, payload: dict):
        """Send a JSON POST via the configured post function.

        Two conventions supported:
          * ``_direct_post(url, json=payload, timeout=…)`` — absolute URL
          * agent ``post(path, data)``  —  relative path only

        When the agent-style fallback is used the absolute *url* is
        converted back to a relative path so that ``post()`` does not
        prepend BACKEND a second time.
        """
        try:
            r = self._post(url, json=payload, timeout=(5, 12))
        except TypeError:
            # Agent post(path, data) — strip the backend prefix to avoid
            # double URL construction: http://localhost:8080 + http://...
            rel = self._relative_path(url)
            r = self._post(rel, payload)
        return r

    # ------------------------------------------------------------------
    # Public API — preserved signatures
    # ------------------------------------------------------------------

    @staticmethod
    def should_submit(file_path: str) -> bool:
        if not file_path:
            return False
        _, ext = os.path.splitext(file_path)
        ext_lower = ext.lower()
        if ext_lower in SUBMITTABLE_EXTENSIONS:
            return True
        if ext_lower:
            log.debug("Intel lookup skipped", reason="non_executable extension", extension=ext_lower)
        return False

    # --- Legacy hash cache (used by existing tests) ---

    def _get_cached_hash(self, file_hash: str) -> Optional[dict]:
        entry = self._hash_cache.get(file_hash)
        if entry is None:
            return None
        result, ts = entry
        if time.time() - ts < INTEL_CACHE_TTL:
            return result
        del self._hash_cache[file_hash]
        return None

    def _set_cached_hash(self, file_hash: str, result: Optional[dict]):
        self._hash_cache[file_hash] = (result, time.time())
        if len(self._hash_cache) > 10000:
            cutoff = time.time() - INTEL_CACHE_TTL
            self._hash_cache = {k: v for k, v in self._hash_cache.items() if v[1] >= cutoff}

    # --- Core lookup with caching, concurrency control, error handling ---

    def _perform_lookup(self, indicator: str, payload: dict, ioc_type: str,
                        score_fn) -> Optional[dict]:
        """Shared lookup logic — called by *submit_ip*, *submit_hash*, *submit_domain*."""
        cache_key = self._cache_key(indicator)

        # 1. Shared cache (10 min TTL)
        cached = self._get_cached_lookup(indicator)
        if cached is not None:
            log.debug(f"Threat lookup cache HIT | {ioc_type}={indicator[:16]}")
            log_cache(indicator, True)
            return cached
        log_cache(indicator, False)

        # 2. Per-indicator cooldown (10 s minimum between lookups of same indicator)
        with _indicator_cooldown_lock:
            last_ts = _indicator_cooldowns.get(cache_key, 0)
            remaining = _INDICATOR_COOLDOWN - (time.time() - last_ts)
            if remaining > 0:
                log.debug(f"Threat lookup cooldown | {ioc_type}={indicator[:16]} "
                          f"retry_in={remaining:.1f}s")
                # Try legacy cache fallback
                if indicator in self._reported_indicators:
                    return self._cached_result(indicator, ioc_type)
                return None
            _indicator_cooldowns[cache_key] = time.time()
            # Prune cooldown map
            if len(_indicator_cooldowns) > 10000:
                cutoff = time.time() - _INDICATOR_COOLDOWN
                _indicator_cooldowns.clear()

        # 3. Legacy per-instance dedup
        if indicator in self._reported_indicators:
            return self._cached_result(indicator, ioc_type)
        self._reported_indicators.add(indicator)

        # 4. Global rate-limit
        self._rate_limit()

        # 5. Concurrency gate
        acquired = _lookup_semaphore.acquire(timeout=15)
        if not acquired:
            log.warn("Intel lookup throttled", indicator=indicator[:16], type=ioc_type)
            return None

        try:
            url = f"{self._backend_url}/api/threats/lookup"
            t_start = time.time()
            log.debug(f"Threat lookup started | {ioc_type}={indicator[:16]}")
            r = self._post_json(url, payload)
            elapsed = time.time() - t_start
            log.debug(f"Threat lookup completed in {elapsed:.3f}s | {ioc_type}={indicator[:16]}")
            log.info("Intel request duration",
                     indicator=indicator[:16], type=ioc_type, latency=f"{elapsed:.3f}s")

            if r is None:
                log.warn("Intel lookup failed", indicator=indicator[:16], error="no response")
                return None

            # Normalise response — agent post() returns a dict;
            # requests.Response needs .json() parsing.
            if isinstance(r, dict):
                result = r
            elif hasattr(r, "json"):
                try:
                    result = r.json()
                except ValueError:
                    log.warn("Intel lookup failed",
                             indicator=indicator[:16], error="invalid JSON response")
                    return None
                # HTTP errors
                if hasattr(r, "status_code"):
                    if r.status_code >= 500:
                        log.warn("Intel lookup failed",
                                 indicator=indicator[:16], error=f"HTTP {r.status_code}")
                        return None
                    if r.status_code >= 400:
                        log.warn("Intel lookup failed",
                                 indicator=indicator[:16], error=f"HTTP {r.status_code} (client error)")
                        return None
            else:
                result = r

            if not isinstance(result, dict):
                log.warn("Intel lookup failed",
                         indicator=indicator[:16], error="unexpected response type")
                return None

            found = result.get("found", False)
            score = score_fn(result) if callable(score_fn) else 0

            response: dict = {
                "indicator": indicator,
                "type": ioc_type,
                "found": found,
                "score": score,
            }
            if result.get("cached"):
                response["cached"] = True
            if found:
                response["result"] = result

            # Update both cache layers
            self._set_cached_lookup(indicator, response)
            self._reputation_cache[indicator] = score

            # Only log "success" on a genuinely successful response
            log.info("Intel lookup success",
                     indicator=indicator[:16],
                     type=ioc_type,
                     score=score,
                     latency=f"{elapsed:.3f}s")
            log_lookup(indicator, ioc_type, "", response, elapsed)

            return response

        except requests.exceptions.Timeout:
            log.warn("Intel lookup failed",
                     indicator=indicator[:16], error="network timeout")
            log_lookup(indicator, ioc_type, "", None, time.time() - t_start)
            return None
        except requests.exceptions.ConnectionError:
            log.warn("Intel lookup failed",
                     indicator=indicator[:16], error="connection failure")
            log_lookup(indicator, ioc_type, "", None, time.time() - t_start)
            return None
        except Exception as e:
            log.warn("Intel lookup failed",
                     indicator=indicator[:16], error=str(e))
            log_lookup(indicator, ioc_type, "", None, time.time() - t_start)
            return None
        finally:
            _lookup_semaphore.release()

    # --- Score calculators (preserved from original) ---

    def _calculate_ip_reputation(self, ip: str, result: dict) -> int:
        score = 0
        if result.get("found"):
            score += 40
        if result.get("malicious", False):
            score += 30
        return min(score, 100)

    def _calculate_hash_reputation(self, result: dict) -> int:
        score = 0
        if result.get("found"):
            score += 40
        positive = result.get("positives", 0) or 0
        total = result.get("total", 0) or 1
        detection_ratio = positive / total
        score += int(detection_ratio * 50)
        return min(score, 100)

    def _calculate_domain_reputation(self, domain: str, result: dict) -> int:
        score = 0
        if result.get("found"):
            score += 40
        domain_lower = domain.lower()
        parts = domain_lower.split(".")
        base = ".".join(parts[-2:]) if len(parts) >= 2 else domain_lower
        if base in DYNAMIC_DNS_DOMAINS:
            score += 25
        for tld in SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                score += 15
                break
        return min(score, 100)

    # --- Submit methods (preserved signatures) ---

    def submit_ip(self, ip: str, process_name: str = "", reason: str = "") -> Optional[dict]:
        def score_fn(result):
            return self._calculate_ip_reputation(ip, result)
        result = self._perform_lookup(ip, {"value": ip}, "ip", score_fn)
        if result and result.get("found"):
            log.info("Malicious IP detected", ip=ip, process=process_name, reason=reason)
        return result

    def submit_hash(self, file_hash: str, file_path: str = "") -> Optional[dict]:
        # Check legacy hash cache first (24 h TTL)
        cached = self._get_cached_hash(file_hash)
        if cached is not None:
            # Also populate verdict cache so agent can skip future scans
            import sys
            _agent = sys.modules.get("__main__")
            if _agent and hasattr(_agent, "_verdict_cache"):
                score = cached.get("score", 0) if isinstance(cached, dict) else 0
                _agent._verdict_cache[file_hash] = score
            return cached

        def score_fn(result):
            return self._calculate_hash_reputation(result)

        result = self._perform_lookup(file_hash, {"value": file_hash}, "hash", score_fn)
        if result is not None:
            score = result.get("score", 0)
            import sys
            _agent = sys.modules.get("__main__")
            if _agent and hasattr(_agent, "_verdict_cache"):
                _agent._verdict_cache[file_hash] = score
            self._set_cached_hash(file_hash, result)
            if file_path:
                log.info("Hash lookup result", hash=file_hash[:16], file_path=file_path, score=score)
        return result

    def submit_domain(self, domain: str, reason: str = "") -> Optional[dict]:
        def score_fn(result):
            return self._calculate_domain_reputation(domain, result)
        result = self._perform_lookup(domain, {"value": domain}, "domain", score_fn)
        if result and result.get("found"):
            log.info("Malicious domain detected", domain=domain, reason=reason)
        return result

    # --- Utility methods (preserved) ---

    def _cached_result(self, indicator: str, ioc_type: str) -> Optional[dict]:
        score = self._reputation_cache.get(indicator, 0)
        return {"indicator": indicator, "type": ioc_type, "cached": True, "score": score}

    def get_unreported_ips(self, ips: List[str]) -> List[str]:
        return [ip for ip in ips if ip not in self._reported_indicators]

    def get_reputation_summary(self) -> dict:
        high_risk = {k: v for k, v in self._reputation_cache.items() if v >= 50}
        return {
            "total_submitted": len(self._reported_indicators),
            "high_risk_indicators": len(high_risk),
            "cached_scores": len(self._reputation_cache),
        }


# ---------------------------------------------------------------------------
# Background worker for non-blocking threat lookups
# ---------------------------------------------------------------------------
MAX_CONCURRENT_LOOKUPS = 3

_background_queue: "queue.Queue[Tuple[str, str]]" = queue.Queue()
_background_worker: Optional[threading.Thread] = None
_pending_indicators: set = set()
_pending_lock = threading.Lock()


def start_background_worker(submitter: IntelSubmitter):
    global _background_worker
    if _background_worker is not None and _background_worker.is_alive():
        return

    def _loop():
        sem = threading.Semaphore(MAX_CONCURRENT_LOOKUPS)
        while True:
            file_hash, file_path = _background_queue.get()
            sem.acquire()
            with _pending_lock:
                _pending_indicators.add(file_hash)
            try:
                submitter.submit_hash(file_hash, file_path)
            except Exception:
                log.warn("Background lookup failed", hash=file_hash[:16])
            finally:
                with _pending_lock:
                    _pending_indicators.discard(file_hash)
                sem.release()
                _background_queue.task_done()

    _background_worker = threading.Thread(target=_loop, daemon=True)
    _background_worker.start()
    log.info("Background threat-lookup worker started")


def submit_background(file_hash: str, file_path: str = ""):
    """Enqueue a hash lookup — returns immediately, worker handles it.
    Skips enqueue if the same indicator is already pending.
    """
    with _pending_lock:
        if file_hash in _pending_indicators:
            log.debug("Background lookup skipped", hash=file_hash[:16], reason="already_pending")
            return
    _background_queue.put((file_hash, file_path))
