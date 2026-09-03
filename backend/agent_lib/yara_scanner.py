"""
agent_lib/yara_scanner.py

Static malware detection via YARA rule matching.
Scans files (and optionally live process memory) against a compiled
YARA ruleset and reports matches in the same shape the rest of
agent_lib uses (dict payload -> _report()).

Design notes:
- Rules are compiled ONCE at startup (compiling per-scan is slow and
  is the #1 cause of high CPU in home-grown YARA integrations).
- Falls back gracefully (like watchdog in file_monitor.py) if the
  `yara-python` package or a rules directory isn't available, so the
  agent doesn't crash on hosts where this feature isn't configured.
- Exposes both a class (YaraScanner) for direct use and a couple of
  module-level convenience functions so it can be dropped into
  all_features.py the same way other checks are written there.
"""

import os
import time
import threading
from typing import Dict, List, Optional

from agent_lib.logger import log

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

try:
    import psutil
except ImportError:
    psutil = None


DEFAULT_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "yara_rules")

# Files larger than this are skipped by default (avoid hanging on huge
# ISO/VM images dropped into a watched folder).
DEFAULT_MAX_SCAN_BYTES = 100 * 1024 * 1024  # 100 MB

# Extensions worth scanning with YARA — keep this in sync with
# file_monitor.EXECUTABLE_EXTENSIONS plus a few archive/document types
# that commonly carry droppers.
SCANNABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".hta", ".scr", ".msi", ".jar", ".apk", ".elf", ".so", ".bin",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf",
}


class YaraScanner:
    """Compiles a YARA ruleset once and reuses it for every scan call."""

    def __init__(self, rules_dir: str = DEFAULT_RULES_DIR,
                 max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
                 timeout: int = 10):
        self._rules_dir = rules_dir
        self._max_scan_bytes = max_scan_bytes
        self._timeout = timeout
        self._rules = None
        self._rule_count = 0
        self._lock = threading.Lock()
        self._compiled_at = 0.0
        if YARA_AVAILABLE:
            self._compile()
        else:
            log.warn("yara-python not installed — YARA scanning disabled")

    # -- setup ---------------------------------------------------------

    def _discover_rule_files(self) -> List[str]:
        if not os.path.isdir(self._rules_dir):
            return []
        found = []
        for root, _dirs, files in os.walk(self._rules_dir):
            for fname in files:
                if fname.lower().endswith((".yar", ".yara")):
                    found.append(os.path.join(root, fname))
        return found

    def _compile(self):
        rule_files = self._discover_rule_files()
        if not rule_files:
            log.warn("No YARA rule files found", rules_dir=self._rules_dir)
            self._rules = None
            self._rule_count = 0
            return
        try:
            # yara.compile accepts a {namespace: filepath} mapping so
            # rule name collisions across files don't clobber each other.
            filepaths = {f"ns_{i}": path for i, path in enumerate(rule_files)}
            self._rules = yara.compile(filepaths=filepaths)
            self._rule_count = len(rule_files)
            self._compiled_at = time.time()
            log.info("YARA rules compiled", rule_files=self._rule_count, rules_dir=self._rules_dir)
        except yara.Error as e:
            log.error("YARA rule compilation failed", error=str(e))
            self._rules = None
            self._rule_count = 0

    def reload_rules(self):
        """Hot-reload rules without restarting the agent (e.g. after a
        rules-pack update pushed down from the backend)."""
        if not YARA_AVAILABLE:
            return
        with self._lock:
            self._compile()

    @property
    def is_ready(self) -> bool:
        return YARA_AVAILABLE and self._rules is not None

    # -- scanning --------------------------------------------------------

    def is_scannable(self, path: str) -> bool:
        _, ext = os.path.splitext(path)
        return ext.lower() in SCANNABLE_EXTENSIONS

    def scan_file(self, path: str) -> Optional[Dict]:
        """Scan a single file on disk. Returns a match dict or None."""
        if not self.is_ready:
            return None
        try:
            if not os.path.isfile(path):
                return None
            if os.path.getsize(path) > self._max_scan_bytes:
                log.debug("YARA scan skipped (too large)", path=path)
                return None
        except OSError:
            return None

        try:
            with self._lock:
                matches = self._rules.match(filepath=path, timeout=self._timeout)
        except yara.TimeoutError:
            log.warn("YARA scan timed out", path=path)
            return None
        except Exception as e:
            log.debug("YARA scan error", path=path, error=str(e))
            return None

        if not matches:
            return None

        return self._build_result(path, matches)

    def scan_bytes(self, data: bytes, label: str = "") -> Optional[Dict]:
        """Scan an in-memory buffer (e.g. a process memory region)."""
        if not self.is_ready or not data:
            return None
        try:
            with self._lock:
                matches = self._rules.match(data=data, timeout=self._timeout)
        except Exception as e:
            log.debug("YARA memory scan error", label=label, error=str(e))
            return None
        if not matches:
            return None
        return self._build_result(label, matches)

    def scan_process(self, pid: int) -> Optional[Dict]:
        """Scan a running process's memory. Requires elevated privileges
        on most platforms; fails closed (returns None) otherwise."""
        if not self.is_ready or not YARA_AVAILABLE:
            return None
        try:
            with self._lock:
                matches = self._rules.match(pid=pid, timeout=self._timeout)
        except Exception as e:
            log.debug("YARA process scan error", pid=pid, error=str(e))
            return None
        if not matches:
            return None
        return self._build_result(f"pid:{pid}", matches)

    @staticmethod
    def _build_result(target: str, matches) -> Dict:
        rule_names = [m.rule for m in matches]
        severities = [
            (m.meta.get("severity", "medium") if hasattr(m, "meta") else "medium")
            for m in matches
        ]
        # Highest-severity match wins for the top-level severity field.
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        top_severity = max(severities, key=lambda s: order.get(s, 0)) if severities else "medium"
        return {
            "target": target,
            "matched_rules": rule_names,
            "rule_count": len(rule_names),
            "severity": top_severity,
            "tags": sorted({t for m in matches for t in getattr(m, "tags", [])}),
        }


# ------------------------------------------------------------------------
# Module-level singleton + convenience wrapper, so this can be dropped
# into agent_lib/all_features.py the same way other checks are written
# there (init() + send_*() calling back into _report()).
# ------------------------------------------------------------------------

_scanner: Optional[YaraScanner] = None


def init(rules_dir: str = DEFAULT_RULES_DIR) -> YaraScanner:
    global _scanner
    if _scanner is None:
        _scanner = YaraScanner(rules_dir=rules_dir)
    return _scanner


def get_scanner() -> Optional[YaraScanner]:
    return _scanner


def scan_file_for_report(path: str, sha256: str = "") -> Optional[Dict]:
    """Helper used by file_monitor / all_features integration points.
    Returns a payload shaped like the other agent_lib report dicts,
    or None if there's no match / scanner isn't ready."""
    if _scanner is None or not _scanner.is_ready:
        return None
    if not _scanner.is_scannable(path):
        return None
    result = _scanner.scan_file(path)
    if not result:
        return None
    return {
        "file_path": path,
        "file_hash": sha256,
        "detection_reason": f"YARA match: {', '.join(result['matched_rules'][:5])}",
        "action": "malicious",
        "scanner_type": "yara",
        "severity": result["severity"],
        "matched_rules": result["matched_rules"],
        "tags": result["tags"],
    }
