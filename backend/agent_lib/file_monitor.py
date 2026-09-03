import hashlib
import os
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from agent_lib.logger import log


try:
    from watchdog.events import PatternMatchingEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    PatternMatchingEventHandler = object


MONITOR_DIRS_WINDOWS = [
    os.path.expandvars("%USERPROFILE%\\Downloads"),
    os.path.expandvars("%USERPROFILE%\\Desktop"),
    os.path.expandvars("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
]

MONITOR_DIRS_LINUX = [
    os.path.expanduser("~/Downloads"),
]

MONITOR_DIRS_MACOS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
]

# Only these extensions generate security-relevant file events
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd",
                         ".vbs", ".js", ".hta", ".scr", ".msi"}

# Directories wholly excluded from monitoring (exact name match)
EXCLUDE_DIR_NAMES = {"logs", "__pycache__", ".git", ".venv", "venv", "node_modules",
                     ".gitlab", ".svn", "cache", "cached", ".cache", "browsercache",
                     "chrome_cache", "firefox_cache", "crx_install", "_metadata"}

# Directories excluded by name prefix (browser temp extraction artifacts)
EXCLUDE_DIR_PREFIXES = {"scoped_dir", "chromiumcrx_"}

# File extensions excluded from event generation (assets, images, fonts, docs)
EXCLUDE_EXTENSIONS = {".log", ".pyc", ".pyo", ".db", ".sqlite", ".sqlite3",
                      ".js", ".css", ".html", ".htm", ".json", ".xml", ".part", ".tmp",
                      ".svg", ".png", ".gif", ".ico", ".jpg", ".jpeg", ".webp",
                      ".map", ".woff", ".woff2", ".ttf", ".txt"}

# Suffixes excluded (journal files, partial downloads)
EXCLUDE_SUFFIXES = {".db-journal", ".db-wal", ".db-shm", ".crdownload", ".download"}

# Specific filenames excluded
EXCLUDE_FILES = {"agent.log", "debug.log", "error.log"}


def hash_file_md5(path: str) -> str:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def hash_file_sha1(path: str) -> str:
    try:
        h = hashlib.sha1()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def hash_file_sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def is_executable(path: str) -> bool:
    _, ext = os.path.splitext(path)
    return ext.lower() in EXECUTABLE_EXTENSIONS


class FileEventHandler(PatternMatchingEventHandler):
    def __init__(self, on_event: Callable):
        super().__init__(patterns=["*"], ignore_directories=False, case_sensitive=False)
        self._on_event = on_event

    def on_created(self, event):
        if not event.is_directory:
            self._on_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._on_event("modified", event.src_path)


class FileMonitor:
    def __init__(self, os_type: str = "windows"):
        self._observer = None
        self._running = False
        self._events: List[dict] = []
        self._lock = threading.Lock()
        self._os_type = os_type.lower()
        self._monitor_dirs = self._get_dirs()
        self._dedup_cache: Dict[str, float] = {}
        self._dedup_window = 2.0

    def _get_dirs(self) -> List[str]:
        if self._os_type == "windows":
            return MONITOR_DIRS_WINDOWS
        elif self._os_type == "linux":
            return MONITOR_DIRS_LINUX
        elif self._os_type == "darwin" or self._os_type == "macos":
            return MONITOR_DIRS_MACOS
        return []

    @staticmethod
    def _is_excluded(path: str) -> bool:
        if not path:
            return True
        normalized = os.path.normpath(path).lower()
        parts = normalized.replace("\\", "/").split("/")
        for part in parts:
            if part in EXCLUDE_DIR_NAMES:
                return True
            for prefix in EXCLUDE_DIR_PREFIXES:
                if part.startswith(prefix):
                    return True
        fname = os.path.basename(normalized)
        if fname in EXCLUDE_FILES:
            return True
        _, ext = os.path.splitext(fname)
        if ext.lower() in EXCLUDE_EXTENSIONS:
            return True
        for suffix in EXCLUDE_SUFFIXES:
            if fname.endswith(suffix):
                return True
        return False

    def _handle_event(self, change_type: str, path: str):
        if not path or self._is_excluded(path):
            return
        now = time.time()
        dedup_key = f"{change_type}:{path}"
        last_time = self._dedup_cache.get(dedup_key, 0.0)
        if now - last_time < self._dedup_window:
            return
        self._dedup_cache[dedup_key] = now
        if len(self._dedup_cache) > 10000:
            cutoff = now - 60
            self._dedup_cache = {k: v for k, v in self._dedup_cache.items() if v >= cutoff}
        try:
            if not os.path.exists(path):
                return
        except OSError:
            return
        try:
            event_type = "file_create" if change_type == "created" else "file_modify"
            info = {
                "event_type": event_type,
                "change_type": change_type,
                "file_path": path,
                "file_name": os.path.basename(path),
                "file_size": os.path.getsize(path),
                "is_executable": is_executable(path),
                "detected_at": time.time(),
            }
        except OSError:
            return
        if info["is_executable"]:
            info["md5"] = hash_file_md5(path)
            info["sha1"] = hash_file_sha1(path)
            info["sha256"] = hash_file_sha256(path)
        with self._lock:
            self._events.append(info)
        log.debug("File event", change_type=change_type, path=path, executable=info["is_executable"])

    def start(self):
        if not WATCHDOG_AVAILABLE:
            log.warn("watchdog not installed — file monitoring disabled")
            return
        self._observer = Observer()
        for d in self._monitor_dirs:
            if os.path.isdir(d):
                handler = FileEventHandler(self._handle_event)
                self._observer.schedule(handler, d, recursive=True)
                log.info("Watching directory", path=d)
        self._observer.start()
        self._running = True

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
        self._running = False

    def drain_events(self) -> List[dict]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
        return events
