import os
import hashlib
import uuid
import time
import platform
from agent_lib.logger import log

def _get_canary_directories() -> list:
    home = os.path.expanduser("~")
    sys_type = platform.system().lower()
    if sys_type == "windows":
        return [
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Pictures"),
            os.path.join(home, "Music"),
            os.path.join(home, "Videos"),
            os.path.join(home, "AppData", "Roaming"),
        ]
    elif sys_type == "darwin":  # macOS
        return [
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Pictures"),
            os.path.join(home, "Library", "Application Support"),
        ]
    else:  # Linux
        return [
            os.path.join(home, "Documents"),
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            os.path.join(home, "Pictures"),
            os.path.join(home, ".config"),
        ]

CANARY_DIRECTORIES = _get_canary_directories()

CANARY_PREFIX = ".canary_"
CANARY_MARKER = "EDR_CANARY_TRAP"

_canary_files = {}
_last_check = 0


def _canary_content(canary_id: str) -> str:
    return f"{CANARY_MARKER}:{canary_id}\nDO NOT DELETE OR MODIFY THIS FILE\n"


def deploy_canaries():
    deployed = 0
    for d in CANARY_DIRECTORIES:
        if not os.path.isdir(d):
            continue
        canary_id = str(uuid.uuid4())
        fname = f"{CANARY_PREFIX}{canary_id[:8]}.txt"
        fpath = os.path.join(d, fname)
        try:
            with open(fpath, "w") as f:
                f.write(_canary_content(canary_id))
            os.system(f'attrib +h "{fpath}"') if os.name == "nt" else None
            _canary_files[fpath] = canary_id
            deployed += 1
        except Exception as e:
            log.debug("Canary deploy failed", path=fpath, error=str(e))
    log.info("Canary files deployed", count=deployed)
    return deployed


def verify_canaries():
    events = []
    for fpath, canary_id in list(_canary_files.items()):
        try:
            if not os.path.exists(fpath):
                h = hashlib.sha256(fpath.encode()).hexdigest()
                events.append({
                    "file_path": fpath,
                    "reason": "DELETED",
                    "file_hash": h,
                    "directory": os.path.dirname(fpath),
                })
                log.warn("Canary file deleted!", path=fpath)
                continue
            with open(fpath, "r") as f:
                content = f.read()
            if CANARY_MARKER not in content:
                h = hashlib.sha256(open(fpath, "rb").read()).hexdigest()
                events.append({
                    "file_path": fpath,
                    "reason": "MODIFIED",
                    "file_hash": h,
                    "directory": os.path.dirname(fpath),
                })
                log.warn("Canary file modified!", path=fpath)
        except Exception as e:
            log.debug("Canary verify failed", path=fpath, error=str(e))
    return events


def check_canaries():
    global _last_check
    if not _canary_files:
        deploy_canaries()
    now = time.time()
    if now - _last_check < 60:
        return []
    _last_check = now
    events = verify_canaries()
    if events:
        log.warn("Canary tamper detected", count=len(events))
    return events
