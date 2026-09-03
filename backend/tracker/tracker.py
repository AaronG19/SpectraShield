import os
import sys
import tempfile

SUSPICIOUS_PARENT_CHILD = [
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("outlook.exe", "powershell.exe"),
    ("explorer.exe", "cmd.exe"),
    ("explorer.exe", "powershell.exe"),
    ("chrome.exe", "cmd.exe"),
    ("chrome.exe", "powershell.exe"),
    ("firefox.exe", "cmd.exe"),
    ("firefox.exe", "powershell.exe"),
    ("rundll32.exe", "regsvr32.exe"),
    ("svchost.exe", "powershell.exe"),
]

SUSPICIOUS_NAMES = [
    "mimikatz.exe", "pwdump.exe", "gsecdump.exe", "wce.exe",
    "procdump.exe", "cain.exe", "john.exe", "hashcat.exe",
    "nc.exe", "netcat.exe", "ncat.exe", "bind.exe", "wsh.exe",
    "plink.exe", "putty.exe", "psexec.exe",
]

_TEMP_ROOTS_CACHE = None


def _get_temp_roots():
    global _TEMP_ROOTS_CACHE
    if _TEMP_ROOTS_CACHE is not None:
        return _TEMP_ROOTS_CACHE
    roots = set()
    # Windows — environment variables
    for var in ("TEMP", "TMP"):
        val = os.environ.get(var)
        if val:
            roots.add(os.path.normcase(os.path.normpath(os.path.abspath(val))))
    tempdir = tempfile.gettempdir()
    if tempdir:
        roots.add(os.path.normcase(os.path.normpath(os.path.abspath(tempdir))))
    localappdata = os.environ.get("LOCALAPPDATA")
    if localappdata:
        roots.add(os.path.normcase(os.path.normpath(os.path.abspath(os.path.join(localappdata, "Temp")))))
    roots.add(os.path.normcase(os.path.normpath(os.path.abspath(r"c:\windows\temp"))))
    # Linux
    roots.add("/tmp")
    roots.add("/var/tmp")
    roots.add("/dev/shm")
    # macOS
    roots.add("/private/tmp")
    _TEMP_ROOTS_CACHE = sorted(roots)
    return _TEMP_ROOTS_CACHE


class ProcessTreeTracker:
    def __init__(self, event_emitter):
        self._emitter = event_emitter
        self._processes = []
        self._tree = {}

    @property
    def all_processes(self):
        return self._processes

    @all_processes.setter
    def all_processes(self, value):
        self._processes = value

    def build_tree(self):
        self._tree = {}
        for p in self._processes:
            self._tree[p["pid"]] = p
        for p in self._processes:
            parent = self._tree.get(p["ppid"])
            if parent is not None:
                parent.setdefault("children", []).append(p)

    def detect_suspicious_parent_child(self):
        findings = []
        for p in self._processes:
            parent = self._tree.get(p["ppid"])
            if parent is None:
                continue
            pname = parent.get("name", "").lower()
            cname = p.get("name", "").lower()
            for bad_p, bad_c in SUSPICIOUS_PARENT_CHILD:
                if pname == bad_p.lower() and cname == bad_c.lower():
                    findings.append({
                        "type": "suspicious_parent_child",
                        "parent_name": parent.get("name", ""),
                        "parent_pid": parent.get("pid", 0),
                        "child_name": p.get("name", ""),
                        "child_pid": p.get("pid", 0),
                        "risk": "HIGH",
                        "description": f"Suspicious child process '{cname}' spawned by '{pname}'",
                        "child_cmdline": p.get("cmdline", ""),
                    })
        return findings

    def detect_suspicious_process_names(self):
        findings = []
        for p in self._processes:
            name = p.get("name", "").lower()
            for bad in SUSPICIOUS_NAMES:
                if name == bad.lower():
                    findings.append({
                        "type": "suspicious_name",
                        "parent_name": "",
                        "parent_pid": 0,
                        "child_name": p.get("name", ""),
                        "child_pid": p.get("pid", 0),
                        "risk": "CRITICAL",
                        "description": f"Known malicious process name detected: '{name}'",
                        "child_cmdline": p.get("cmdline", ""),
                    })
        return findings

    def detect_temp_directory_processes(self):
        return []
