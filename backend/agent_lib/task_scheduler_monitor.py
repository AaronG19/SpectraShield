"""
Feature: Scheduled Task / Cron Job Monitoring
----------------------------------------------
Detects persistence mechanisms created by malware via Windows Task
Scheduler or Linux cron / systemd timers.

Approach: snapshot current tasks -> diff against previous snapshot
-> flag new / modified / removed entries.

No kernel access needed - uses native OS CLI tools only:
  Windows : schtasks /query
  Linux   : crontab -l, /etc/cron.*, systemctl list-timers
"""

import platform
import subprocess
import json
import os
from pathlib import Path
from datetime import datetime

IS_WINDOWS = platform.system() == "Windows"


class ScheduledTaskMonitor:

    def __init__(self, state_file="task_snapshot.json"):
        # Make path absolute to the agent directory to avoid polluting whatever Cwd we are in
        if not os.path.isabs(state_file):
            state_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", state_file)
        self.state_file = Path(state_file)

    def _get_windows_tasks(self):
        out = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            capture_output=True, text=True, check=False
        )
        tasks = {}
        lines = out.stdout.strip().splitlines()
        if len(lines) < 2:
            return tasks
        headers = [h.strip('"') for h in lines[0].split('","')]
        for line in lines[1:]:
            fields = [f.strip('"') for f in line.split('","')]
            if len(fields) != len(headers):
                continue
            row = dict(zip(headers, fields))
            name = row.get("TaskName", line)
            tasks[name] = row
        return tasks

    def _get_linux_cron_jobs(self):
        jobs = {}

        # Per-user crontabs
        try:
            users_out = subprocess.run(["getent", "passwd"], capture_output=True, text=True)
            usernames = [line.split(":")[0] for line in users_out.stdout.splitlines()]
        except Exception:
            usernames = [os.environ.get("USER", "root")]

        for user in usernames:
            res = subprocess.run(["crontab", "-l", "-u", user],
                                  capture_output=True, text=True)
            if res.returncode == 0 and res.stdout.strip():
                for i, line in enumerate(res.stdout.strip().splitlines()):
                    if line.strip() and not line.strip().startswith("#"):
                        jobs[f"user:{user}:{i}"] = line.strip()

        # System-wide cron dirs
        system_paths = [
            "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
            "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"
        ]
        for p in system_paths:
            path = Path(p)
            if path.is_file():
                jobs[f"file:{p}"] = path.read_text(errors="ignore")
            elif path.is_dir():
                for f in path.iterdir():
                    if f.is_file():
                        jobs[f"file:{f}"] = f.read_text(errors="ignore")

        # systemd timers (modern cron replacement, also abused for persistence)
        res = subprocess.run(["systemctl", "list-timers", "--all", "--no-pager"],
                              capture_output=True, text=True)
        if res.returncode == 0:
            jobs["systemd:timers"] = res.stdout

        return jobs

    def snapshot(self):
        return self._get_windows_tasks() if IS_WINDOWS else self._get_linux_cron_jobs()

    def check_for_changes(self):
        """Returns dict: {new: [...], modified: [...], removed: [...]}"""
        # Ensure logs folder exists
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        
        current = self.snapshot()
        previous = {}
        if self.state_file.exists():
            try:
                previous = json.loads(self.state_file.read_text())
            except Exception:
                previous = {}

        new_keys = set(current) - set(previous)
        removed_keys = set(previous) - set(current)
        modified_keys = {
            k for k in (set(current) & set(previous))
            if json.dumps(current[k], sort_keys=True) != json.dumps(previous[k], sort_keys=True)
        }

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "new": [{"key": k, "detail": current[k]} for k in new_keys],
            "modified": [{"key": k, "detail": current[k]} for k in modified_keys],
            "removed": list(removed_keys),
        }

        self.state_file.write_text(json.dumps(current, indent=2, default=str))
        return result


if __name__ == "__main__":
    monitor = ScheduledTaskMonitor()
    diff = monitor.check_for_changes()
    print(json.dumps(diff, indent=2))
