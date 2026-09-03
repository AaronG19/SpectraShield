import os
import platform
from typing import Dict, List

from services.platform.base import PlatformAbstraction, PlatformInfo


class LinuxPlatform(PlatformAbstraction):
    def detect_os(self) -> str:
        return "linux"

    def get_platform_info(self) -> PlatformInfo:
        return PlatformInfo(
            os_type="linux",
            os_version=platform.version(),
            machine=platform.machine(),
            is_admin=os.geteuid() == 0,
        )

    def get_persistence_locations(self) -> List[str]:
        return [
            "~/.bashrc",
            "~/.bash_profile",
            "~/.profile",
            "~/.zshrc",
            "~/.config/autostart/",
            "/etc/rc.local",
            "/etc/init.d/",
            "/etc/systemd/system/",
            "/etc/cron.d/",
            "/var/spool/cron/",
            "~/.ssh/authorized_keys",
            "/etc/ld.so.preload",
        ]

    def get_system_paths(self) -> Dict[str, str]:
        return {
            "bin": "/bin",
            "sbin": "/sbin",
            "usr_bin": "/usr/bin",
            "usr_sbin": "/usr/sbin",
            "usr_local_bin": "/usr/local/bin",
            "etc": "/etc",
            "tmp": "/tmp",
            "var_tmp": "/var/tmp",
            "home": "/home",
            "root": "/root",
            "opt": "/opt",
        }

    def normalize_path(self, path: str) -> str:
        if not path:
            return path
        return path.replace("\\", "/").lower()

    def get_log_location(self) -> str:
        return "/var/log/agent_security"

    def get_config_location(self) -> str:
        return "/etc/agent_security"

    def is_system_process(self, process_name: str) -> bool:
        system_processes = {
            "init", "systemd", "systemd-journald", "systemd-udevd",
            "systemd-resolved", "systemd-logind", "dbus-daemon",
            "sshd", "cron", "rsyslogd", "syslogd",
            "kthreadd", "kworker", "ksoftirqd",
        }
        return process_name.lower() in {p.lower() for p in system_processes}

    def get_temporary_directories(self) -> List[str]:
        return ["/tmp", "/var/tmp", "/dev/shm"]
