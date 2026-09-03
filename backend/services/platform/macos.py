import os
import platform
from typing import Dict, List

from services.platform.base import PlatformAbstraction, PlatformInfo


class MacOSPlatform(PlatformAbstraction):
    def detect_os(self) -> str:
        return "macos"

    def get_platform_info(self) -> PlatformInfo:
        return PlatformInfo(
            os_type="macos",
            os_version=platform.mac_ver()[0],
            machine=platform.machine(),
            is_admin=os.geteuid() == 0,
        )

    def get_persistence_locations(self) -> List[str]:
        return [
            "~/Library/LaunchAgents/",
            "/Library/LaunchAgents/",
            "/Library/LaunchDaemons/",
            "~/.bash_profile",
            "~/.zshrc",
            "~/.config/autostart/",
            "/etc/rc.common",
            "/etc/rc.local",
            "/System/Library/StartupItems/",
            "/System/Library/LaunchDaemons/",
            "~/.ssh/authorized_keys",
        ]

    def get_system_paths(self) -> Dict[str, str]:
        return {
            "bin": "/bin",
            "sbin": "/sbin",
            "usr_bin": "/usr/bin",
            "usr_local_bin": "/usr/local/bin",
            "opt_homebrew": "/opt/homebrew/bin",
            "etc": "/etc",
            "tmp": "/tmp",
            "var_tmp": "/var/tmp",
            "users": "/Users",
            "applications": "/Applications",
            "Library": "/Library",
            "System_Library": "/System/Library",
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
            "launchd", "syslogd", "kernel_task", "notifyd",
            "configd", "coreaudiod", "WindowServer", "loginwindow",
            "UserEventAgent", "remoted", "distnoted",
        }
        return process_name.lower() in {p.lower() for p in system_processes}

    def get_temporary_directories(self) -> List[str]:
        return ["/tmp", "/var/tmp"]
