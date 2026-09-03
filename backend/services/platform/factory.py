import platform
from typing import Optional

from services.platform.base import PlatformAbstraction
from services.platform.windows import WindowsPlatform
from services.platform.linux import LinuxPlatform
from services.platform.macos import MacOSPlatform


def create_platform() -> PlatformAbstraction:
    system = platform.system().lower()
    if system == "windows":
        return WindowsPlatform()
    elif system == "linux":
        return LinuxPlatform()
    elif system == "darwin":
        return MacOSPlatform()
    else:
        return WindowsPlatform()


_platform_instance: Optional[PlatformAbstraction] = None


def get_platform() -> PlatformAbstraction:
    global _platform_instance
    if _platform_instance is None:
        _platform_instance = create_platform()
    return _platform_instance
