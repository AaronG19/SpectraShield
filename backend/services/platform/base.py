from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple


class PlatformInfo:
    def __init__(self, os_type: str, os_version: str, machine: str, is_admin: bool):
        self.os_type = os_type
        self.os_version = os_version
        self.machine = machine
        self.is_admin = is_admin


class PlatformAbstraction(ABC):
    @abstractmethod
    def detect_os(self) -> str:
        ...

    @abstractmethod
    def get_platform_info(self) -> PlatformInfo:
        ...

    @abstractmethod
    def get_persistence_locations(self) -> List[str]:
        ...

    @abstractmethod
    def get_system_paths(self) -> Dict[str, str]:
        ...

    @abstractmethod
    def normalize_path(self, path: str) -> str:
        ...

    @abstractmethod
    def get_log_location(self) -> str:
        ...

    @abstractmethod
    def get_config_location(self) -> str:
        ...

    @abstractmethod
    def is_system_process(self, process_name: str) -> bool:
        ...

    @abstractmethod
    def get_temporary_directories(self) -> List[str]:
        ...
