"""Detection tools — wrap detector/patterns.py, persistence.py and lateral_movement.py."""
from core.reasoning.tool_executor import ReasoningTool


class DetectLolBinTool(ReasoningTool):
    name = "detect_lolbin"
    description = "Detect Living-Off-the-Land binary usage from process name + cmdline."
    category = "detection"

    def run(self, process_name: str = "", cmdline: str = "") -> dict:
        from detector.patterns import analyze_lolbin
        return self._result(analyze_lolbin(process_name, cmdline))


class DetectSuspiciousCmdlineTool(ReasoningTool):
    name = "detect_suspicious_cmdline"
    description = "Detect suspicious command-line patterns (encoding, redirection, recon)."
    category = "detection"

    def run(self, cmdline: str = "") -> dict:
        from detector.patterns import detect_suspicious_cmdline
        return self._result(detect_suspicious_cmdline(cmdline))


class DetectPowerShellAbuseTool(ReasoningTool):
    name = "detect_powershell_abuse"
    description = "Detect PowerShell abuse patterns (encoded commands, download cradle, AMSI bypass)."
    category = "detection"

    def run(self, cmdline: str = "") -> dict:
        from detector.patterns import detect_powershell_abuse
        return self._result(detect_powershell_abuse(cmdline))


class DetectPersistenceTool(ReasoningTool):
    name = "detect_persistence"
    description = "Detect persistence mechanisms (scheduled tasks, WMI, autorun, services)."
    category = "detection"

    def run(self, cmdline: str = "", process_name: str = "", file_path: str = "",
            os_type: str = "windows") -> dict:
        from detector.persistence import detect_persistence_mechanisms
        return self._result(detect_persistence_mechanisms(cmdline, process_name, file_path, os_type))


class DetectRegistryAutorunTool(ReasoningTool):
    name = "detect_registry_autorun"
    description = "Detect registry autorun/persistence indicators from a registry change."
    category = "detection"

    def run(self, key_path: str = "", value_name: str = "", new_value: str = "") -> dict:
        from detector.persistence import detect_registry_autorun
        return self._result(detect_registry_autorun(key_path, value_name, new_value))


class DetectLateralMovementTool(ReasoningTool):
    name = "detect_lateral_movement"
    description = "Detect lateral movement indicators (RDP, PsExec, SMB, WMI, winrm) from a cmdline."
    category = "detection"

    def run(self, cmdline: str = "") -> dict:
        from detector.lateral_movement import detect_lateral_movement_cmdline
        return self._result(detect_lateral_movement_cmdline(cmdline))
