from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.logging import logger
from detector.patterns import (
    analyze_lolbin,
    analyze_parent_child,
    detect_powershell_abuse,
    detect_suspicious_cmdline,
)
from detector.persistence import (
    detect_persistence_mechanisms,
    detect_registry_autorun,
)
from detector.lateral_movement import detect_lateral_movement_cmdline


class BehavioralDetectionResult:
    def __init__(self):
        self.findings: List[dict] = []
        self.max_risk_score: int = 0
        self.detection_types: set = set()
        self.agent_id: Optional[str] = None
        self.analyzed_at: Optional[str] = None

    def add_finding(self, finding: dict):
        if finding:
            self.findings.append(finding)
            risk_str = finding.get("risk", "low")
            risk_map = {"low": 10, "medium": 30, "high": 50, "critical": 80}
            self.max_risk_score = max(self.max_risk_score, risk_map.get(risk_str, 0))
            self.detection_types.add(finding.get("finding_type", finding.get("type", "unknown")))

    def to_dict(self) -> dict:
        return {
            "findings": self.findings,
            "max_risk_score": self.max_risk_score,
            "detection_types": list(self.detection_types),
            "total_findings": len(self.findings),
            "has_findings": len(self.findings) > 0,
            "analyzed_at": self.analyzed_at or datetime.now(timezone.utc).isoformat(),
        }


class BehavioralEngine:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def analyze_process(
        self,
        process_name: str,
        cmdline: str,
        parent_name: str = "",
        file_path: str = "",
        user: str = "",
        os_type: str = "windows",
        agent_id: Optional[str] = None,
    ) -> BehavioralDetectionResult:
        result = BehavioralDetectionResult()
        result.agent_id = agent_id

        if not self.enabled:
            return result

        if cmdline:
            cmdline_lower = cmdline.lower()
        else:
            cmdline_lower = ""

        lolbin_finding = analyze_lolbin(process_name, cmdline)
        result.add_finding(lolbin_finding)

        if "powershell" in process_name.lower() or "pwsh" in process_name.lower():
            ps_findings = detect_powershell_abuse(cmdline)
            for f in ps_findings:
                result.add_finding(f)

        if cmdline:
            cmd_findings = detect_suspicious_cmdline(cmdline)
            for f in cmd_findings:
                result.add_finding(f)

        if parent_name:
            parent_child = analyze_parent_child(parent_name, process_name)
            result.add_finding(parent_child)

        persistence_findings = detect_persistence_mechanisms(cmdline, process_name, file_path, os_type)
        for f in persistence_findings:
            result.add_finding(f)

        lat_findings = detect_lateral_movement_cmdline(cmdline)
        for f in lat_findings:
            result.add_finding(f)

        result.analyzed_at = datetime.now(timezone.utc).isoformat()
        return result

    def analyze_registry_change(
        self,
        key_path: str,
        value_name: str,
        new_value: str,
        change_type: str = "modified",
        agent_id: Optional[str] = None,
    ) -> BehavioralDetectionResult:
        result = BehavioralDetectionResult()
        result.agent_id = agent_id

        if not self.enabled:
            return result

        autorun = detect_registry_autorun(key_path, value_name, new_value)
        result.add_finding(autorun)

        result.analyzed_at = datetime.now(timezone.utc).isoformat()
        return result

    def analyze_network_connection(
        self,
        remote_ip: str,
        remote_port: int,
        process_name: str = "",
        local_ip: str = "",
        agent_id: Optional[str] = None,
    ) -> BehavioralDetectionResult:
        result = BehavioralDetectionResult()
        result.agent_id = agent_id

        if not self.enabled:
            return result

        from detector.lateral_movement import KNOWN_LATERAL_MOVEMENT_PORTS
        if remote_port in KNOWN_LATERAL_MOVEMENT_PORTS:
            result.add_finding({
                "finding_type": "lateral_movement_port",
                "risk": "high",
                "port": remote_port,
                "remote_ip": remote_ip,
                "process": process_name,
                "description": f"Connection to lateral movement port {remote_port} on {remote_ip} from {process_name}",
            })
            result.max_risk_score = max(result.max_risk_score, 50)

        result.analyzed_at = datetime.now(timezone.utc).isoformat()
        return result
