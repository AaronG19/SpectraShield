import time
from typing import Dict, List, Optional

from agent_lib.logger import log


class CorrelatedThreat:
    def __init__(self, threat_type: str, indicators: List[dict], score: int):
        self.threat_type = threat_type
        self.indicators = indicators
        self.score = min(score, 100)
        self.timestamp = time.time()
        self.mitre_ids = list(set(
            i.get("mitre_id", "") for i in indicators if i.get("mitre_id")
        ))
        self.mitre_techniques = list(set(
            i.get("mitre_technique", "") for i in indicators if i.get("mitre_technique")
        ))
        self.processes = list(set(
            i.get("process_name", "") for i in indicators if i.get("process_name")
        ))
        self.risk_score = self.score
        self.severity = self._calc_severity()

    def _calc_severity(self) -> str:
        if self.score >= 80:
            return "CRITICAL"
        elif self.score >= 50:
            return "HIGH"
        elif self.score >= 25:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "threat_type": self.threat_type,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "mitre_ids": self.mitre_ids,
            "mitre_techniques": self.mitre_techniques,
            "processes": self.processes,
            "indicator_count": len(self.indicators),
            "indicators": self.indicators,
        }


class CorrelationEngine:
    CORRELATION_WINDOW = 300  # 5 minutes

    def __init__(self):
        self._findings: List[dict] = []
        self._alerts: List[CorrelatedThreat] = []

    def add_finding(self, finding: dict):
        now = time.time()
        cutoff = now - self.CORRELATION_WINDOW
        self._findings[:] = [f for f in self._findings if f.get("_ts", 0) >= cutoff]
        finding["_ts"] = now
        self._findings.append(finding)
        threat = self._correlate(finding)
        if threat:
            self._alerts.append(threat)
            log.warn("Correlated threat", type=threat.threat_type, score=threat.score)
        return threat

    def _correlate(self, new_finding: dict) -> Optional[CorrelatedThreat]:
        rule = new_finding.get("rule", "")
        process = new_finding.get("process_name", "")
        remote_ip = new_finding.get("remote_ip", "")

        # Group findings by process
        same_process = [f for f in self._findings
                        if f.get("process_name") == process
                        and f.get("_ts", 0) >= time.time() - self.CORRELATION_WINDOW]

        if len(same_process) >= 3:
            total_score = sum(f.get("risk_score", 0) for f in same_process)
            return CorrelatedThreat(
                threat_type="multi_rule_attack",
                indicators=list(same_process),
                score=total_score,
            )

        # Network + behavioral correlation
        if remote_ip:
            ip_findings = [f for f in self._findings
                           if f.get("remote_ip") == remote_ip
                           and f.get("_ts", 0) >= time.time() - self.CORRELATION_WINDOW]
            if len(ip_findings) >= 2:
                total_score = sum(f.get("risk_score", 0) for f in ip_findings)
                return CorrelatedThreat(
                    threat_type="network_behavioral_correlation",
                    indicators=list(ip_findings),
                    score=total_score,
                )

        # Check for LOLBin + network combo
        if rule == "lolbin_abuse":
            lolbin_network = [f for f in self._findings
                              if f.get("process_name") == process
                              and f.get("remote_ip")
                              and f.get("_ts", 0) >= time.time() - self.CORRELATION_WINDOW]
            if len(lolbin_network) >= 2:
                total_score = sum(f.get("risk_score", 0) for f in lolbin_network)
                return CorrelatedThreat(
                    threat_type="lolbin_with_network",
                    indicators=list(lolbin_network),
                    score=total_score,
                )

        # Credential dumping + persistence combo
        if rule == "credential_dumping":
            same_proc = [f for f in self._findings
                         if f.get("process_name") == process
                         and f.get("_ts", 0) >= time.time() - self.CORRELATION_WINDOW]
            has_persistence = any(
                f.get("rule") in ("suspicious_service", "scheduled_task")
                for f in same_proc
            )
            if has_persistence:
                return CorrelatedThreat(
                    threat_type="credential_theft_with_persistence",
                    indicators=list(same_proc),
                    score=60,
                )

        return None

    def get_recent_alerts(self, max_age: float = 3600) -> List[dict]:
        now = time.time()
        return [
            a.to_dict() for a in self._alerts
            if now - a.timestamp <= max_age
        ]

    def get_stats(self) -> dict:
        return {
            "active_findings": len(self._findings),
            "total_correlated_alerts": len(self._alerts),
            "recent_alerts": len(self.get_recent_alerts(300)),
        }
