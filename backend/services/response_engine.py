import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.logging import logger


class ResponseAction(str, Enum):
    HOST_ISOLATE = "host_isolate"
    PROCESS_TERMINATE = "process_terminate"
    NETWORK_BLOCK = "network_block"
    QUARANTINE_FILE = "quarantine_file"
    ALERT_ONLY = "alert_only"
    KILL_SESSION = "kill_session"
    DISABLE_USER = "disable_user"
    BLOCK_APP = "block_app"
    DNS_BLOCK = "dns_block"
    FIREWALL_RULE = "firewall_rule"


class ResponsePolicy:
    def __init__(
        self,
        name: str,
        description: str,
        condition: Callable[[dict], bool],
        actions: List[ResponseAction],
        min_severity: str = "medium",
        cooldown_seconds: int = 300,
        enabled: bool = True,
    ):
        self.name = name
        self.description = description
        self.condition = condition
        self.actions = actions
        self.min_severity = min_severity
        self.cooldown_seconds = cooldown_seconds
        self.enabled = enabled
        self._last_triggered: Dict[str, float] = {}

    def evaluate(self, event: dict, agent_id: str) -> Optional[List[ResponseAction]]:
        if not self.enabled:
            return None

        import time as _time
        now = _time.time()
        if agent_id in self._last_triggered:
            if now - self._last_triggered[agent_id] < self.cooldown_seconds:
                return None

        if self.condition(event):
            self._last_triggered[agent_id] = now
            return self.actions
        return None


class ResponseEngine:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.policies: List[ResponsePolicy] = []
        self._action_history: List[dict] = []
        self._register_default_policies()

    def _register_default_policies(self):
        self.add_policy(ResponsePolicy(
            name="ransomware_response",
            description="Isolate host and terminate processes on ransomware detection",
            condition=lambda e: e.get("event_type") in ("ransomware", "impact") and e.get("severity") in ("high", "critical"),
            actions=[ResponseAction.HOST_ISOLATE, ResponseAction.PROCESS_TERMINATE, ResponseAction.ALERT_ONLY],
            min_severity="high",
            cooldown_seconds=600,
        ))

        self.add_policy(ResponsePolicy(
            name="credential_theft_response",
            description="Terminate credential dumping processes and alert",
            condition=lambda e: e.get("event_type") in ("credential_dumping", "credential_access") and e.get("severity") in ("high", "critical"),
            actions=[ResponseAction.PROCESS_TERMINATE, ResponseAction.KILL_SESSION, ResponseAction.ALERT_ONLY],
            min_severity="high",
            cooldown_seconds=300,
        ))

        self.add_policy(ResponsePolicy(
            name="c2_beaconing_response",
            description="Block network connections to C2 infrastructure",
            condition=lambda e: e.get("event_type") in ("c2_beaconing", "beaconing", "command_and_control") and e.get("severity") in ("high", "critical"),
            actions=[ResponseAction.NETWORK_BLOCK, ResponseAction.DNS_BLOCK, ResponseAction.ALERT_ONLY],
            min_severity="high",
            cooldown_seconds=600,
        ))

        self.add_policy(ResponsePolicy(
            name="lateral_movement_response",
            description="Isolate host and block lateral movement ports",
            condition=lambda e: e.get("event_type") in ("lateral_movement",) and e.get("severity") in ("high", "critical"),
            actions=[ResponseAction.HOST_ISOLATE, ResponseAction.FIREWALL_RULE, ResponseAction.ALERT_ONLY],
            min_severity="high",
            cooldown_seconds=300,
        ))

        self.add_policy(ResponsePolicy(
            name="malware_download_response",
            description="Quarantine downloaded malware and block source",
            condition=lambda e: e.get("event_type") in ("malware", "lolbin", "script_block", "exploit") and e.get("severity") in ("high", "critical"),
            actions=[ResponseAction.QUARANTINE_FILE, ResponseAction.PROCESS_TERMINATE, ResponseAction.ALERT_ONLY],
            min_severity="high",
            cooldown_seconds=300,
        ))

        self.add_policy(ResponsePolicy(
            name="persistence_response",
            description="Alert on persistence mechanism detection",
            condition=lambda e: e.get("event_type") in ("persistence",) and e.get("severity") in ("high", "critical"),
            actions=[ResponseAction.ALERT_ONLY],
            min_severity="high",
            cooldown_seconds=600,
        ))

        self.add_policy(ResponsePolicy(
            name="fileless_attack_response",
            description="Terminate fileless attack processes (PowerShell, WMI, etc.)",
            condition=lambda e: e.get("event_type") in ("fileless_malware", "process_injection") and e.get("severity") in ("high", "critical"),
            actions=[ResponseAction.PROCESS_TERMINATE, ResponseAction.ALERT_ONLY],
            min_severity="high",
            cooldown_seconds=300,
        ))

    def add_policy(self, policy: ResponsePolicy):
        self.policies.append(policy)

    def evaluate_event(self, event: dict, agent_id: str = "") -> List[dict]:
        if not self.enabled:
            return []

        triggered = []
        for policy in self.policies:
            actions = policy.evaluate(event, agent_id)
            if actions:
                response_record = {
                    "policy": policy.name,
                    "description": policy.description,
                    "actions": [a.value for a in actions],
                    "agent_id": agent_id,
                    "event": event,
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                }
                self._action_history.append(response_record)
                triggered.append(response_record)
                logger.info(
                    f"Response policy '{policy.name}' triggered for agent {agent_id}",
                    policy=policy.name,
                    agent_id=agent_id,
                    actions=[a.value for a in actions],
                )
        return triggered

    def get_action_history(self, limit: int = 50) -> List[dict]:
        return sorted(self._action_history, key=lambda x: x["triggered_at"], reverse=True)[:limit]

    def execute_action(self, action: ResponseAction, target: str, agent_id: str) -> dict:
        result = {
            "action": action.value,
            "target": target,
            "agent_id": agent_id,
            "status": "initiated",
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"Executing response action: {action.value} on {target}", **result)
        self._action_history.append(result)
        return result
