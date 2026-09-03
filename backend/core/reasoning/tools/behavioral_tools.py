"""Behavioral analysis tools — wrap BehavioralEngine methods."""
from core.reasoning.tool_executor import ReasoningTool
from core.reasoning.tools._engines import get_engine


class AnalyzeBehaviorTool(ReasoningTool):
    name = "analyze_behavior"
    description = "Run full behavioral analysis on a process (lolbin, powershell abuse, suspicious cmdline, parent-child, persistence, lateral movement)."
    category = "behavioral"

    def run(self, process_name: str = "", cmdline: str = "", parent_name: str = "",
            file_path: str = "", user: str = "", os_type: str = "windows",
            agent_id: str = "") -> dict:
        engine = get_engine("behavioral_engine")
        if engine is None:
            return self._error("behavioral_engine unavailable")
        result = engine.analyze_process(
            process_name=process_name, cmdline=cmdline, parent_name=parent_name,
            file_path=file_path, user=user, os_type=os_type,
            agent_id=agent_id or None,
        )
        return self._result(result.to_dict())


class AnalyzeRegistryChangeTool(ReasoningTool):
    name = "analyze_registry_change"
    description = "Analyze a registry change for autorun/persistence indicators."
    category = "behavioral"

    def run(self, key_path: str = "", value_name: str = "", new_value: str = "",
            change_type: str = "modified", agent_id: str = "") -> dict:
        engine = get_engine("behavioral_engine")
        if engine is None:
            return self._error("behavioral_engine unavailable")
        result = engine.analyze_registry_change(
            key_path=key_path, value_name=value_name, new_value=new_value,
            change_type=change_type, agent_id=agent_id or None,
        )
        return self._result(result.to_dict())


class AnalyzeNetworkConnectionTool(ReasoningTool):
    name = "analyze_network_connection"
    description = "Analyze a network connection for lateral movement port indicators."
    category = "behavioral"

    def run(self, remote_ip: str = "", remote_port: int = 0, process_name: str = "",
            local_ip: str = "", agent_id: str = "") -> dict:
        engine = get_engine("behavioral_engine")
        if engine is None:
            return self._error("behavioral_engine unavailable")
        result = engine.analyze_network_connection(
            remote_ip=remote_ip, remote_port=remote_port, process_name=process_name,
            local_ip=local_ip, agent_id=agent_id or None,
        )
        return self._result(result.to_dict())
