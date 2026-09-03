"""Tool Executor — uniform async contract and centralized registry.

Every reasoning tool wraps an existing EDR capability (an engine singleton, a
detector function or a persistence/notification primitive) behind a single
``execute(**kwargs) -> dict`` contract. The Reasoning Engine never imports
services directly; it only talks to tools through the registry below.
"""
from abc import ABC
from typing import Any, Dict, List, Optional


class ReasoningTool(ABC):
    """Base class for all reasoning tools.

    Subclasses implement ``run(**kwargs)`` (sync core) and may override
    ``execute`` when the tool is inherently async (e.g. WebSocket broadcast).
    """

    name: str = ""
    description: str = ""
    category: str = "analysis"
    version: str = "1.0"

    def _result(self, data: Any) -> Dict[str, Any]:
        return {"status": "success", "tool": self.name, "data": data}

    def _error(self, message: Any) -> Dict[str, Any]:
        return {"status": "error", "tool": self.name, "error": str(message)}

    def run(self, **kwargs) -> Dict[str, Any]:
        raise NotImplementedError(f"Tool '{self.name}' does not implement run()")

    async def execute(self, **kwargs) -> Dict[str, Any]:
        try:
            return self.run(**kwargs)
        except Exception as exc:  # never let a tool failure take down the pipeline
            return self._error(exc)


class ToolExecutor:
    """Routes tool calls by name and enforces call limits."""

    def __init__(self, registry: Optional[Dict[str, ReasoningTool]] = None,
                 max_calls_per_event: Optional[int] = None):
        self._registry: Dict[str, ReasoningTool] = registry or {}
        self._max_calls = max_calls_per_event

    def register(self, tool: ReasoningTool) -> None:
        if not tool.name:
            raise ValueError("Tool must declare a name")
        self._registry[tool.name] = tool

    def register_many(self, tools: List[ReasoningTool]) -> None:
        for tool in tools:
            self.register(tool)

    def get(self, name: str) -> Optional[ReasoningTool]:
        return self._registry.get(name)

    def available_tools(self) -> List[Dict[str, str]]:
        return [
            {"name": t.name, "description": t.description, "category": t.category, "version": t.version}
            for t in self._registry.values()
        ]

    def has(self, name: str) -> bool:
        return name in self._registry

    async def execute(self, name: str, **kwargs) -> Dict[str, Any]:
        tool = self._registry.get(name)
        if tool is None:
            return {"status": "error", "tool": name, "error": f"Unknown tool '{name}'"}
        return await tool.execute(**kwargs)

    async def execute_limited(self, name: str, calls_so_far: int, **kwargs) -> Dict[str, Any]:
        if self._max_calls and calls_so_far >= self._max_calls:
            return {"status": "error", "tool": name, "error": "Max tool calls per event reached"}
        return await self.execute(name, **kwargs)


def build_tool_registry() -> Dict[str, ReasoningTool]:
    """Instantiate all tool modules and return the name -> tool map."""
    from core.reasoning.tools.behavioral_tools import (
        AnalyzeBehaviorTool, AnalyzeRegistryChangeTool, AnalyzeNetworkConnectionTool,
    )
    from core.reasoning.tools.risk_tools import (
        CalculateRiskTool, CalculateBehavioralRiskTool, CheckRiskThresholdTool,
    )
    from core.reasoning.tools.correlation_tools import CorrelateEventTool, ListIncidentsTool
    from core.reasoning.tools.response_tools import (
        EvaluateResponseTool, ExecuteResponseTool, GetResponseHistoryTool,
    )
    from core.reasoning.tools.threat_intel_tools import LookupThreatIntelTool
    from core.reasoning.tools.ml_tools import (
        PredictAnomalyIForestTool, PredictAnomalySVMTool, CheckBaselineTool, UpdateBaselineTool,
    )
    from core.reasoning.tools.detection_tools import (
        DetectLolBinTool, DetectPersistenceTool, DetectRegistryAutorunTool,
        DetectLateralMovementTool, DetectPowerShellAbuseTool, DetectSuspiciousCmdlineTool,
    )
    from core.reasoning.tools.data_tools import (
        QueryRecentAlertsTool, QueryAlertCountsTool, QueryReasoningHistoryTool,
        QueryAgentProfileTool, QueryAgentActivityTool,
    )
    from core.reasoning.tools.notification_tools import (
        BroadcastAlertTool, BroadcastAgentTool, BroadcastMonitoringTool,
    )

    tools = [
        AnalyzeBehaviorTool(), AnalyzeRegistryChangeTool(), AnalyzeNetworkConnectionTool(),
        CalculateRiskTool(), CalculateBehavioralRiskTool(), CheckRiskThresholdTool(),
        CorrelateEventTool(), ListIncidentsTool(),
        EvaluateResponseTool(), ExecuteResponseTool(), GetResponseHistoryTool(),
        LookupThreatIntelTool(),
        PredictAnomalyIForestTool(), PredictAnomalySVMTool(), CheckBaselineTool(), UpdateBaselineTool(),
        DetectLolBinTool(), DetectPersistenceTool(), DetectRegistryAutorunTool(),
        DetectLateralMovementTool(), DetectPowerShellAbuseTool(), DetectSuspiciousCmdlineTool(),
        QueryRecentAlertsTool(), QueryAlertCountsTool(), QueryReasoningHistoryTool(),
        QueryAgentProfileTool(), QueryAgentActivityTool(),
        BroadcastAlertTool(), BroadcastAgentTool(), BroadcastMonitoringTool(),
    ]
    return {tool.name: tool for tool in tools}


# Lazy singleton registry so modules can share one executor.
_executor: Optional[ToolExecutor] = None


def get_tool_executor() -> ToolExecutor:
    global _executor
    if _executor is None:
        from config import REASONING_MAX_TOOL_CALLS_PER_EVENT
        _executor = ToolExecutor(registry=build_tool_registry(), max_calls_per_event=REASONING_MAX_TOOL_CALLS_PER_EVENT)
    return _executor
