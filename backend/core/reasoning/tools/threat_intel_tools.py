"""Threat intelligence tools — wrap ThreatIntelService."""
from core.reasoning.tool_executor import ReasoningTool
from core.reasoning.tools._engines import get_engine


class LookupThreatIntelTool(ReasoningTool):
    name = "lookup_threat_intel"
    description = "Reputation lookup of an IP / hash / domain / URL against threat intelligence providers."
    category = "threat_intel"

    def run(self, indicator: str = "") -> dict:
        engine = get_engine("threat_intel_service")
        if engine is None:
            return self._error("threat_intel_service unavailable")
        if not indicator:
            return self._error("indicator is required")
        return self._result(engine.lookup(indicator))
