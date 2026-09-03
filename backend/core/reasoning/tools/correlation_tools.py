"""Correlation tools — wrap CorrelationEngine."""
from core.reasoning.tool_executor import ReasoningTool
from core.reasoning.tools._engines import get_engine


class CorrelateEventTool(ReasoningTool):
    name = "correlate_event"
    description = "Feed an event into the correlation engine and return a correlated incident if an attack chain forms."
    category = "correlation"

    def run(self, event: dict = None, agent_id: str = "", event_type: str = "",
            source: str = "") -> dict:
        engine = get_engine("correlation_engine")
        if engine is None:
            return self._error("correlation_engine unavailable")
        incident = engine.ingest_event(
            event or {}, agent_id=agent_id, event_type=event_type, source=source,
        )
        if incident is None:
            return self._result({"incident": None, "correlated": False})
        return self._result({"incident": incident.to_dict(), "correlated": True})


class ListIncidentsTool(ReasoningTool):
    name = "list_incidents"
    description = "List currently active correlation incidents."
    category = "correlation"

    def run(self, limit: int = 20) -> dict:
        engine = get_engine("correlation_engine")
        if engine is None:
            return self._error("correlation_engine unavailable")
        incidents = engine.get_active_incidents()
        return self._result(incidents[:limit])
