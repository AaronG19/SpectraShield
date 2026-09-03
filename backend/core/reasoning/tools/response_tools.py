"""Response tools — wrap ResponseEngine."""
from core.reasoning.tool_executor import ReasoningTool
from core.reasoning.tools._engines import get_engine


class EvaluateResponseTool(ReasoningTool):
    name = "evaluate_response"
    description = "Evaluate an event against active response policies and return triggered actions."
    category = "response"

    def run(self, event: dict = None, agent_id: str = "") -> dict:
        engine = get_engine("response_engine")
        if engine is None:
            return self._error("response_engine unavailable")
        triggered = engine.evaluate_event(event or {}, agent_id)
        return self._result({"triggered": triggered, "count": len(triggered)})


class ExecuteResponseTool(ReasoningTool):
    name = "execute_response"
    description = "Execute a response action against a target on an agent (queued via PendingAction)."
    category = "response"

    def run(self, action: str = "", target: str = "", agent_id: str = "") -> dict:
        engine = get_engine("response_engine")
        if engine is None:
            return self._error("response_engine unavailable")
        try:
            from services.response_engine import ResponseAction
            action_enum = ResponseAction(action)
        except (ValueError, ImportError):
            return self._error(f"Invalid response action '{action}'")
        result = engine.execute_action(action_enum, target, agent_id)
        return self._result(result)


class GetResponseHistoryTool(ReasoningTool):
    name = "get_response_history"
    description = "Fetch recent response actions taken by the response engine."
    category = "response"

    def run(self, limit: int = 50) -> dict:
        engine = get_engine("response_engine")
        if engine is None:
            return self._error("response_engine unavailable")
        return self._result(engine.get_action_history(limit=limit))
