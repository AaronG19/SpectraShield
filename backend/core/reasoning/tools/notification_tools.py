"""Notification tools — wrap WebSocket connection managers.

These tools are inherently async; they override ``execute`` directly.
"""
from core.reasoning.tool_executor import ReasoningTool


class BroadcastAlertTool(ReasoningTool):
    name = "broadcast_alert"
    description = "Push a payload to all clients subscribed to /ws/alerts."
    category = "notification"

    async def execute(self, payload: dict = None, **kwargs) -> dict:
        from ws.manager import ws_alerts
        try:
            await ws_alerts.broadcast(payload or {})
            return self._result({"broadcast": True, "channel": "alerts"})
        except Exception as exc:
            return self._error(exc)


class BroadcastAgentTool(ReasoningTool):
    name = "broadcast_agent"
    description = "Push a payload to all clients subscribed to /ws/agents."
    category = "notification"

    async def execute(self, payload: dict = None, **kwargs) -> dict:
        from ws.manager import ws_agents
        try:
            await ws_agents.broadcast(payload or {})
            return self._result({"broadcast": True, "channel": "agents"})
        except Exception as exc:
            return self._error(exc)


class BroadcastMonitoringTool(ReasoningTool):
    name = "broadcast_monitoring"
    description = "Push a payload to clients subscribed to an agent's /ws/monitoring channel."
    category = "notification"

    async def execute(self, agent_id: str = "", payload: dict = None, **kwargs) -> dict:
        from ws.manager import ws_monitoring
        manager = ws_monitoring.get(agent_id)
        if manager is None:
            return self._result({"broadcast": False, "channel": "monitoring", "reason": "no subscribers"})
        try:
            await manager.broadcast(payload or {})
            return self._result({"broadcast": True, "channel": "monitoring", "agent_id": agent_id})
        except Exception as exc:
            return self._error(exc)
