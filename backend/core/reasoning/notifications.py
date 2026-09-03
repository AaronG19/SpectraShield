"""WebSocket broadcast helpers for the reasoning layer.

Schedules non-blocking pushes to the existing ws/manager channels so plan
updates and approval requests surface in the dashboard immediately.
"""
import asyncio
import functools
from typing import Any, Dict, Optional

from core.logging import logger


def schedule_broadcast(channel: str, payload: Dict[str, Any],
                       agent_id: Optional[str] = None) -> None:
    """Schedule a broadcast on the running event loop (or spawn a thread)."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None

    async def _run():
        try:
            from ws.manager import ws_alerts, ws_agents, ws_monitoring
            if channel == "alerts":
                await ws_alerts.broadcast(payload)
            elif channel == "agents":
                await ws_agents.broadcast(payload)
            elif channel == "monitoring" and agent_id:
                manager = ws_monitoring.get(agent_id)
                if manager:
                    await manager.broadcast(payload)
        except Exception as exc:
            logger.warning("Broadcast failed", channel=channel, error=str(exc))

    if loop is not None and loop.is_running():
        loop.create_task(_run())
    else:
        def _spawn():
            inner = asyncio.new_event_loop()
            try:
                inner.run_until_complete(_run())
            finally:
                inner.close()

        import threading
        threading.Thread(target=_spawn, daemon=True).start()


def broadcast_alert_created(alert_id: str, agent_id: str, severity: str,
                            alert_type: str, verdict: str) -> None:
    schedule_broadcast("alerts", {
        "type": "alert_created",
        "alert_id": alert_id,
        "agent_id": agent_id,
        "severity": severity,
        "alert_type": alert_type,
        "verdict": verdict,
        "source": "reasoning",
    })


def broadcast_plan_update(plan_id: str, agent_id: str, status: str,
                          plan_type: str, awaiting_approval: bool = False) -> None:
    schedule_broadcast("agents", {
        "type": "plan_update",
        "plan_id": plan_id,
        "agent_id": agent_id,
        "status": status,
        "plan_type": plan_type,
        "awaiting_approval": awaiting_approval,
        "source": "reasoning",
    })
