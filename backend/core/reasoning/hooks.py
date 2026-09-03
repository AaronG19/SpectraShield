"""Telemetry ingestion hooks (Phase 2 shadow mode).

An ASGI middleware intercepts every ``POST /api/agents/{agent_id}/<feature>/report``
call and forwards the payload to the Perception + Reasoning engines as a
background task, so shadow reasoning never blocks the existing route handlers.
"""
import asyncio
import re
from typing import Any, Dict

from starlette.middleware.base import BaseHTTPMiddleware

from core.logging import logger
from core.reasoning.perception import canonical_event_type
from core.reasoning.working_memory import working_memory

_REPORT_PATH = re.compile(r"^/api/agents/[^/]+/(?P<feature>[^/]+)/report$")


async def reasoning_ingest(agent_id: str, event_type: str, payload: Dict[str, Any]) -> None:
    """Normalize, cache and evaluate one telemetry event.

    Shadow mode (AGENTIC_SHADOW_MODE) logs decisions without side effects.
    Otherwise the Reasoning Engine becomes the authoritative decision-maker
    (Phase 3: alert creation, response queueing, plan creation).
    """
    try:
        from core.reasoning.perception import perception_engine
        from core.reasoning.reasoning_engine import reasoning_engine
        from db.base import SessionLocal
        try:
            from config import AGENTIC_SHADOW_MODE, AGENTIC_MODE
        except ImportError:
            AGENTIC_SHADOW_MODE, AGENTIC_MODE = False, False

        if not AGENTIC_MODE:
            return

        event = perception_engine.normalize(event_type, agent_id, payload)
        working_memory.push(event)

        db = SessionLocal()
        try:
            await reasoning_engine.evaluate(event, db=db, shadow=bool(AGENTIC_SHADOW_MODE))
        finally:
            db.close()
    except Exception as exc:  # never let reasoning break telemetry ingestion
        logger.warning("Reasoning ingestion failed", agent_id=agent_id, event_type=event_type, error=str(exc))


def _schedule_reasoning(agent_id: str, event_type: str, payload: Dict[str, Any]) -> None:
    try:
        asyncio.get_event_loop().create_task(reasoning_ingest(agent_id, event_type, payload))
    except RuntimeError:
        # No running loop (e.g. sync context) — run inline in a thread to avoid blocking.
        import threading

        def _run():
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(reasoning_ingest(agent_id, event_type, payload))
            finally:
                loop.close()

        threading.Thread(target=_run, daemon=True).start()


class ReasoningTelemetryMiddleware(BaseHTTPMiddleware):
    """Non-blocking shadow-mode telemetry forwarder.

    Mounted in main.py only when ``AGENTIC_MODE`` is enabled. BaseHTTPMiddleware
    buffers the request body so downstream handlers still receive it intact.
    """

    async def dispatch(self, request, call_next):
        try:
            path = request.url.path
            method = request.method
            match = _REPORT_PATH.match(path)
            if method == "POST" and match:
                payload: Dict[str, Any] = {}
                try:
                    payload = await request.json()
                except Exception:
                    payload = {}
                agent_id = path.split("/")[3]
                event_type = canonical_event_type(match.group("feature"))
                _schedule_reasoning(agent_id, event_type, payload)
        except Exception:
            logger.warning("Reasoning telemetry middleware skipped request", path=getattr(request, "url", None))
        return await call_next(request)
