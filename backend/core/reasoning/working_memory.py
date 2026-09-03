"""Working Memory Manager — per-agent sliding windows of normalized events.

Thread-safe, time-windowed cache used by the Reasoning Engine. Persists
checkpoints to ``agent_context_snapshots`` for crash recovery. Inert unless
``AGENTIC_MODE`` is enabled.
"""
import asyncio
import json
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from config import (
        WORKING_MEMORY_EVENT_TTL_SECONDS,
        WORKING_MEMORY_INVESTIGATION_TTL_SECONDS,
        WORKING_MEMORY_MAX_EVENTS_PER_AGENT,
    )
except ImportError:
    try:
        from backend.config import (
            WORKING_MEMORY_EVENT_TTL_SECONDS,
            WORKING_MEMORY_INVESTIGATION_TTL_SECONDS,
            WORKING_MEMORY_MAX_EVENTS_PER_AGENT,
        )
    except ImportError:
        WORKING_MEMORY_EVENT_TTL_SECONDS = 3600
        WORKING_MEMORY_INVESTIGATION_TTL_SECONDS = 86400
        WORKING_MEMORY_MAX_EVENTS_PER_AGENT = 100

from core.reasoning.models import AgentContext, NormalizedEvent


class WorkingMemoryManager:
    """Maintains a bounded sliding window of normalized events per agent."""

    def __init__(self, max_events_per_agent: Optional[int] = None,
                 event_ttl_seconds: Optional[int] = None,
                 investigation_ttl_seconds: Optional[int] = None):
        self._max_events = max_events_per_agent or WORKING_MEMORY_MAX_EVENTS_PER_AGENT
        self._event_ttl = event_ttl_seconds if event_ttl_seconds is not None else WORKING_MEMORY_EVENT_TTL_SECONDS
        self._investigation_ttl = investigation_ttl_seconds if investigation_ttl_seconds is not None else WORKING_MEMORY_INVESTIGATION_TTL_SECONDS
        self._lock = threading.RLock()
        self._contexts: Dict[str, AgentContext] = {}

    # --- basic state ops ---

    def _ensure_context(self, agent_id: str) -> AgentContext:
        ctx = self._contexts.get(agent_id)
        if ctx is None:
            ctx = AgentContext(agent_id=agent_id)
            ctx.events = deque(maxlen=self._max_events if self._max_events else None)
            self._contexts[agent_id] = ctx
        elif self._max_events and ctx.events.maxlen != self._max_events:
            ctx.events = deque(list(ctx.events), maxlen=self._max_events)
        return ctx

    def push(self, event: NormalizedEvent) -> None:
        with self._lock:
            ctx = self._ensure_context(event.agent_id)
            ctx.events.append(event)
            ctx.touch()
        self._prune_events(event.agent_id)

    def get_recent_events(self, agent_id: str, window_seconds: Optional[int] = None,
                          event_type: Optional[str] = None) -> List[NormalizedEvent]:
        ttl = window_seconds if window_seconds is not None else self._event_ttl
        with self._lock:
            ctx = self._contexts.get(agent_id)
            if ctx is None:
                return []
            events = ctx.recent(ttl)
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            return list(events)

    def get_context(self, agent_id: str) -> Optional[AgentContext]:
        with self._lock:
            ctx = self._contexts.get(agent_id)
            if ctx is None:
                return None
            ctx.recent(self._event_ttl)
            return ctx

    def all_agent_ids(self) -> List[str]:
        with self._lock:
            return list(self._contexts.keys())

    def sizes(self) -> Dict[str, int]:
        with self._lock:
            return {aid: len(ctx.events) for aid, ctx in self._contexts.items()}

    def event_count(self) -> int:
        with self._lock:
            return sum(len(ctx.events) for ctx in self._contexts.values())

    def clear(self, agent_id: Optional[str] = None) -> None:
        with self._lock:
            if agent_id is not None:
                self._contexts.pop(agent_id, None)
            else:
                self._contexts.clear()

    def remove_expired_agents(self) -> int:
        cutoff = datetime.utcnow() - timedelta(seconds=self._investigation_ttl)
        stale = []
        with self._lock:
            for aid, ctx in self._contexts.items():
                if ctx.last_updated < cutoff:
                    stale.append(aid)
            for aid in stale:
                del self._contexts[aid]
        return len(stale)

    # --- eviction / pruning ---

    def _prune_events(self, agent_id: str) -> None:
        """Drop events older than the event TTL for the given agent."""
        with self._lock:
            ctx = self._contexts.get(agent_id)
            if ctx is None:
                return
            ctx.recent(self._event_ttl)

    # --- persistence (checkpoints to agent_context_snapshots) ---

    def _snapshot_row(self, agent_id: str) -> Optional[dict]:
        ctx = self.get_context(agent_id)
        if ctx is None:
            return None
        return {
            "agent_id": agent_id,
            "context_data": json.dumps({
                "events": [e.to_dict() for e in list(ctx.events)],
                "metadata": ctx.metadata,
                "last_updated": ctx.last_updated.isoformat(),
            }, default=str),
        }

    def snapshot_all(self, db) -> int:
        """Write checkpoints for every active agent context. Returns rows written."""
        rows = []
        for agent_id in self.all_agent_ids():
            row = self._snapshot_row(agent_id)
            if row:
                rows.append(row)
        if not rows:
            return 0
        try:
            from models.reasoning import AgentContextSnapshot
            for row in rows:
                db.add(AgentContextSnapshot(agent_id=row["agent_id"], context_data=row["context_data"]))
            db.commit()
        except Exception:
            db.rollback()
            return 0
        return len(rows)

    async def snapshot_all_async(self, db_factory) -> int:
        """Async checkpoint helper (DB writes happen in a worker thread)."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._checkpoint_with_factory, db_factory)

    def _checkpoint_with_factory(self, db_factory) -> int:
        db = db_factory()
        try:
            return self.snapshot_all(db)
        finally:
            db.close()

    def restore(self, db, agent_id: Optional[str] = None) -> int:
        """Restore working memory from the latest snapshots. Returns events restored."""
        try:
            from models.reasoning import AgentContextSnapshot
            query = db.query(AgentContextSnapshot)
            if agent_id:
                query = query.filter(AgentContextSnapshot.agent_id == agent_id)
            # Load the most recent snapshot per agent in one pass.
            rows = query.order_by(AgentContextSnapshot.snapshot_at.desc()).all()
            latest: Dict[str, AgentContextSnapshot] = {}
            for row in rows:
                if row.agent_id not in latest:
                    latest[row.agent_id] = row
        except Exception:
            return 0

        restored = 0
        with self._lock:
            for aid, row in latest.items():
                try:
                    data = json.loads(row.context_data or "{}")
                    ctx = self._ensure_context(aid)
                    for ev in data.get("events", []):
                        ctx.events.append(NormalizedEvent.from_dict(ev))
                    ctx.metadata = data.get("metadata", {})
                    restored += len(ctx.events)
                except Exception:
                    continue
        return restored


working_memory = WorkingMemoryManager()
