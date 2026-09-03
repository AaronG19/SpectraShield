"""Routers package — exposes all APIRouter instances."""
from routers import (
    auth,
    dashboard,
    agents,
    alerts,
    threats,
    policies,
    analytics,
    detections,
    engines,
    actions,
    groups,
    reports,
    reasoning,
    websockets as ws_router,
)

__all__ = [
    "auth",
    "dashboard",
    "agents",
    "alerts",
    "threats",
    "policies",
    "analytics",
    "detections",
    "engines",
    "actions",
    "groups",
    "reports",
    "reasoning",
    "ws_router",
]
