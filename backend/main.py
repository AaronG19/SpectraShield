"""
main.py — Lightweight application entry point.

All route logic, models, schemas, helpers, and business logic have been
extracted into their respective packages. This file only:
1. Reads configuration
2. Initialises singleton service engines
3. Mounts all APIRouter instances under /api
4. Applies the _patched_execute monkey-patch that queues response actions
   into the PendingAction table so agents can poll for them.
"""
import json
from contextlib import asynccontextmanager
from datetime import timedelta

import jwt
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
try:
    from config import (
        CORS_ORIGINS, DATABASE_URL, LOCAL_THREAT_DB_PATH, SECRET_KEY,
        ABUSEIPDB_API_KEY, OTX_API_KEY, GREYNOISE_API_KEY, VT_API_KEY,
        BEHAVIORAL_ANALYSIS_ENABLED, ML_ENABLED, AUTO_RESPONSE_ENABLED,
        RISK_SCORE_THRESHOLD_LOW, RISK_SCORE_THRESHOLD_MEDIUM,
        RISK_SCORE_THRESHOLD_HIGH, RISK_SCORE_THRESHOLD_CRITICAL,
        CORRELATION_TIME_WINDOW, LOG_LEVEL, AGENTIC_MODE,
    )
except ImportError:
    try:
        from backend.config import (
            CORS_ORIGINS, DATABASE_URL, LOCAL_THREAT_DB_PATH, SECRET_KEY,
            ABUSEIPDB_API_KEY, OTX_API_KEY, GREYNOISE_API_KEY, VT_API_KEY,
            BEHAVIORAL_ANALYSIS_ENABLED, ML_ENABLED, AUTO_RESPONSE_ENABLED,
            RISK_SCORE_THRESHOLD_LOW, RISK_SCORE_THRESHOLD_MEDIUM,
            RISK_SCORE_THRESHOLD_HIGH, RISK_SCORE_THRESHOLD_CRITICAL,
            CORRELATION_TIME_WINDOW, LOG_LEVEL, AGENTIC_MODE,
        )
    except ImportError:
        CORS_ORIGINS = ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"]
        DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/agent_security"
        LOCAL_THREAT_DB_PATH = "./threat_db.json"
        SECRET_KEY = "default-secret-key-change-in-production"
        ABUSEIPDB_API_KEY = ""
        OTX_API_KEY = ""
        GREYNOISE_API_KEY = ""
        VT_API_KEY = ""
        BEHAVIORAL_ANALYSIS_ENABLED = True
        ML_ENABLED = False
        AUTO_RESPONSE_ENABLED = True
        RISK_SCORE_THRESHOLD_LOW = 20
        RISK_SCORE_THRESHOLD_MEDIUM = 40
        RISK_SCORE_THRESHOLD_HIGH = 65
        RISK_SCORE_THRESHOLD_CRITICAL = 85
        CORRELATION_TIME_WINDOW = 3600
        LOG_LEVEL = "INFO"
        AGENTIC_MODE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
from core.logging import logger, AgentLogger
AgentLogger.configure(log_level=LOG_LEVEL)

# ---------------------------------------------------------------------------
# Threat-intel service
# ---------------------------------------------------------------------------
from services.threat_intel import ThreatIntelService, configure as configure_intel
configure_intel(
    VT_API_KEY=VT_API_KEY,
    ABUSEIPDB_API_KEY=ABUSEIPDB_API_KEY,
    OTX_API_KEY=OTX_API_KEY,
    GREYNOISE_API_KEY=GREYNOISE_API_KEY,
)
threat_intel_service = ThreatIntelService()

# ---------------------------------------------------------------------------
# Engine singletons
# ---------------------------------------------------------------------------
from services.behavioral_engine import BehavioralEngine
from services.risk_scoring import RiskScoringEngine
from services.correlation_engine import CorrelationEngine
from services.response_engine import ResponseEngine, ResponseAction

behavioral_engine = BehavioralEngine(enabled=BEHAVIORAL_ANALYSIS_ENABLED)
risk_scoring_engine = RiskScoringEngine(thresholds={
    "low": RISK_SCORE_THRESHOLD_LOW,
    "medium": RISK_SCORE_THRESHOLD_MEDIUM,
    "high": RISK_SCORE_THRESHOLD_HIGH,
    "critical": RISK_SCORE_THRESHOLD_CRITICAL,
})
correlation_engine = CorrelationEngine(time_window_minutes=CORRELATION_TIME_WINDOW // 60)
response_engine = ResponseEngine(enabled=AUTO_RESPONSE_ENABLED)

# ML Detectors (optional)
from services.ml.base import MLFallback
from services.ml.isolation_forest import create_if_available as create_iforest
from services.ml.one_class_svm import create_if_available as create_svm
from services.ml.baseliner import BehavioralBaseliner

iforest_detector = create_iforest() if ML_ENABLED else MLFallback()
svm_detector = create_svm() if ML_ENABLED else MLFallback()
behavioral_baseliner = BehavioralBaseliner() if ML_ENABLED else None

# Cross-platform abstraction
from services.platform.factory import get_platform
platform_abstraction = get_platform()

logger.info(
    "All engines initialized",
    behavioral=BEHAVIORAL_ANALYSIS_ENABLED,
    ml=ML_ENABLED,
    auto_response=AUTO_RESPONSE_ENABLED,
)

# ---------------------------------------------------------------------------
# Reasoning layer singletons (Agentic Redesign)
# ---------------------------------------------------------------------------
# These are wired even when AGENTIC_MODE is disabled so routers can query
# state; the reasoning pipeline itself only activates when the flag is on.
from core.reasoning.perception import perception_engine
from core.reasoning.working_memory import working_memory
from core.reasoning.tool_executor import get_tool_executor
from core.reasoning.reasoning_engine import reasoning_engine
from core.reasoning.planning_engine import planning_engine

tool_executor = get_tool_executor()

if AGENTIC_MODE:
    logger.info(
        "Agentic reasoning layer enabled",
        shadow_mode=__import__("config", fromlist=["AGENTIC_SHADOW_MODE"]).AGENTIC_SHADOW_MODE,
    )

# ---------------------------------------------------------------------------
# Database (must come after engine singletons so models are registered)
# ---------------------------------------------------------------------------
from db.base import SessionLocal
from db.init_db import lifespan

# ---------------------------------------------------------------------------
# Monkey-patch response_engine.execute_action so every triggered action is
# also persisted as a PendingAction row, allowing agents to poll for it.
# ---------------------------------------------------------------------------
from models.alert import PendingAction

_original_execute = response_engine.execute_action

def _patched_execute(action, target, agent_id):
    result = _original_execute(action, target, agent_id)
    db = SessionLocal()
    try:
        db.add(PendingAction(agent_id=agent_id, action=action.value, target=target, source="policy"))
        db.commit()
    finally:
        db.close()
    return result

response_engine.execute_action = _patched_execute

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Security EDR API",
    version="3.5.1",
    description="Endpoint Detection & Response backend",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if AGENTIC_MODE:
    from core.reasoning.hooks import ReasoningTelemetryMiddleware
    app.add_middleware(ReasoningTelemetryMiddleware)

# ---------------------------------------------------------------------------
# Mount routers
# ---------------------------------------------------------------------------
from routers import (
    auth, dashboard, agents, alerts, threats, policies, analytics,
    detections, engines, actions, groups, reports, reasoning, ws_router,
)

PREFIX = "/api"

app.include_router(auth.router, prefix=PREFIX)
app.include_router(dashboard.router, prefix=PREFIX)
app.include_router(agents.router, prefix=PREFIX)
app.include_router(alerts.router, prefix=PREFIX)
app.include_router(threats.router, prefix=PREFIX)
app.include_router(policies.router, prefix=PREFIX)
app.include_router(analytics.router, prefix=PREFIX)
app.include_router(detections.router, prefix=PREFIX)
app.include_router(engines.router, prefix=PREFIX)
app.include_router(actions.router, prefix=PREFIX)
app.include_router(groups.router, prefix=PREFIX)
app.include_router(reports.router, prefix=PREFIX)
app.include_router(reasoning.router, prefix=PREFIX)
# WebSocket routes have no prefix — they live directly under /ws/...
app.include_router(ws_router.router)


@app.get("/")
async def root():
    return {"status": "ok", "service": "Security EDR API", "version": "3.5.1"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
