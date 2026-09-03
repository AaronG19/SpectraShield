import json
import os
from typing import Any, Dict, List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _parse_list(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return [v.strip() for v in value.split(",") if v.strip()]


def _parse_bool(value, default):
    if not value:
        return default
    return value.lower() in ("1", "true", "yes", "y", "on")


def _parse_int(value, default, min_val=None, max_val=None):
    try:
        v = int(value) if value is not None else default
        if min_val is not None:
            v = max(v, min_val)
        if max_val is not None:
            v = min(v, max_val)
        return v
    except (ValueError, TypeError):
        return default


def _parse_float(value, default):
    try:
        return float(value) if value is not None else default
    except (ValueError, TypeError):
        return default


# --- Database ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/agent_security")

# --- Security ---
ENV = os.getenv("ENV", "production")
SECRET_KEY = os.getenv("SECRET_KEY", os.getenv("AGENT_SECRET_KEY"))
if not SECRET_KEY:
    if ENV == "production":
        raise RuntimeError(
            "SECRET_KEY is not set. Set the SECRET_KEY environment variable "
            "(e.g. in your .env file) before starting the app in production."
        )
    SECRET_KEY = "dev-only-insecure-key-do-not-use-in-prod"
    print("WARNING: SECRET_KEY not set — using an insecure development key. "
          "Set SECRET_KEY in your environment before deploying.")

# --- CORS ---
CORS_ORIGINS = _parse_list(os.getenv("CORS_ORIGINS"), ["http://localhost:5173", "http://localhost:3000"])

# --- Logging ---
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# --- Threat Intelligence ---
THREAT_INTEL_URL = os.getenv("THREAT_INTEL_URL", "")
SYNC_INTERVAL = _parse_int(os.getenv("SYNC_INTERVAL"), 3600, 60, 86400)
ENABLE_OFFLINE_MODE = _parse_bool(os.getenv("ENABLE_OFFLINE_MODE"), True)
LOCAL_THREAT_DB_PATH = os.getenv("LOCAL_THREAT_DB_PATH", "./local_threat_db.json")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")
TELEMETRY_ENABLED = _parse_bool(os.getenv("TELEMETRY_ENABLED"), True)

# --- Agent Settings ---
AGENT_POLL_INTERVAL = _parse_int(os.getenv("AGENT_POLL_INTERVAL"), 30, 5, 3600)
AGENT_HASH_INTERVAL = _parse_int(os.getenv("AGENT_HASH_INTERVAL"), 150, 10, 86400)

# --- Threat Intelligence Provider API Keys ---
VT_API_KEY = os.getenv("VT_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
VIRUSTOTAL_API_KEY = VT_API_KEY

# --- Behavioral Detection ---
BEHAVIORAL_ANALYSIS_ENABLED = _parse_bool(os.getenv("BEHAVIORAL_ANALYSIS_ENABLED"), True)

# --- ML Detection ---
ML_ENABLED = _parse_bool(os.getenv("ML_ENABLED"), False)

# --- Risk Scoring ---
RISK_SCORE_THRESHOLD_LOW = _parse_int(os.getenv("RISK_SCORE_THRESHOLD_LOW"), 20, 0, 100)
RISK_SCORE_THRESHOLD_MEDIUM = _parse_int(os.getenv("RISK_SCORE_THRESHOLD_MEDIUM"), 40, 0, 100)
RISK_SCORE_THRESHOLD_HIGH = _parse_int(os.getenv("RISK_SCORE_THRESHOLD_HIGH"), 65, 0, 100)
RISK_SCORE_THRESHOLD_CRITICAL = _parse_int(os.getenv("RISK_SCORE_THRESHOLD_CRITICAL"), 85, 0, 100)

# --- Auto Response ---
AUTO_RESPONSE_ENABLED = _parse_bool(os.getenv("AUTO_RESPONSE_ENABLED"), True)

# --- Correlation ---
CORRELATION_TIME_WINDOW = _parse_int(os.getenv("CORRELATION_TIME_WINDOW"), 3600, 60, 604800)

# --- Agentic Mode Configuration ---
AGENTIC_MODE = _parse_bool(os.getenv("AGENTIC_MODE"), False)                     # Master switch
AGENTIC_SEVERITY = _parse_bool(os.getenv("AGENTIC_SEVERITY"), False)             # Phase 3a
AGENTIC_CORRELATION = _parse_bool(os.getenv("AGENTIC_CORRELATION"), False)       # Phase 3b
AGENTIC_ALERTS = _parse_bool(os.getenv("AGENTIC_ALERTS"), False)                 # Phase 3c
AGENTIC_RESPONSE = _parse_bool(os.getenv("AGENTIC_RESPONSE"), False)             # Phase 3d
AGENTIC_PLANNING = _parse_bool(os.getenv("AGENTIC_PLANNING"), False)             # Phase 4
AGENTIC_SHADOW_MODE = _parse_bool(os.getenv("AGENTIC_SHADOW_MODE"), False)       # Phase 2

# --- Working Memory ---
WORKING_MEMORY_EVENT_TTL_SECONDS = _parse_int(os.getenv("WORKING_MEMORY_EVENT_TTL_SECONDS"), 3600, 60, 604800)
WORKING_MEMORY_INVESTIGATION_TTL_SECONDS = _parse_int(os.getenv("WORKING_MEMORY_INVESTIGATION_TTL_SECONDS"), 86400, 60, 604800)
WORKING_MEMORY_CHECKPOINT_INTERVAL_SECONDS = _parse_int(os.getenv("WORKING_MEMORY_CHECKPOINT_INTERVAL_SECONDS"), 300, 10, 86400)
WORKING_MEMORY_MAX_EVENTS_PER_AGENT = _parse_int(os.getenv("WORKING_MEMORY_MAX_EVENTS_PER_AGENT"), 100, 10, 10000)

# --- Reasoning Engine ---
REASONING_AUTO_EXECUTE_CONFIDENCE = _parse_float(os.getenv("REASONING_AUTO_EXECUTE_CONFIDENCE"), 0.8)
REASONING_MAX_TOOL_CALLS_PER_EVENT = _parse_int(os.getenv("REASONING_MAX_TOOL_CALLS_PER_EVENT"), 10, 1, 100)

# --- Planning Engine ---
PLANNING_MAX_STEPS = _parse_int(os.getenv("PLANNING_MAX_STEPS"), 20, 1, 100)
PLANNING_STEP_TIMEOUT_SECONDS = _parse_int(os.getenv("PLANNING_STEP_TIMEOUT_SECONDS"), 30, 1, 3600)

# --- Gemini LLM Configuration ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-1.5-flash")
LLM_API_TIMEOUT = _parse_int(os.getenv("LLM_API_TIMEOUT"), 10, 1, 60)
AGENTIC_LLM_ENABLED = _parse_bool(os.getenv("AGENTIC_LLM_ENABLED"), True)