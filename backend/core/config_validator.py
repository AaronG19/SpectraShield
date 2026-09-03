import os
from typing import Any, Dict, List, Optional, Tuple


class ConfigValidator:
    def __init__(self):
        self._errors: List[str] = []
        self._warnings: List[str] = []

    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        self._errors = []
        self._warnings = []
        for key, rules in self._rules.items():
            value = config.get(key)
            self._check(key, value, rules)
        return len(self._errors) == 0, self._errors, self._warnings

    _rules = {
        "DATABASE_URL": {"type": str, "required": True},
        "SECRET_KEY": {"type": str, "required": True, "min_length": 16},
        "CORS_ORIGINS": {"type": list, "required": False},
        "LOG_LEVEL": {"type": str, "required": False, "choices": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
        "VT_API_KEY": {"type": str, "required": False},
        "ABUSEIPDB_API_KEY": {"type": str, "required": False},
        "OTX_API_KEY": {"type": str, "required": False},
        "GREYNOISE_API_KEY": {"type": str, "required": False},
        "RISK_SCORE_THRESHOLD_LOW": {"type": (int, float), "required": False, "min": 0, "max": 100},
        "RISK_SCORE_THRESHOLD_MEDIUM": {"type": (int, float), "required": False, "min": 0, "max": 100},
        "RISK_SCORE_THRESHOLD_HIGH": {"type": (int, float), "required": False, "min": 0, "max": 100},
        "RISK_SCORE_THRESHOLD_CRITICAL": {"type": (int, float), "required": False, "min": 0, "max": 100},
        "AUTO_RESPONSE_ENABLED": {"type": bool, "required": False},
        "BEHAVIORAL_ANALYSIS_ENABLED": {"type": bool, "required": False},
        "ML_ENABLED": {"type": bool, "required": False},
        "AGENT_POLL_INTERVAL": {"type": int, "required": False, "min": 5, "max": 3600},
        "AGENT_HASH_INTERVAL": {"type": int, "required": False, "min": 10, "max": 86400},
        "SYNC_INTERVAL": {"type": int, "required": False, "min": 60, "max": 86400},
        "CORRELATION_TIME_WINDOW": {"type": int, "required": False, "min": 60, "max": 604800},
    }

    def _check(self, key: str, value: Any, rules: dict):
        if rules.get("required") and value is None:
            self._errors.append(f"{key} is required but not set")
            return
        if value is None:
            return
        expected_type = rules.get("type")
        if expected_type and not isinstance(value, expected_type):
            self._errors.append(f"{key} must be of type {expected_type.__name__}, got {type(value).__name__}")
            return
        min_len = rules.get("min_length")
        if min_len and isinstance(value, str) and len(value) < min_len:
            self._errors.append(f"{key} must be at least {min_len} characters long")
        min_val = rules.get("min")
        max_val = rules.get("max")
        if isinstance(value, (int, float)):
            if min_val is not None and value < min_val:
                self._errors.append(f"{key} must be >= {min_val}")
            if max_val is not None and value > max_val:
                self._errors.append(f"{key} must be <= {max_val}")
        choices = rules.get("choices")
        if choices and value not in choices:
            self._errors.append(f"{key} must be one of {choices}, got '{value}'")


def validate_config(config_module) -> Tuple[bool, List[str], List[str]]:
    config_dict = {k: getattr(config_module, k, None) for k in ConfigValidator._rules}
    validator = ConfigValidator()
    return validator.validate(config_dict)
