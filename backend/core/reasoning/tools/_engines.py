"""Lazy access to the singleton engines created in main.py.

Tools must not import main.py at module load (circular dependency). They
resolve engine references lazily at call time, mirroring the ``_get_engines()``
pattern used by routers/engines.py.
"""
from typing import Any, Dict, Optional


def _load_engines() -> Dict[str, Any]:
    try:
        from main import (
            behavioral_engine, risk_scoring_engine, correlation_engine,
            response_engine, threat_intel_service, iforest_detector,
            svm_detector, behavioral_baseliner, platform_abstraction,
        )
    except ImportError:
        try:
            from backend.main import (
                behavioral_engine, risk_scoring_engine, correlation_engine,
                response_engine, threat_intel_service, iforest_detector,
                svm_detector, behavioral_baseliner, platform_abstraction,
            )
        except ImportError:
            return {}
    return {
        "behavioral_engine": behavioral_engine,
        "risk_scoring_engine": risk_scoring_engine,
        "correlation_engine": correlation_engine,
        "response_engine": response_engine,
        "threat_intel_service": threat_intel_service,
        "iforest_detector": iforest_detector,
        "svm_detector": svm_detector,
        "behavioral_baseliner": behavioral_baseliner,
        "platform_abstraction": platform_abstraction,
    }


_engines_cache: Optional[Dict[str, Any]] = None


def get_engines() -> Dict[str, Any]:
    global _engines_cache
    if _engines_cache is None:
        _engines_cache = _load_engines()
    return _engines_cache


def get_engine(name: str) -> Any:
    return get_engines().get(name)


def clear_engine_cache() -> None:
    global _engines_cache
    _engines_cache = None
