"""Risk scoring tools — wrap RiskScoringEngine."""
from core.reasoning.tool_executor import ReasoningTool
from core.reasoning.tools._engines import get_engine


class CalculateRiskTool(ReasoningTool):
    name = "calculate_risk"
    description = "Compute a risk score for an event (category base score x severity multiplier + components)."
    category = "risk"

    def run(self, event_type: str = "behavioral_anomaly", severity: str = "medium",
            agent_id: str = "", event_id: str = "", additional_components: dict = None) -> dict:
        engine = get_engine("risk_scoring_engine")
        if engine is None:
            return self._error("risk_scoring_engine unavailable")
        score = engine.calculate_score(
            event_type=event_type, severity=severity, agent_id=agent_id or None,
            event_id=event_id or None, additional_components=additional_components,
        )
        threshold = engine.check_threshold(score)
        data = score.to_dict()
        data["threshold_check"] = threshold
        return self._result(data)


class CalculateBehavioralRiskTool(ReasoningTool):
    name = "calculate_behavioral_risk"
    description = "Derive a risk score from a behavioral detection result dict."
    category = "risk"

    def run(self, behavioral_result: dict = None, agent_id: str = "") -> dict:
        engine = get_engine("risk_scoring_engine")
        if engine is None:
            return self._error("risk_scoring_engine unavailable")
        score = engine.calculate_behavioral_score(behavioral_result or {}, agent_id or None)
        threshold = engine.check_threshold(score)
        data = score.to_dict()
        data["threshold_check"] = threshold
        return self._result(data)


class CheckRiskThresholdTool(ReasoningTool):
    name = "check_risk_threshold"
    description = "Map a numeric risk score to low/medium/high/critical threshold level."
    category = "risk"

    def run(self, total_score: float = 0.0) -> dict:
        engine = get_engine("risk_scoring_engine")
        if engine is None:
            return self._error("risk_scoring_engine unavailable")
        thresholds = engine.thresholds or {}
        total = float(total_score or 0.0)
        if total >= thresholds.get("critical", 85):
            level = "critical"
        elif total >= thresholds.get("high", 65):
            level = "high"
        elif total >= thresholds.get("medium", 40):
            level = "medium"
        else:
            level = "low"
        return self._result({"level": level, "score": total, "thresholds": thresholds})
