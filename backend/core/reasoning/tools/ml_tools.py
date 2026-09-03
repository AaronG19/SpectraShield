"""ML tools — wrap IsolationForest / OneClassSVM detectors and the behavioral baseliner."""
from typing import Any, Dict

from core.reasoning.tool_executor import ReasoningTool
from core.reasoning.tools._engines import get_engine


def _unpack_prediction(result: Any) -> Dict[str, Any]:
    if isinstance(result, (tuple, list)) and len(result) == 2:
        return {"prediction": result[0], "confidence": result[1]}
    return {"prediction": result}


class PredictAnomalyIForestTool(ReasoningTool):
    name = "predict_anomaly_iforest"
    description = "Predict anomaly using the IsolationForest ML detector."
    category = "ml"

    def run(self, sample: dict = None, agent_id: str = "") -> dict:
        detector = get_engine("iforest_detector")
        if detector is None:
            return self._error("iforest_detector unavailable")
        return self._result(_unpack_prediction(detector.predict(sample or {})))


class PredictAnomalySVMTool(ReasoningTool):
    name = "predict_anomaly_svm"
    description = "Predict anomaly using the OneClassSVM ML detector."
    category = "ml"

    def run(self, sample: dict = None, agent_id: str = "") -> dict:
        detector = get_engine("svm_detector")
        if detector is None:
            return self._error("svm_detector unavailable")
        return self._result(_unpack_prediction(detector.predict(sample or {})))


class CheckBaselineTool(ReasoningTool):
    name = "check_baseline"
    description = "Check agent resource metrics against its learned behavioral baseline."
    category = "ml"

    def run(self, agent_id: str = "", metrics: dict = None) -> dict:
        baseliner = get_engine("behavioral_baseliner")
        if baseliner is None:
            return self._error("behavioral_baseliner unavailable or ML disabled")
        is_anomalous, details = baseliner.is_anomalous(agent_id, metrics or {})
        return self._result({"is_anomalous": bool(is_anomalous), "details": details})


class UpdateBaselineTool(ReasoningTool):
    name = "update_baseline"
    description = "Update an agent's behavioral baseline with current metrics."
    category = "ml"

    def run(self, agent_id: str = "", metrics: dict = None) -> dict:
        baseliner = get_engine("behavioral_baseliner")
        if baseliner is None:
            return self._error("behavioral_baseliner unavailable or ML disabled")
        baseliner.update(agent_id, metrics or {})
        return self._result({"updated": True})
