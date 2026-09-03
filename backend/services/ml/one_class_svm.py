from typing import Any, Dict, List, Optional, Tuple

from services.ml.base import MLDetector, MLNotAvailable

try:
    import numpy as np
    from sklearn.svm import OneClassSVM as SKOneClassSVM
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class OneClassSVMDetector(MLDetector):
    def __init__(
        self,
        nu: float = 0.1,
        kernel: str = "rbf",
        gamma: str = "auto",
    ):
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        self._model = None
        self._feature_names: List[str] = []
        self._trained = False

    def is_available(self) -> bool:
        return SKLEARN_AVAILABLE

    def _require_sklearn(self):
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn is not installed. Install with: pip install scikit-learn")

    def train(self, data: List[Dict[str, Any]], labels: Optional[List[int]] = None) -> dict:
        self._require_sklearn()
        if not data:
            return {"status": "error", "message": "No training data provided"}

        self._feature_names = list(data[0].keys())
        X = np.array([[d[k] for k in self._feature_names] for d in data])

        self._model = SKOneClassSVM(nu=self.nu, kernel=self.kernel, gamma=self.gamma)
        self._model.fit(X)
        self._trained = True

        n_outliers = sum(1 for p in self._model.predict(X) if p == -1)
        return {
            "status": "trained",
            "samples": len(data),
            "features": len(self._feature_names),
            "outliers_detected": n_outliers,
            "nu": self.nu,
        }

    def predict(self, sample: Dict[str, Any]) -> Tuple[int, float]:
        self._require_sklearn()
        if not self._trained:
            return (0, 0.0)

        X = np.array([[sample.get(k, 0) for k in self._feature_names]])
        pred = self._model.predict(X)[0]
        score = self._model.score_samples(X)[0]
        is_outlier = 1 if pred == -1 else 0
        return (is_outlier, float(score))

    def predict_batch(self, samples: List[Dict[str, Any]]) -> List[Tuple[int, float]]:
        self._require_sklearn()
        if not self._trained:
            return [(0, 0.0) for _ in samples]

        X = np.array([[s.get(k, 0) for k in self._feature_names] for s in samples])
        preds = self._model.predict(X)
        scores = self._model.score_samples(X)
        return [
            (1 if p == -1 else 0, float(s))
            for p, s in zip(preds, scores)
        ]

    def get_model_info(self) -> dict:
        return {
            "type": "OneClassSVM",
            "available": self.is_available(),
            "trained": self._trained,
            "features": self._feature_names,
            "nu": self.nu,
            "kernel": self.kernel,
        }


def create_if_available(**kwargs) -> MLDetector:
    if SKLEARN_AVAILABLE:
        return OneClassSVMDetector(**kwargs)
    return MLNotAvailable()
