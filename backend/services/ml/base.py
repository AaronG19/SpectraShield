from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class MLDetector(ABC):
    """Abstract base class for all ML-based detectors."""

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @abstractmethod
    def train(self, data: List[Dict[str, Any]], labels: Optional[List[int]] = None) -> dict:
        ...

    @abstractmethod
    def predict(self, sample: Dict[str, Any]) -> Tuple[int, float]:
        ...

    @abstractmethod
    def predict_batch(self, samples: List[Dict[str, Any]]) -> List[Tuple[int, float]]:
        ...


class MLNotAvailable(MLDetector):
    def is_available(self) -> bool:
        return False

    def train(self, data, labels=None):
        raise NotImplementedError("ML module is not available")

    def predict(self, sample):
        raise NotImplementedError("ML module is not available")

    def predict_batch(self, samples):
        raise NotImplementedError("ML module is not available")


class MLFallback(MLDetector):
    def is_available(self) -> bool:
        return False

    def train(self, data, labels=None):
        return {"status": "ml_disabled", "note": "ML detection is disabled. Enable ML_ENABLED=true and install scikit-learn."}

    def predict(self, sample):
        return (0, 0.0)

    def predict_batch(self, samples):
        return [(0, 0.0) for _ in samples]
