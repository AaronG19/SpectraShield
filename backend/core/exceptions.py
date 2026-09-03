class AgentSecurityError(Exception):
    """Base exception for all agent security errors."""

    def __init__(self, message: str, code: str = "UNKNOWN_ERROR", status_code: int = 500):
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(self.message)


class ConfigurationError(AgentSecurityError):
    def __init__(self, message: str):
        super().__init__(message, code="CONFIG_ERROR", status_code=500)


class ValidationError(AgentSecurityError):
    def __init__(self, message: str):
        super().__init__(message, code="VALIDATION_ERROR", status_code=400)


class DetectionError(AgentSecurityError):
    def __init__(self, message: str, detection_type: str = "unknown"):
        super().__init__(message, code=f"DETECTION_{detection_type.upper()}_ERROR", status_code=500)


class ResponseError(AgentSecurityError):
    def __init__(self, message: str, action: str = "unknown"):
        super().__init__(message, code=f"RESPONSE_{action.upper()}_ERROR", status_code=500)


class CorrelationError(AgentSecurityError):
    def __init__(self, message: str):
        super().__init__(message, code="CORRELATION_ERROR", status_code=500)


class RiskScoreError(AgentSecurityError):
    def __init__(self, message: str):
        super().__init__(message, code="RISK_SCORE_ERROR", status_code=500)


class MLNotAvailableError(AgentSecurityError):
    def __init__(self):
        super().__init__("ML module not available. Install scikit-learn.", code="ML_NOT_AVAILABLE", status_code=503)
