"""Domain exceptions raised by CTI Automator connectors."""


class CTIAutomatorError(Exception):
    """Base exception for expected application-level failures."""


class ConnectorError(CTIAutomatorError):
    """Raised when an external CTI connector cannot return valid data."""


class DocumentExtractionError(CTIAutomatorError):
    """Raised when a PDF cannot be read or contains no extractable text."""


class LLMResponseError(CTIAutomatorError):
    """Raised when Ollama is unavailable or returns invalid structured data."""


class ExportError(CTIAutomatorError):
    """Raised when intelligence cannot be represented or delivered."""


class SanitizationError(CTIAutomatorError):
    """Raised when DLP policy enforcement fails before any LLM call."""


class DetectionRuleError(CTIAutomatorError):
    """Raised when defensive rules cannot be generated or validated."""


class MemoryStoreError(CTIAutomatorError):
    """Raised when historical memory is unavailable or returns invalid data."""


class SecOpsError(CTIAutomatorError):
    """Raised when a SecOps case cannot be delivered or reconciled."""


class NotificationError(CTIAutomatorError):
    """Raised when a ChatOps notification cannot be delivered."""
