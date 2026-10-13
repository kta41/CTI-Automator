"""Domain exceptions raised by CTI Automator connectors."""


class CTIAutomatorError(Exception):
    """Base exception for expected application-level failures."""


class ConnectorError(CTIAutomatorError):
    """Raised when an external CTI connector cannot return valid data."""


class DocumentExtractionError(CTIAutomatorError):
    """Raised when a PDF cannot be read or contains no extractable text."""


class LLMResponseError(CTIAutomatorError):
    """Raised when Ollama is unavailable or returns invalid structured data."""
