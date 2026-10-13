"""Domain exceptions raised by CTI Automator connectors."""


class CTIAutomatorError(Exception):
    """Base exception for expected application-level failures."""


class ConnectorError(CTIAutomatorError):
    """Raised when an external CTI connector cannot return valid data."""

