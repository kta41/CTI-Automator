"""Core package for CTI Automator."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cti-automator")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
