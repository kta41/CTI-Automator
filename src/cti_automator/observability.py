"""Content-free structured events and bounded operational metrics."""

from __future__ import annotations

import json
import logging
import sys
import time
from collections.abc import Callable
from contextvars import ContextVar
from datetime import UTC, datetime
from functools import wraps
from typing import ParamSpec, TypeVar
from uuid import uuid4

from prometheus_client import Counter, Histogram

P = ParamSpec("P")
R = TypeVar("R")
_run_id: ContextVar[str | None] = ContextVar("cti_run_id", default=None)
logger = logging.getLogger("cti_automator.operations")
EXECUTIONS = Counter(
    "cti_operations_total", "Completed operations", ["operation", "outcome"]
)
LATENCY = Histogram(
    "cti_operation_seconds",
    "Operation duration",
    ["operation"],
    buckets=(0.01, 0.1, 0.5, 1, 5, 10, 30, 60, 120, 240, 600, 900),
)
ITEMS = Counter("cti_items_total", "Processed items", ["operation"])
QUOTAS = Counter("cti_quota_errors_total", "Enrichment quota errors", ["operation"])
OPERATIONS = frozenset(
    {
        "cli",
        "mcp",
        "otx",
        "threatfox",
        "analysis",
        "opencti",
        "enrichment",
        "repository",
    }
)

for _operation in OPERATIONS:
    for _outcome in ("success", "error"):
        EXECUTIONS.labels(_operation, _outcome).inc(0)
    LATENCY.labels(_operation)
    ITEMS.labels(_operation).inc(0)
    QUOTAS.labels(_operation).inc(0)


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": record.levelname,
                "run_id": getattr(record, "run_id", _run_id.get()),
                "operation": getattr(record, "operation", "unknown"),
                "event": getattr(record, "event", "library"),
                "duration_seconds": getattr(record, "duration_seconds", None),
                "count": getattr(record, "count", None),
                "error_category": getattr(record, "error_category", None),
            }
        )


def configure_logging(level: str = "INFO") -> None:
    normalized = level.upper()
    if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError(
            "CTI_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL"
        )
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter())
    handler.setLevel(normalized)
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(normalized)
    fastmcp_logger = logging.getLogger("fastmcp")
    fastmcp_logger.handlers.clear()
    fastmcp_logger.setLevel(normalized)
    fastmcp_logger.propagate = True
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(normalized)
    logger.propagate = False


def observe(
    operation: str, *, new_run: bool = False
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Instrument boundaries without recording arguments, results or exceptions."""
    if operation not in OPERATIONS:
        raise ValueError("Unregistered operation metric label")

    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        @wraps(function)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            token = _run_id.set(
                str(uuid4()) if new_run else (_run_id.get() or str(uuid4()))
            )
            start = time.monotonic()
            metadata: dict[str, object] = {
                "operation": operation,
                "run_id": _run_id.get(),
            }
            logger.info("operation", extra={**metadata, "event": "start"})
            outcome = "success"
            try:
                result = function(*args, **kwargs)
                count = len(result) if isinstance(result, (tuple, list)) else None
                indicators = getattr(result, "indicators", None)
                if isinstance(indicators, (tuple, list)):
                    count = len(indicators)
                if count is not None:
                    ITEMS.labels(operation).inc(count)
                logger.info(
                    "operation",
                    extra={
                        **metadata,
                        "event": "end",
                        "count": count,
                        "duration_seconds": time.monotonic() - start,
                    },
                )
                return result
            except Exception as exc:
                outcome = "error"
                category = type(exc).__name__
                if category == "QuotaError":
                    QUOTAS.labels(operation).inc()
                logger.error(
                    "operation",
                    extra={
                        **metadata,
                        "event": "error",
                        "error_category": category,
                        "duration_seconds": time.monotonic() - start,
                    },
                )
                raise
            finally:
                EXECUTIONS.labels(operation, outcome).inc()
                LATENCY.labels(operation).observe(time.monotonic() - start)
                _run_id.reset(token)

        return wrapped

    return decorate
