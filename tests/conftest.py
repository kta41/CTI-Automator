import logging

import pytest

from cti_automator.observability import logger


@pytest.fixture(autouse=True)
def restore_application_logging():
    root = logging.getLogger()
    root_handlers, root_level = root.handlers[:], root.level
    handlers, level, propagate = logger.handlers[:], logger.level, logger.propagate
    fastmcp = logging.getLogger("fastmcp")
    fast_handlers, fast_level, fast_propagate = (
        fastmcp.handlers[:],
        fastmcp.level,
        fastmcp.propagate,
    )
    yield
    root.handlers, root.level = root_handlers, root_level
    logger.handlers, logger.level, logger.propagate = handlers, level, propagate
    fastmcp.handlers, fastmcp.level, fastmcp.propagate = (
        fast_handlers,
        fast_level,
        fast_propagate,
    )
