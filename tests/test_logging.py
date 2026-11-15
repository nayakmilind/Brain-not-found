import logging

import structlog

from app.core.logging import configure_logging


def test_configure_logging_sets_root_level_and_structured_logger() -> None:
    configure_logging("WARNING")

    assert logging.getLogger().level == logging.WARNING
    assert structlog.get_logger("test").isEnabledFor(logging.WARNING)


def test_httpx_request_urls_are_not_logged_at_info_level() -> None:
    configure_logging("INFO")

    assert logging.getLogger("httpx").level == logging.WARNING
