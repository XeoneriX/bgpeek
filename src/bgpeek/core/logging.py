"""structlog configuration — renderer selection and shared processor chain.

Called once at application startup before the first logger is used. Chooses a
renderer based on `settings.log_format`:

- ``console`` (default) — human-readable colourless output, same shape as the
  structlog default; safe for `docker logs` / interactive tail.
- ``json`` — NDJSON, one event per line. Any external log shipper (Vector,
  promtail, fluent-bit) and our built-in HTTP shipper consume this format
  without a parser.
- ``logfmt`` — ``key=value`` pairs, familiar to Loki/Datadog ingest pipelines.

All events share the same processor prefix so request-id correlation, log
level and ISO-8601 timestamp land in every record regardless of renderer.
"""

from __future__ import annotations

import logging

import structlog

from bgpeek.config import settings

_LEVELS: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "warn": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

_VALID_FORMATS: frozenset[str] = frozenset({"console", "json", "logfmt"})


def configure_logging() -> None:
    """Install the global structlog config. Idempotent — safe to call twice.

    `cache_logger_on_first_use` stays off so reconfiguration at runtime (and
    in tests, where fixtures reshape the pipeline repeatedly) takes effect
    for *already-instantiated* loggers. The per-call overhead is a single
    dict lookup and is negligible in practice.
    """
    level = _LEVELS.get(settings.log_level.lower(), logging.INFO)
    fmt = settings.log_format.lower()
    if fmt not in _VALID_FORMATS:
        fmt = "console"

    shared: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    renderer: structlog.types.Processor
    if fmt == "json":
        renderer = structlog.processors.JSONRenderer()
    elif fmt == "logfmt":
        renderer = structlog.processors.LogfmtRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )
