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
from collections.abc import MutableMapping
from typing import Any

import structlog

from bgpeek.config import settings
from bgpeek.core.log_shipper import _shipping_processor

_LEVELS: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "warn": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

_VALID_FORMATS: frozenset[str] = frozenset({"console", "json", "logfmt"})

# Substrings (case-insensitive) that mark a log-field value as too sensitive to
# emit. Matches keys like ``password``, ``Api-Key``, ``X-Auth-Token``, etc. The
# redactor runs before ``_shipping_processor``, so the remote sink never sees
# the raw secret even if a log line accidentally bound one.
_SECRET_KEY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "api_key",
    "apikey",
    "secret",
    "token",
    "authorization",
    "auth_header",
    "encryption_key",
    "bind_password",
    "client_secret",
    "jwt_secret",
    "session_secret",
    "cookie",
)
_REDACTED = "***"


def _redact_secrets(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Replace values whose *key* looks secret-shaped with ``***``.

    Keyed by substring match on the field name (case-insensitive). We do not
    scan values — a free-form ``error`` or ``raw_output`` string is left alone
    because a value-scan produces too many false positives and cannot reliably
    redact. Callers who know a value is sensitive must name the field
    accordingly (``password=...``, ``api_key=...``).
    """
    for key in list(event_dict.keys()):
        lowered = key.lower()
        if any(sub in lowered for sub in _SECRET_KEY_SUBSTRINGS):
            if event_dict[key] not in (None, ""):
                event_dict[key] = _REDACTED
    return event_dict


def _add_service(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Attach `service=<name>` so downstream log backends can partition by deployment."""
    event_dict.setdefault("service", settings.service_name or "bgpeek")
    return event_dict


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
        _add_service,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        _redact_secrets,
    ]

    renderer: structlog.types.Processor
    if fmt == "json":
        renderer = structlog.processors.JSONRenderer()
    elif fmt == "logfmt":
        renderer = structlog.processors.LogfmtRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    # The shipper processor captures a snapshot of the structured event
    # *before* the final renderer turns it into a console/json/logfmt string.
    # It is a no-op when `BGPEEK_LOG_SHIP_URL` is unset.
    structlog.configure(
        processors=[*shared, _shipping_processor, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )
