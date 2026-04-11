"""Process-wide asyncpg connection pool."""

from __future__ import annotations

import asyncpg
import structlog

log = structlog.get_logger(__name__)

_pool: asyncpg.Pool | None = None


async def init_pool(dsn: str, *, min_size: int = 2, max_size: int = 10) -> asyncpg.Pool:
    """Open the global asyncpg pool. Idempotent if called twice with the same DSN."""
    global _pool
    if _pool is not None:
        return _pool
    log.info("opening db pool", dsn=_redact_dsn(dsn), min_size=min_size, max_size=max_size)
    _pool = await asyncpg.create_pool(
        dsn=dsn,
        min_size=min_size,
        max_size=max_size,
        command_timeout=30,
    )
    return _pool


def get_pool() -> asyncpg.Pool:
    """Return the active pool. Raises RuntimeError if `init_pool` was not called."""
    if _pool is None:
        raise RuntimeError("db pool not initialised — call init_pool() first")
    return _pool


async def close_pool() -> None:
    """Close the global pool. Safe to call multiple times."""
    global _pool
    if _pool is None:
        return
    log.info("closing db pool")
    await _pool.close()
    _pool = None


def _redact_dsn(dsn: str) -> str:
    """Strip the password from a DSN for logging."""
    if "@" not in dsn or "://" not in dsn:
        return dsn
    scheme, rest = dsn.split("://", 1)
    if "@" not in rest:
        return dsn
    creds, host = rest.rsplit("@", 1)
    if ":" in creds:
        user, _ = creds.split(":", 1)
        return f"{scheme}://{user}:***@{host}"
    return f"{scheme}://{creds}@{host}"
