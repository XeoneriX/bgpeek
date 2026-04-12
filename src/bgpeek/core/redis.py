"""Process-wide async Redis client."""

from __future__ import annotations

import redis.asyncio as aioredis
import structlog

log = structlog.get_logger(__name__)

_redis: aioredis.Redis | None = None


async def init_redis(url: str) -> aioredis.Redis:
    """Open the global Redis connection. Idempotent if called twice."""
    global _redis
    if _redis is not None:
        return _redis
    log.info("opening redis connection", url=_redact_url(url))
    _redis = aioredis.from_url(url, decode_responses=True)
    # Verify connectivity.
    await _redis.ping()  # type: ignore[misc]
    log.info("redis connected")
    return _redis


def get_redis() -> aioredis.Redis:
    """Return the active Redis client. Raises RuntimeError if not initialised."""
    if _redis is None:
        raise RuntimeError("redis not initialised — call init_redis() first")
    return _redis


async def close_redis() -> None:
    """Close the global Redis client. Safe to call multiple times."""
    global _redis
    if _redis is None:
        return
    log.info("closing redis connection")
    await _redis.aclose()
    _redis = None


def _redact_url(url: str) -> str:
    """Strip password from a Redis URL for logging."""
    if "@" not in url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if "@" not in rest:
        return url
    creds, host = rest.rsplit("@", 1)
    if ":" in creds:
        user, _ = creds.split(":", 1)
        return f"{scheme}://{user}:***@{host}"
    return f"{scheme}://{creds}@{host}"
