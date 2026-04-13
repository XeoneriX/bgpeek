"""Redis-backed circuit breaker for SSH connections to network devices.

Uses Redis sorted sets to track failure timestamps per device. When the number
of recent failures (within the cooldown window) reaches the threshold, the
device is considered "open" (tripped) and queries are rejected until the
window expires.

If Redis is unavailable the breaker degrades gracefully — devices are always
treated as available.
"""

from __future__ import annotations

import time

import structlog

from bgpeek.config import settings

log = structlog.get_logger(__name__)

_KEY_PREFIX = "bgpeek:cb"


def _key(device_name: str) -> str:
    return f"{_KEY_PREFIX}:{device_name}"


async def _get_redis():  # noqa: ANN202
    """Return the Redis client or ``None`` if unavailable."""
    try:
        from bgpeek.core.redis import get_redis

        return get_redis()
    except RuntimeError:
        return None


async def record_failure(device_name: str) -> None:
    """Record an SSH failure for *device_name*."""
    if not settings.circuit_breaker_enabled:
        return

    redis = await _get_redis()
    if redis is None:
        return

    now = time.time()
    key = _key(device_name)
    try:
        async with redis.pipeline(transaction=False) as pipe:
            pipe.zadd(key, {str(now): now})
            # Evict entries older than the cooldown window.
            pipe.zremrangebyscore(key, "-inf", now - settings.circuit_breaker_cooldown)
            pipe.expire(key, settings.circuit_breaker_cooldown)
            await pipe.execute()

        log.warning(
            "circuit_breaker_failure_recorded",
            device=device_name,
            threshold=settings.circuit_breaker_threshold,
        )
    except Exception:
        log.debug("circuit_breaker_redis_error", device=device_name, exc_info=True)


async def record_success(device_name: str) -> None:
    """Clear all recorded failures for *device_name*."""
    if not settings.circuit_breaker_enabled:
        return

    redis = await _get_redis()
    if redis is None:
        return

    try:
        await redis.delete(_key(device_name))
    except Exception:
        log.debug("circuit_breaker_redis_error", device=device_name, exc_info=True)


async def is_device_available(device_name: str) -> bool:
    """Return ``True`` if *device_name* has not tripped the circuit breaker.

    When the breaker is disabled or Redis is unreachable the function returns
    ``True`` (fail-open).
    """
    if not settings.circuit_breaker_enabled:
        return True

    redis = await _get_redis()
    if redis is None:
        return True

    now = time.time()
    key = _key(device_name)
    try:
        # Count failures within the cooldown window.
        count = await redis.zcount(key, now - settings.circuit_breaker_cooldown, "+inf")
        if count >= settings.circuit_breaker_threshold:
            log.info(
                "circuit_breaker_open",
                device=device_name,
                failures=count,
                threshold=settings.circuit_breaker_threshold,
                cooldown=settings.circuit_breaker_cooldown,
            )
            return False
        return True
    except Exception:
        log.debug("circuit_breaker_redis_error", device=device_name, exc_info=True)
        return True
