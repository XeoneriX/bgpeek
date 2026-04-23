"""Redis-backed JWT revocation list.

Tokens carry a random ``jti`` claim (see :func:`bgpeek.core.jwt.create_token`).
Logout writes ``bgpeek:jwt_revoked:<jti>`` to Redis with a TTL equal to the
token's remaining lifetime, so the entry disappears the moment the JWT would
have expired anyway — no unbounded growth. The auth resolver checks the key
before accepting a JWT.

If Redis is unavailable the revocation layer fails open: tokens are treated
as valid, same graceful-degradation pattern we use for the rate limiter and
circuit breaker. Losing logout-revocation on a Redis outage is a strictly
smaller blast radius than refusing every authenticated request.
"""

from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger(__name__)

_KEY_PREFIX = "bgpeek:jwt_revoked"


def _key(jti: str) -> str:
    return f"{_KEY_PREFIX}:{jti}"


async def _get_redis() -> Any | None:
    """Return the Redis client or ``None`` if unavailable."""
    try:
        from bgpeek.core.redis import get_redis

        return get_redis()
    except RuntimeError:
        return None


async def revoke(jti: str, ttl_seconds: int) -> None:
    """Mark ``jti`` as revoked for ``ttl_seconds``. No-op if Redis is down.

    ``ttl_seconds`` should be the JWT's remaining lifetime (``exp - now``).
    Using a longer TTL wastes Redis memory; using a shorter one would let a
    revoked token become valid again before the natural expiry. Callers that
    can't compute the remaining lifetime cleanly should pass the full
    ``settings.jwt_expire_minutes * 60`` and accept the small over-retention.
    """
    if ttl_seconds <= 0:
        return  # already expired — no need to track
    redis = await _get_redis()
    if redis is None:
        log.warning("jwt_revoke_redis_unavailable", jti=jti)
        return
    try:
        await redis.setex(_key(jti), ttl_seconds, "1")
    except Exception:
        log.warning("jwt_revoke_redis_error", jti=jti, exc_info=True)


async def is_revoked(jti: str) -> bool:
    """Return True if ``jti`` is currently on the revocation list.

    Fail-open on Redis errors so an outage can't lock out every authenticated
    user. The log warning lets us notice the degradation.
    """
    redis = await _get_redis()
    if redis is None:
        return False
    try:
        return bool(await redis.exists(_key(jti)))
    except Exception:
        log.warning("jwt_revoke_redis_error", jti=jti, exc_info=True)
        return False
