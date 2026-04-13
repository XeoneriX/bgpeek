"""Sliding-window rate limiter backed by Redis sorted sets."""

from __future__ import annotations

import time
from dataclasses import dataclass

import structlog
from fastapi import Depends, HTTPException, Request, Response, status

from bgpeek.config import settings
from bgpeek.core.auth import authenticate, optional_auth
from bgpeek.core.redis import get_redis
from bgpeek.models.user import User, UserRole

log = structlog.get_logger(__name__)

_KEY_PREFIX = "bgpeek:rl"


def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting X-Forwarded-For behind trusted proxies."""
    client_ip = request.client.host if request.client else "unknown"
    if not settings.trusted_proxies:
        return client_ip
    trusted = {ip.strip() for ip in settings.trusted_proxies.split(",") if ip.strip()}
    if client_ip in trusted:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # Take the last untrusted IP in the chain
            ips = [ip.strip() for ip in forwarded.split(",")]
            for ip in reversed(ips):
                if ip not in trusted:
                    return ip
            return ips[0]  # all trusted, use first
    return client_ip


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Outcome of a rate-limit check."""

    allowed: bool
    limit: int
    remaining: int
    reset: int  # seconds until window resets


async def check_rate_limit(
    key: str,
    limit: int,
    window: int = 60,
) -> RateLimitResult:
    """Check whether *key* has exceeded *limit* requests in *window* seconds.

    Uses a Redis sorted set with timestamps as scores (sliding window).
    If Redis is unavailable the request is always allowed (graceful degradation).
    """
    try:
        redis = get_redis()
    except RuntimeError:
        log.warning("rate_limit_redis_unavailable", key=key)
        return RateLimitResult(allowed=True, limit=limit, remaining=limit, reset=0)

    now = time.time()
    window_start = now - window
    full_key = f"{_KEY_PREFIX}:{key}"

    try:
        pipe = redis.pipeline(transaction=True)
        pipe.zremrangebyscore(full_key, 0, window_start)
        pipe.zcard(full_key)
        results = await pipe.execute()
        count: int = results[1]

        if count < limit:
            pipe2 = redis.pipeline(transaction=True)
            pipe2.zadd(full_key, {str(now): now})
            pipe2.expire(full_key, window + 1)
            await pipe2.execute()
            remaining = limit - count - 1
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=max(remaining, 0),
                reset=window,
            )

        # Over limit — find when the oldest entry in the window expires.
        oldest = await redis.zrange(full_key, 0, 0, withscores=True)
        reset = int(oldest[0][1] + window - now) + 1 if oldest else window
        return RateLimitResult(
            allowed=False,
            limit=limit,
            remaining=0,
            reset=max(reset, 1),
        )
    except Exception:
        log.warning("rate_limit_redis_error", key=key, exc_info=True)
        return RateLimitResult(allowed=True, limit=limit, remaining=limit, reset=0)


def _set_headers(response: Response, result: RateLimitResult) -> None:
    """Attach standard rate-limit headers to *response*."""
    response.headers["X-RateLimit-Limit"] = str(result.limit)
    response.headers["X-RateLimit-Remaining"] = str(result.remaining)
    response.headers["X-RateLimit-Reset"] = str(result.reset)


def _effective_limit(base_limit: int, user: User | None) -> int:
    """Return the effective limit: admins bypass, NOC gets 2x."""
    if user is not None and user.role == UserRole.ADMIN:
        return 0  # sentinel: bypass
    if user is not None and user.role == UserRole.NOC:
        return base_limit * 2
    return base_limit


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


async def rate_limit_query(
    request: Request,
    response: Response,
    caller: User | None = Depends(optional_auth),  # noqa: B008
) -> None:
    """Per-IP query rate limit. Admins bypass; NOC gets 2x."""
    if not settings.rate_limit_enabled:
        return

    limit = _effective_limit(settings.rate_limit_query, caller)
    if limit == 0:
        return  # admin bypass

    ip = _get_client_ip(request)
    result = await check_rate_limit(f"query:{ip}", limit)
    _set_headers(response, result)

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate limit exceeded",
            headers={
                "Retry-After": str(result.reset),
                "X-RateLimit-Limit": str(result.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(result.reset),
            },
        )


async def rate_limit_login(
    request: Request,
    response: Response,
) -> None:
    """Per-IP login rate limit."""
    if not settings.rate_limit_enabled:
        return

    ip = _get_client_ip(request)
    result = await check_rate_limit(f"login:{ip}", settings.rate_limit_login)
    _set_headers(response, result)

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts",
            headers={
                "Retry-After": str(result.reset),
                "X-RateLimit-Limit": str(result.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(result.reset),
            },
        )


async def rate_limit_api(
    request: Request,
    response: Response,
    caller: User = Depends(authenticate),  # noqa: B008
) -> None:
    """Per-user API rate limit (identified by user id). Admins bypass; NOC 2x."""
    if not settings.rate_limit_enabled:
        return

    limit = _effective_limit(settings.rate_limit_api, caller)
    if limit == 0:
        return  # admin bypass

    identifier = str(caller.id)
    result = await check_rate_limit(f"api:{identifier}", limit)
    _set_headers(response, result)

    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="API rate limit exceeded",
            headers={
                "Retry-After": str(result.reset),
                "X-RateLimit-Limit": str(result.limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(result.reset),
            },
        )
