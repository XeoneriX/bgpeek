"""Query result cache backed by Redis."""

from __future__ import annotations

import hashlib

import structlog

from bgpeek.config import settings
from bgpeek.core.redis import get_redis
from bgpeek.models.query import QueryRequest, QueryResponse

log = structlog.get_logger(__name__)

_KEY_PREFIX = "bgpeek:cache:"


def _cache_key(request: QueryRequest, user_role: str | None = None) -> str:
    """Build a deterministic cache key from the query parameters and caller role.

    The role is part of the key because privileged callers (admin/NOC) bypass
    the output filter in ``execute_query``, so the cached ``QueryResponse``
    contains different data than what a public caller is allowed to see.
    Without a role-scoped key, a public caller hitting a recently-populated
    admin entry for the same target would receive the unfiltered response.
    """
    role = user_role or "anonymous"
    raw = f"{request.device_name}:{request.query_type.value}:{request.target}:{role}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"{_KEY_PREFIX}{request.device_name}:{digest}"


async def get_cached(request: QueryRequest, user_role: str | None = None) -> QueryResponse | None:
    """Return cached response if present, otherwise ``None``."""
    try:
        r = get_redis()
    except RuntimeError:
        return None

    key = _cache_key(request, user_role)
    try:
        data = await r.get(key)
    except Exception:
        log.warning("cache_get_failed", key=key, exc_info=True)
        return None

    if data is None:
        return None

    log.debug("cache_hit", key=key)
    return QueryResponse.model_validate_json(data)


async def set_cached(
    request: QueryRequest,
    response: QueryResponse,
    user_role: str | None = None,
    ttl: int | None = None,
) -> None:
    """Store a query response in cache with the given TTL (seconds)."""
    try:
        r = get_redis()
    except RuntimeError:
        return

    if ttl is None:
        ttl = settings.cache_ttl

    key = _cache_key(request, user_role)
    try:
        await r.set(key, response.model_dump_json(), ex=ttl)
        log.debug("cache_set", key=key, ttl=ttl)
    except Exception:
        log.warning("cache_set_failed", key=key, exc_info=True)


async def invalidate_device(device_name: str) -> None:
    """Delete all cached entries for a device using key prefix scan."""
    try:
        r = get_redis()
    except RuntimeError:
        return

    pattern = f"{_KEY_PREFIX}{device_name}:*"
    try:
        cursor = 0
        deleted = 0
        while True:
            cursor, keys = await r.scan(cursor=cursor, match=pattern, count=100)
            if keys:
                await r.delete(*keys)
                deleted += len(keys)
            if cursor == 0:
                break
        if deleted:
            log.info("cache_invalidated", device_name=device_name, keys_deleted=deleted)
    except Exception:
        log.warning("cache_invalidate_failed", device_name=device_name, exc_info=True)
