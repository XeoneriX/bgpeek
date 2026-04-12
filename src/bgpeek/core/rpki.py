"""RPKI validation for BGP routes via Cloudflare's RPKI API."""

from __future__ import annotations

import asyncio
from enum import StrEnum

import httpx
import structlog

from bgpeek.config import settings
from bgpeek.core.redis import get_redis
from bgpeek.models.query import BGPRoute

log = structlog.get_logger(__name__)

_REDIS_KEY_PREFIX = "bgpeek:rpki:"


class RpkiStatus(StrEnum):
    """RPKI validation status for a BGP route."""

    VALID = "valid"
    INVALID = "invalid"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"


def _extract_origin_asn(as_path: str) -> int | None:
    """Extract the origin ASN (last AS number) from an AS path string."""
    if not as_path or not as_path.strip():
        return None
    parts = as_path.strip().split()
    for part in reversed(parts):
        if part.isdigit():
            return int(part)
    return None


def _redis_key(prefix: str, asn: int) -> str:
    """Build a Redis cache key for an RPKI lookup."""
    return f"{_REDIS_KEY_PREFIX}{asn}:{prefix}"


async def _get_cached_status(prefix: str, asn: int) -> RpkiStatus | None:
    """Return cached RPKI status if present, otherwise None."""
    try:
        r = get_redis()
    except RuntimeError:
        return None
    try:
        data = await r.get(_redis_key(prefix, asn))
    except Exception:
        log.warning("rpki_cache_get_failed", prefix=prefix, asn=asn, exc_info=True)
        return None
    if data is None:
        return None
    try:
        return RpkiStatus(data)
    except ValueError:
        return None


async def _set_cached_status(prefix: str, asn: int, status: RpkiStatus) -> None:
    """Store RPKI status in Redis with configured TTL."""
    try:
        r = get_redis()
    except RuntimeError:
        return
    try:
        await r.set(
            _redis_key(prefix, asn),
            status.value,
            ex=settings.rpki_cache_ttl,
        )
    except Exception:
        log.warning("rpki_cache_set_failed", prefix=prefix, asn=asn, exc_info=True)


async def validate_rpki(prefix: str, origin_asn: int) -> RpkiStatus:
    """Check RPKI validity for a prefix+origin pair via Cloudflare API."""
    # Check cache first
    cached = await _get_cached_status(prefix, origin_asn)
    if cached is not None:
        log.debug("rpki_cache_hit", prefix=prefix, asn=origin_asn, status=cached)
        return cached

    url = f"{settings.rpki_api_url}/AS{origin_asn}/{prefix}"
    try:
        async with httpx.AsyncClient(timeout=settings.rpki_timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, httpx.TimeoutException, ValueError):
        log.warning("rpki_api_failed", prefix=prefix, asn=origin_asn, exc_info=True)
        status = RpkiStatus.UNKNOWN
        await _set_cached_status(prefix, origin_asn, status)
        return status

    # Cloudflare response: {"prefix": ..., "asn": ..., "state": "Valid"/"Invalid"/"NotFound"}
    raw_state = data.get("state", "").lower()
    if raw_state == "valid":
        status = RpkiStatus.VALID
    elif raw_state == "invalid":
        status = RpkiStatus.INVALID
    elif raw_state in ("notfound", "not found"):
        status = RpkiStatus.NOT_FOUND
    else:
        status = RpkiStatus.UNKNOWN

    await _set_cached_status(prefix, origin_asn, status)
    log.debug("rpki_validated", prefix=prefix, asn=origin_asn, status=status)
    return status


async def validate_routes(routes: list[BGPRoute]) -> list[BGPRoute]:
    """Enrich parsed routes with RPKI validation status.

    Deduplicates lookups: the same (prefix, origin_asn) pair is only queried once.
    """
    if not settings.rpki_enabled:
        return routes

    # Build a map of unique (prefix, origin_asn) pairs
    pairs: dict[tuple[str, int], list[int]] = {}
    for idx, route in enumerate(routes):
        asn = _extract_origin_asn(route.as_path or "")
        if asn is None:
            route.rpki_status = RpkiStatus.UNKNOWN
            continue
        key = (route.prefix, asn)
        pairs.setdefault(key, []).append(idx)

    if not pairs:
        return routes

    # Query all unique pairs concurrently
    keys = list(pairs.keys())
    results = await asyncio.gather(
        *(validate_rpki(prefix, asn) for prefix, asn in keys),
        return_exceptions=True,
    )

    # Assign results back to routes
    for (prefix, asn), result in zip(keys, results, strict=True):
        if isinstance(result, BaseException):
            log.warning("rpki_validate_exception", prefix=prefix, asn=asn, error=str(result))
            status = RpkiStatus.UNKNOWN
        else:
            status = result
        for idx in pairs[(prefix, asn)]:
            routes[idx].rpki_status = status.value

    return routes
