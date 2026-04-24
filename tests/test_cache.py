"""Tests for the Redis query cache layer."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from bgpeek.core.cache import _KEY_PREFIX, _cache_key, get_cached, invalidate_device, set_cached
from bgpeek.models.query import QueryRequest, QueryResponse, QueryType


def _make_request(
    device: str = "rt1",
    query_type: QueryType = QueryType.BGP_ROUTE,
    target: str = "8.8.8.0/24",
) -> QueryRequest:
    return QueryRequest(device_name=device, query_type=query_type, target=target)


def _make_response(device: str = "rt1", target: str = "8.8.8.0/24") -> QueryResponse:
    return QueryResponse(
        device_name=device,
        query_type=QueryType.BGP_ROUTE,
        target=target,
        command="show route 8.8.8.0/24",
        raw_output="8.8.8.0/24 via 10.0.0.1",
        filtered_output="8.8.8.0/24 via 10.0.0.1",
        runtime_ms=42,
    )


def test_cache_key_deterministic() -> None:
    req = _make_request()
    assert _cache_key(req) == _cache_key(req)


def test_cache_key_includes_prefix() -> None:
    req = _make_request()
    key = _cache_key(req)
    assert key.startswith(_KEY_PREFIX)


def test_cache_key_includes_device_name() -> None:
    req = _make_request(device="edge-01")
    key = _cache_key(req)
    assert key.startswith(f"{_KEY_PREFIX}edge-01:")


def test_cache_key_varies_by_target() -> None:
    k1 = _cache_key(_make_request(target="1.1.1.0/24"))
    k2 = _cache_key(_make_request(target="2.2.2.0/24"))
    assert k1 != k2


def test_cache_key_varies_by_query_type() -> None:
    k1 = _cache_key(_make_request(query_type=QueryType.BGP_ROUTE))
    k2 = _cache_key(_make_request(query_type=QueryType.PING))
    assert k1 != k2


def test_cache_key_varies_by_device() -> None:
    k1 = _cache_key(_make_request(device="rt1"))
    k2 = _cache_key(_make_request(device="rt2"))
    assert k1 != k2


def test_cache_key_varies_by_user_role() -> None:
    req = _make_request()
    k_admin = _cache_key(req, user_role="admin")
    k_noc = _cache_key(req, user_role="noc")
    k_public = _cache_key(req, user_role="public")
    k_anon = _cache_key(req, user_role=None)
    assert len({k_admin, k_noc, k_public, k_anon}) == 4


def test_cache_key_anonymous_is_default() -> None:
    """Calling `_cache_key` without a role matches calling it with ``None``."""
    req = _make_request()
    assert _cache_key(req) == _cache_key(req, user_role=None)


async def test_get_cached_returns_none_when_redis_unavailable() -> None:
    with patch("bgpeek.core.cache.get_redis", side_effect=RuntimeError):
        result = await get_cached(_make_request())
    assert result is None


async def test_get_cached_returns_none_on_miss() -> None:
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    with patch("bgpeek.core.cache.get_redis", return_value=mock_redis):
        result = await get_cached(_make_request())
    assert result is None


async def test_get_set_roundtrip() -> None:
    store: dict[str, str] = {}
    mock_redis = AsyncMock()

    async def mock_set(key: str, value: str, ex: int | None = None) -> None:
        store[key] = value

    async def mock_get(key: str) -> str | None:
        return store.get(key)

    mock_redis.set = mock_set
    mock_redis.get = mock_get

    req = _make_request()
    resp = _make_response()

    with patch("bgpeek.core.cache.get_redis", return_value=mock_redis):
        await set_cached(req, resp, ttl=120)
        cached = await get_cached(req)

    assert cached is not None
    assert cached.device_name == resp.device_name
    assert cached.filtered_output == resp.filtered_output
    assert cached.runtime_ms == resp.runtime_ms


async def test_set_cached_noop_when_redis_unavailable() -> None:
    with patch("bgpeek.core.cache.get_redis", side_effect=RuntimeError):
        await set_cached(_make_request(), _make_response())


async def test_admin_cached_response_does_not_leak_to_public() -> None:
    """Regression: privileged callers bypass the output filter, so their cached
    response contains unfiltered prefixes and attributes. A subsequent public
    hit on the same target must miss the cache rather than serve the admin
    payload — the role-scoped key guarantees isolation."""
    store: dict[str, str] = {}
    mock_redis = AsyncMock()

    async def mock_set(key: str, value: str, ex: int | None = None) -> None:
        store[key] = value

    async def mock_get(key: str) -> str | None:
        return store.get(key)

    mock_redis.set = mock_set
    mock_redis.get = mock_get

    req = _make_request()
    admin_response = _make_response()
    admin_response.filtered_output = "8.8.8.0/28 via 10.0.0.1  # privileged view"

    with patch("bgpeek.core.cache.get_redis", return_value=mock_redis):
        await set_cached(req, admin_response, user_role="admin")
        public_hit = await get_cached(req, user_role="public")
        anon_hit = await get_cached(req, user_role=None)
        admin_roundtrip = await get_cached(req, user_role="admin")

    assert public_hit is None
    assert anon_hit is None
    assert admin_roundtrip is not None
    assert admin_roundtrip.filtered_output == admin_response.filtered_output


async def test_invalidate_device_scans_and_deletes() -> None:
    mock_redis = AsyncMock()
    keys = [f"{_KEY_PREFIX}rt1:abc", f"{_KEY_PREFIX}rt1:def"]
    mock_redis.scan = AsyncMock(return_value=(0, keys))
    mock_redis.delete = AsyncMock()

    with patch("bgpeek.core.cache.get_redis", return_value=mock_redis):
        await invalidate_device("rt1")

    mock_redis.delete.assert_awaited_once_with(*keys)


async def test_invalidate_device_noop_when_redis_unavailable() -> None:
    with patch("bgpeek.core.cache.get_redis", side_effect=RuntimeError):
        await invalidate_device("rt1")


async def test_invalidate_device_no_keys() -> None:
    mock_redis = AsyncMock()
    mock_redis.scan = AsyncMock(return_value=(0, []))
    mock_redis.delete = AsyncMock()

    with patch("bgpeek.core.cache.get_redis", return_value=mock_redis):
        await invalidate_device("rt1")

    mock_redis.delete.assert_not_awaited()


async def test_query_pipeline_returns_cached_on_second_call() -> None:
    from ipaddress import IPv4Address
    from unittest.mock import patch as _patch

    import asyncpg

    from bgpeek.core.query import execute_query
    from bgpeek.models.credential import Credential
    from bgpeek.models.device import Device

    store: dict[str, str] = {}
    mock_redis = AsyncMock()

    async def mock_set(key: str, value: str, ex: int | None = None) -> None:
        store[key] = value

    async def mock_get(key: str) -> str | None:
        return store.get(key)

    mock_redis.set = mock_set
    mock_redis.get = mock_get

    # This test uses full mocking to avoid needing a real DB + Redis.
    mock_ssh = AsyncMock()
    mock_ssh.__aenter__ = AsyncMock(return_value=mock_ssh)
    mock_ssh.__aexit__ = AsyncMock(return_value=False)
    mock_ssh.send_command = AsyncMock(return_value="8.8.8.0/24 via 10.0.0.1")

    now = datetime.now(tz=UTC)
    device_obj = Device(
        id=1,
        name="rt1",
        address=IPv4Address("10.0.0.1"),
        platform="juniper_junos",
        port=22,
        enabled=True,
        created_at=now,
        updated_at=now,
    )

    cred_obj = Credential(
        id=1,
        name="default",
        username="looking-glass",
        auth_type="key",
        key_name="default.key",
        created_at=now,
        updated_at=now,
    )

    mock_pool = AsyncMock(spec=asyncpg.Pool)
    req = _make_request()

    with (
        _patch("bgpeek.core.cache.get_redis", return_value=mock_redis),
        _patch("bgpeek.core.query.get_pool", return_value=mock_pool),
        _patch("bgpeek.core.query.device_crud.get_device_by_name", return_value=device_obj),
        _patch("bgpeek.core.query.get_credential_for_device", return_value=cred_obj),
        _patch("bgpeek.core.query.SSHClient", return_value=mock_ssh),
        _patch("bgpeek.core.query.log_audit", return_value=None),
    ):
        # First call — cache miss, SSH executed.
        r1 = await execute_query(req)
        assert r1.cached is False

        # Second call — should be a cache hit.
        r2 = await execute_query(req)
        assert r2.cached is True
        assert r2.filtered_output == r1.filtered_output
