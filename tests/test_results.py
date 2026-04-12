"""Tests for shareable query results with UUID permalinks."""

from __future__ import annotations

import uuid

import asyncpg

from bgpeek.db.results import cleanup_expired, get_result, list_results, save_result
from bgpeek.models.query import BGPRoute, QueryResponse, QueryType


def _make_response(**overrides: object) -> QueryResponse:
    defaults: dict[str, object] = {
        "device_name": "rt1",
        "query_type": QueryType.BGP_ROUTE,
        "target": "8.8.8.0/24",
        "command": "show route 8.8.8.0/24",
        "raw_output": "8.8.8.0/24 via 10.0.0.1",
        "filtered_output": "8.8.8.0/24 via 10.0.0.1",
        "runtime_ms": 42,
        "parsed_routes": [
            BGPRoute(prefix="8.8.8.0/24", next_hop="10.0.0.1", as_path="15169", best=True)
        ],
    }
    defaults.update(overrides)
    return QueryResponse(**defaults)  # type: ignore[arg-type]


async def test_save_and_get_roundtrip(pool: asyncpg.Pool) -> None:
    response = _make_response()
    result_id = await save_result(pool, response, user_id=None, username="tester", ttl_days=7)

    stored = await get_result(pool, result_id)
    assert stored is not None
    assert stored.id == result_id
    assert stored.device_name == "rt1"
    assert stored.query_type == QueryType.BGP_ROUTE
    assert stored.target == "8.8.8.0/24"
    assert stored.command == "show route 8.8.8.0/24"
    assert stored.raw_output == "8.8.8.0/24 via 10.0.0.1"
    assert stored.filtered_output == "8.8.8.0/24 via 10.0.0.1"
    assert stored.runtime_ms == 42
    assert stored.username == "tester"
    assert len(stored.parsed_routes) == 1
    assert stored.parsed_routes[0].prefix == "8.8.8.0/24"
    assert stored.parsed_routes[0].best is True
    assert stored.expires_at > stored.created_at


async def test_get_result_missing(pool: asyncpg.Pool) -> None:
    result = await get_result(pool, uuid.uuid4())
    assert result is None


async def test_get_result_expired(pool: asyncpg.Pool) -> None:
    response = _make_response()
    result_id = await save_result(pool, response, user_id=None, username=None, ttl_days=7)
    # Force expiration
    await pool.execute(
        "UPDATE query_results SET expires_at = now() - interval '1 second' WHERE id = $1",
        result_id,
    )

    stored = await get_result(pool, result_id)
    assert stored is None


async def test_list_results_ordering(pool: asyncpg.Pool) -> None:
    for target in ["1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24"]:
        await save_result(
            pool,
            _make_response(target=target),
            user_id=None,
            username=None,
            ttl_days=7,
        )

    results = await list_results(pool)
    assert len(results) == 3
    # Newest first
    assert results[0].target == "3.0.0.0/24"
    assert results[2].target == "1.0.0.0/24"


async def test_list_results_user_filter(pool: asyncpg.Pool) -> None:
    # Create a user to reference
    user_id = await pool.fetchval(
        "INSERT INTO users (username, auth_provider) VALUES ($1, $2) RETURNING id",
        "alice",
        "local",
    )
    other_id = await pool.fetchval(
        "INSERT INTO users (username, auth_provider) VALUES ($1, $2) RETURNING id",
        "bob",
        "local",
    )

    await save_result(
        pool, _make_response(target="1.0.0.0/24"), user_id=user_id, username="alice", ttl_days=7
    )
    await save_result(
        pool, _make_response(target="2.0.0.0/24"), user_id=other_id, username="bob", ttl_days=7
    )

    alice_results = await list_results(pool, user_id=user_id)
    assert len(alice_results) == 1
    assert alice_results[0].target == "1.0.0.0/24"


async def test_cleanup_expired(pool: asyncpg.Pool) -> None:
    rid1 = await save_result(
        pool, _make_response(target="1.0.0.0/24"), user_id=None, username=None, ttl_days=7
    )
    rid2 = await save_result(
        pool, _make_response(target="2.0.0.0/24"), user_id=None, username=None, ttl_days=7
    )

    # Expire one
    await pool.execute(
        "UPDATE query_results SET expires_at = now() - interval '1 second' WHERE id = $1",
        rid1,
    )

    deleted = await cleanup_expired(pool)
    assert deleted == 1

    # The non-expired one is still there
    assert await get_result(pool, rid2) is not None
    assert await get_result(pool, rid1) is None


async def test_list_results_excludes_expired(pool: asyncpg.Pool) -> None:
    rid = await save_result(pool, _make_response(), user_id=None, username=None, ttl_days=7)
    await pool.execute(
        "UPDATE query_results SET expires_at = now() - interval '1 second' WHERE id = $1",
        rid,
    )

    results = await list_results(pool)
    assert len(results) == 0


async def test_save_result_with_user_id(pool: asyncpg.Pool) -> None:
    user_id = await pool.fetchval(
        "INSERT INTO users (username, auth_provider) VALUES ($1, $2) RETURNING id",
        "testuser",
        "local",
    )
    result_id = await save_result(
        pool, _make_response(), user_id=user_id, username="testuser", ttl_days=30
    )
    stored = await get_result(pool, result_id)
    assert stored is not None
    assert stored.user_id == user_id
    assert stored.username == "testuser"
