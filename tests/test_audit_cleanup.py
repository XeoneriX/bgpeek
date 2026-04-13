"""Tests for audit log cleanup."""

from __future__ import annotations

from unittest.mock import AsyncMock

import asyncpg

from bgpeek.db.audit import cleanup_old_entries


async def test_cleanup_calls_delete_with_interval() -> None:
    pool = AsyncMock(spec=asyncpg.Pool)
    pool.execute = AsyncMock(return_value="DELETE 42")
    result = await cleanup_old_entries(pool, ttl_days=90)
    pool.execute.assert_awaited_once()
    args = pool.execute.call_args
    assert "make_interval" in args[0][0]
    assert args[0][1] == 90
    assert result == 42


async def test_cleanup_returns_zero_when_no_rows_deleted() -> None:
    pool = AsyncMock(spec=asyncpg.Pool)
    pool.execute = AsyncMock(return_value="DELETE 0")
    result = await cleanup_old_entries(pool, ttl_days=30)
    assert result == 0


async def test_cleanup_parses_count_from_result_string() -> None:
    pool = AsyncMock(spec=asyncpg.Pool)
    pool.execute = AsyncMock(return_value="DELETE 1337")
    result = await cleanup_old_entries(pool, ttl_days=7)
    assert result == 1337
