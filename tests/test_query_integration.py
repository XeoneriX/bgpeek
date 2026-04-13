"""Integration tests for the query pipeline: API → validator → SSH (mocked) → filter → audit."""

from __future__ import annotations

from ipaddress import IPv4Address
from unittest.mock import AsyncMock, patch

import asyncpg
import pytest

from bgpeek.core.query import QueryExecutionError, execute_query
from bgpeek.core.validators import TargetValidationError
from bgpeek.db import devices as device_crud
from bgpeek.db.audit import list_audit_entries
from bgpeek.db.pool import _pool as _global_pool  # noqa: F401 (need to patch)
from bgpeek.models.device import DeviceCreate
from bgpeek.models.query import QueryRequest, QueryType


async def _seed_device(pool: asyncpg.Pool, name: str = "rt1") -> None:
    await device_crud.create_device(
        pool,
        DeviceCreate(
            name=name,
            address=IPv4Address("10.0.0.1"),
            platform="juniper_junos",
        ),
    )


def _mock_ssh(output: str = "mock bgp output\n8.8.8.0/24 via 10.0.0.1") -> AsyncMock:
    """Return a mock SSHClient context manager."""
    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    mock.send_command = AsyncMock(return_value=output)
    return mock


def _mock_credential() -> AsyncMock:
    """Return a mock credential for SSH resolution."""
    from datetime import UTC, datetime

    from bgpeek.models.credential import Credential

    return AsyncMock(
        return_value=Credential(
            id=1,
            name="test",
            username="looking-glass",
            auth_type="key",
            key_name="test.key",
            created_at=datetime.now(tz=UTC),
            updated_at=datetime.now(tz=UTC),
        )
    )


@pytest.fixture(autouse=True)
def _patch_pool(pool: asyncpg.Pool) -> None:  # noqa: PT004
    """Inject test pool as the global pool so get_pool() works."""
    import bgpeek.db.pool as pool_mod

    pool_mod._pool = pool


async def test_query_bgp_success(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)

    with (
        patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh()),
        patch("bgpeek.core.query.get_credential_for_device", _mock_credential()),
    ):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="8.8.8.0/24"),
        )

    assert result.device_name == "rt1"
    assert result.query_type == QueryType.BGP_ROUTE
    assert "8.8.8.0/24" in result.filtered_output
    assert result.runtime_ms >= 0

    audits = await list_audit_entries(pool, limit=10)
    assert len(audits) == 1
    assert audits[0].success is True
    assert audits[0].query_type == "bgp_route"


async def test_query_filters_specific_routes(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)
    raw = "8.8.8.0/24 via 10.0.0.1\n8.8.8.128/25 via 10.0.0.2\n1.1.1.0/24 via 10.0.0.3"

    with (
        patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh(raw)),
        patch("bgpeek.core.query.get_credential_for_device", _mock_credential()),
    ):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="8.8.8.0/24"),
        )

    assert "8.8.8.0/24" in result.filtered_output
    assert "8.8.8.128/25" not in result.filtered_output
    assert "1.1.1.0/24" in result.filtered_output


async def test_query_bogon_rejected(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)

    with pytest.raises(TargetValidationError, match="bogon"):
        await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="10.0.0.0/8"),
        )

    audits = await list_audit_entries(pool, limit=10)
    assert len(audits) == 1
    assert audits[0].success is False
    assert "bogon" in (audits[0].error_message or "")


async def test_query_prefix_too_specific_rejected(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)

    with pytest.raises(TargetValidationError, match="too specific"):
        await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.BGP_ROUTE, target="1.1.1.0/25"),
        )


async def test_query_device_not_found(pool: asyncpg.Pool) -> None:
    with pytest.raises(QueryExecutionError, match="not found"):
        await execute_query(
            QueryRequest(device_name="no-such", query_type=QueryType.PING, target="8.8.8.8"),
        )


async def test_query_device_disabled(pool: asyncpg.Pool) -> None:
    await _seed_device(pool)
    await device_crud.update_device(
        pool,
        (await device_crud.get_device_by_name(pool, "rt1")).id,  # type: ignore[union-attr]
        __import__("bgpeek.models.device", fromlist=["DeviceUpdate"]).DeviceUpdate(enabled=False),
    )

    with pytest.raises(QueryExecutionError, match="disabled"):
        await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.PING, target="8.8.8.8"),
        )


async def test_query_ping_private_ip_allowed_for_noc(pool: asyncpg.Pool) -> None:
    """NOC/admin users can ping private (RFC1918) addresses."""
    await _seed_device(pool)

    with (
        patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh("PING 10.0.0.1: 5 packets")),
        patch("bgpeek.core.query.get_credential_for_device", _mock_credential()),
    ):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.PING, target="10.0.0.1"),
            user_role="noc",
        )

    assert result.query_type == QueryType.PING
    assert "10.0.0.1" in result.filtered_output


async def test_query_ping_private_ip_blocked_for_public(pool: asyncpg.Pool) -> None:
    """Public users cannot ping private (RFC1918) addresses."""
    await _seed_device(pool)

    with pytest.raises(TargetValidationError, match="private address"):
        await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.PING, target="10.0.0.1"),
            user_role="public",
        )


async def test_query_ping_no_output_filter(pool: asyncpg.Pool) -> None:
    """Ping output should NOT have prefix filtering applied."""
    await _seed_device(pool)
    raw = "PING 1.1.1.0/25: 5 packets\n8.8.8.128/25 line in output"

    with (
        patch("bgpeek.core.query.SSHClient", return_value=_mock_ssh(raw)),
        patch("bgpeek.core.query.get_credential_for_device", _mock_credential()),
    ):
        result = await execute_query(
            QueryRequest(device_name="rt1", query_type=QueryType.PING, target="8.8.8.8"),
        )

    assert result.filtered_output == raw


async def test_audit_always_written(pool: asyncpg.Pool) -> None:
    """Audit log is written even when query fails."""
    with pytest.raises(QueryExecutionError):
        await execute_query(
            QueryRequest(device_name="ghost", query_type=QueryType.BGP_ROUTE, target="8.8.8.0/24"),
        )

    audits = await list_audit_entries(pool, limit=10)
    assert len(audits) == 1
    assert audits[0].success is False
