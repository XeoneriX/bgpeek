"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import asyncpg
import pytest
import pytest_asyncio
from testcontainers.postgres import PostgresContainer  # type: ignore[import-untyped]

from bgpeek.db.migrate import apply_migrations


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    """Spin up a PostgreSQL 16 container for the test session and yield its DSN."""
    with PostgresContainer("postgres:16-alpine") as pg:
        raw = pg.get_connection_url()
        # testcontainers returns the SQLAlchemy-style URL; strip the driver suffix.
        dsn = raw.replace("postgresql+psycopg2://", "postgresql://").replace(
            "postgresql+psycopg://", "postgresql://"
        )
        apply_migrations(dsn)
        yield dsn


@pytest_asyncio.fixture()
async def pool(pg_dsn: str) -> AsyncIterator[asyncpg.Pool]:
    """Per-test asyncpg pool. Truncates tables on teardown so tests are isolated."""
    pool = await asyncpg.create_pool(dsn=pg_dsn, min_size=1, max_size=4)
    assert pool is not None
    try:
        yield pool
    finally:
        async with pool.acquire() as conn:
            await conn.execute(
                "TRUNCATE TABLE query_results, devices, users, audit_log RESTART IDENTITY CASCADE"
            )
        await pool.close()
