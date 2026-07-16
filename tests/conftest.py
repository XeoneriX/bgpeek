"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator

import asyncpg
import pytest
import pytest_asyncio
from testcontainers.postgres import PostgresContainer  # type: ignore[import-untyped]

from bgpeek.db.migrate import apply_migrations


def _docker_available() -> tuple[bool, str]:
    """Return (ok, reason). False when the Docker daemon can't be reached."""
    try:
        import docker  # type: ignore[import-not-found]
    except ImportError as exc:
        return False, f"python docker client missing: {exc}"
    try:
        docker.from_env().ping()
    except Exception as exc:  # docker.errors.DockerException and friends
        return False, f"docker daemon unreachable: {exc}"
    return True, ""


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    """Spin up a PostgreSQL 16 container for the test session and yield its DSN.

    Tests using this fixture are skipped (rather than erroring) when the Docker
    daemon is unavailable locally. CI always has Docker, so integration tests
    still run there; developers without Docker get a clean `pytest` run against
    the unit-test suite.
    """
    ok, reason = _docker_available()
    if not ok:
        pytest.skip(f"integration tests require Docker ({reason})")
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
                "TRUNCATE TABLE webhooks, query_results, devices, users, audit_log RESTART IDENTITY CASCADE"
            )
        await pool.close()
